from __future__ import annotations

import hashlib
import json
import logging
import pickle
from base64 import b64decode, b64encode
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Callable

logger = logging.getLogger(__name__)


class DoNotCache:
    """Signal that an extractor result must not be written to the cache."""

    def __init__(self, value: Any, reason: str | None = None) -> None:
        self.value = value
        self.reason = reason or "No reason provided."

    @classmethod
    def __class_getitem__(cls, _item: object) -> type["DoNotCache"]:
        return cls


@dataclass
class ExtractorContext:
    cache_dir: Path | None = None
    options: dict[str, Any] | None = None

    def get(self, key: str, default: Any = None) -> Any:
        return (self.options or {}).get(key, default)


class BaseExtractor:
    """Small neutral equivalent of the reference extractor cache contract."""

    cache_namespace: ClassVar[str] = "mcp"
    cache_ttl_seconds: ClassVar[int | None] = None

    name: ClassVar[str] = "mcp-extractor"
    version: ClassVar[str] = "1.0"
    cache_key_fn: ClassVar[Callable[[Any], Any] | None] = None

    def __init__(self, cache_service: Any = None, *, context: ExtractorContext | None = None, **_: Any) -> None:
        self._cache_service = cache_service
        self.context = context or ExtractorContext()

    @classmethod
    def cache_key(cls, subject: Any) -> str:
        encoded = json.dumps(subject, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _cache_path(self, subject: Any) -> Path | None:
        if self.context.cache_dir is None:
            return None
        return self.context.cache_dir / self.cache_namespace / f"{self.cache_key(subject)}.json"

    def read_cached(self, subject: Any) -> dict[str, Any] | None:
        path = self._cache_path(subject)
        if path is None or not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def write_cached(self, subject: Any, value: Any) -> None:
        path = self._cache_path(subject)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value, default=str), encoding="utf-8")
        except OSError:
            return

    def _build_cache_key(self, subject: Any) -> str:
        key_subject = self.cache_key_fn(subject) if self.cache_key_fn else subject
        encoded = json.dumps(key_subject, sort_keys=True, default=str).encode("utf-8")
        return f"extractor:{self.name}:{self.version}:{hashlib.sha256(encoded).hexdigest()[:16]}"

    async def extract(self, subject: Any, **kwargs: Any) -> Any:
        """Run the reference cache/compute lifecycle against any cache adapter."""
        cache_key = self._build_cache_key(subject)
        if self._cache_service is not None:
            try:
                cached = await self._cache_service.get(cache_key)
                if cached is not None:
                    value = getattr(cached, "value", cached)
                    if isinstance(value, dict) and "__pickled__" in value:
                        return pickle.loads(b64decode(value["__pickled__"]))
                    return value
            except Exception:
                logger.debug("MCP extractor cache read failed", exc_info=True)
        result = await self._compute(subject, **kwargs)
        if isinstance(result, DoNotCache):
            return result.value
        if self._cache_service is not None and result is not None:
            try:
                from types import SimpleNamespace

                encoded = {"__pickled__": b64encode(pickle.dumps(result)).decode("ascii")}
                await self._cache_service.set(
                    cache_key,
                    SimpleNamespace(value=encoded, updated_at=datetime.now(timezone.utc)),
                    expire_in=60 * 60 * 24 * 31,
                )
            except Exception:
                logger.debug("MCP extractor cache write failed", exc_info=True)
        return result
