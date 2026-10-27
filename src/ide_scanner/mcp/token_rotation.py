from __future__ import annotations

from itertools import cycle


class TokenRotator:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = [token for token in tokens if token]
        self._iterator = cycle(self._tokens) if self._tokens else iter(())

    def next_token(self) -> str | None:
        return next(self._iterator, None)

