from __future__ import annotations

from typing import Any, TypeVar

T = TypeVar("T")


class GeminiVertexLLM:
    """Small provider adapter matching the reference ``agenerate`` contract."""

    def __init__(self, *, model: str, project_id: str | None = None, api_key: str | None = None, **_: Any) -> None:
        self.model = model.split("/", 1)[-1]
        self.project_id = project_id
        self.api_key = api_key

    async def agenerate(
        self,
        *,
        messages: Any,
        response_format: type[T] | None = None,
        max_tokens: int | None = None,
        tools: Any = None,
        thinking_config: Any = None,
        **_: Any,
    ) -> T | str | None:
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:
            raise RuntimeError("The Google GenAI provider is not installed") from exc

        client_kwargs: dict[str, Any] = {}
        if self.api_key:
            client_kwargs["api_key"] = self.api_key
        elif self.project_id:
            client_kwargs.update({"vertexai": True, "project": self.project_id, "location": "global"})
        client = genai.Client(**client_kwargs)
        config_kwargs: dict[str, Any] = {}
        if max_tokens is not None:
            config_kwargs["max_output_tokens"] = max_tokens
        if response_format is not None:
            config_kwargs["response_mime_type"] = "application/json"
            config_kwargs["response_schema"] = response_format
        if tools:
            config_kwargs["tools"] = tools
        config = types.GenerateContentConfig(**config_kwargs)
        response = await client.aio.models.generate_content(
            model=self.model,
            contents=messages,
            config=config,
        )
        if response_format is not None:
            parsed = getattr(response, "parsed", None)
            if parsed is not None:
                return parsed
            text = getattr(response, "text", None)
            if text:
                return response_format.model_validate_json(text)
        return getattr(response, "text", None)

