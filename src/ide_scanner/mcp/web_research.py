from __future__ import annotations

from typing import Any

import httpx


async def scrape_page(url: str, **_: Any) -> str:
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.text


async def google_search(query: str, *, api_key: str | None = None, search_cx: str | None = None, **_: Any) -> list[dict[str, str]]:
    if not api_key or not search_cx:
        return []
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(
            "https://www.googleapis.com/customsearch/v1",
            params={"key": api_key, "cx": search_cx, "q": query},
        )
        response.raise_for_status()
        items = response.json().get("items", [])
        return [{"title": str(item.get("title", "")), "link": str(item.get("link", "")), "snippet": str(item.get("snippet", ""))} for item in items if isinstance(item, dict)]

