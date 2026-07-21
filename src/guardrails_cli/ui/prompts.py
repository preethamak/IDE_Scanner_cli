from __future__ import annotations

import textwrap
from typing import Sequence

from .tables import terminal_width
from .theme import color


def prompt_text(label: str, *, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(color(f"{label}{suffix}: ", "brand")).strip()
    return value or default


def prompt_choice(label: str, choices: Sequence[str], *, default: int = 0, show_choices: bool = True) -> int:
    if show_choices:
        width = max(20, terminal_width() - 7)
        for index, choice in enumerate(choices, start=1):
            wrapped = textwrap.wrap(str(choice), width=width, break_long_words=False, break_on_hyphens=False) or [""]
            print(f"  {color(index, 'brand')}  {wrapped[0]}")
            for line in wrapped[1:]:
                print(f"     {line}")
    while True:
        raw = input(color(f"{label} [{default + 1}]: ", "brand")).strip()
        if not raw:
            return default
        if raw.isdigit():
            index = int(raw) - 1
            if 0 <= index < len(choices):
                return index
        print(color(f"Choose a number from 1 to {len(choices)}.", "yellow"))


def confirm(label: str, *, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(color(f"{label} [{suffix}]: ", "brand")).strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def prompt_indices(label: str, choices: Sequence[str]) -> list[int]:
    """Select one or more rows with values such as 1,3-5 or all."""
    while True:
        raw = input(color(f"{label} [1]: ", "brand_cyan")).strip().lower()
        if not raw:
            return [0]
        if raw in {"all", "a"}:
            return list(range(len(choices)))
        selected: set[int] = set()
        try:
            for token in raw.split(","):
                token = token.strip()
                if "-" in token:
                    start, end = (int(value) for value in token.split("-", 1))
                    selected.update(range(start - 1, end))
                else:
                    selected.add(int(token) - 1)
        except ValueError:
            selected.clear()
        if selected and min(selected) >= 0 and max(selected) < len(choices):
            return sorted(selected)
        print(color(f"Choose 1-{len(choices)}, a comma-separated list, a range, or all.", "yellow"))
