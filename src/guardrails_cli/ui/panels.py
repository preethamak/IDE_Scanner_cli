from __future__ import annotations

import textwrap

from guardrails_cli import __version__

from .tables import ANSI_RE, terminal_width, truncate, visible_len
from .theme import background, color, supports_color


# A 12x12 sampling of the website's canonical guardrails-mark.png. The terminal
# uses the real sampled RGB values rather than an unrelated ASCII symbol.
LOGO_PIXELS: tuple[tuple[str | None, ...], ...] = (
    (None, "#ed3f70", "#ef3d70", "#ee4170", None, None, None, None, None, None, None, None),
    ("#ed3f70", "#f13b72", "#f23b72", "#f43c71", "#f53f6f", None, None, None, None, None, None, None),
    ("#ed3e6f", "#f23a72", "#e63c77", "#ac3f90", "#8e419d", "#525ebf", "#17abf5", "#16b1f7", "#17b0f9", "#16b0fa", "#16b1f9", None),
    ("#ed3f6e", "#f13b72", "#92419b", "#3b45c1", "#3845c2", "#3949c3", "#2a78de", "#19aafa", "#17aefd", "#17adfc", "#17aefc", "#17b1f9"),
    ("#ed3f6f", "#ed3b74", "#6d43ab", "#3745c2", "#3b45c1", "#3a44c0", "#3a47c1", "#2b74dc", "#19a8fa", "#17aefd", "#17adfc", "#17affb"),
    ("#ed3e6f", "#f33a71", "#af3f8f", "#4444bc", "#3945c1", "#3a45c0", "#3a45c0", "#3a46c1", "#2c71da", "#19a7f9", "#16aefd", "#17affb"),
    ("#ed3f6f", "#f23a72", "#f03a72", "#aa3f90", "#4744bb", "#3945c1", "#3b45c0", "#3b45c0", "#3b46c0", "#2c72da", "#18aafb", "#17affc"),
    ("#ed3e6e", "#f13971", "#f13971", "#f13a71", "#af3e8e", "#4943ba", "#3945c1", "#3b45c0", "#3b45c0", "#384ec5", "#1d9cf2", "#17b1fc"),
    ("#ec3c6e", "#f03970", "#f13971", "#f13971", "#f23971", "#b53d8b", "#4e43b8", "#3a43c0", "#3b43bf", "#3459cc", "#1aa3f6", "#17b0fc"),
    (None, "#ed3b6e", "#ed3b6d", "#ec3c6d", "#ec3c6d", "#ee3c6c", "#964596", "#3064d0", "#2a72da", "#1e96ef", "#16adfc", "#17aefb"),
    (None, None, None, None, None, None, None, "#17aef8", "#16adfc", "#15adfd", "#16adfc", "#17aff9"),
    (None, None, None, None, None, None, None, None, "#16aef7", "#16adfa", "#16aff9", "#16b2f6"),
)


def logo_lines() -> list[str]:
    if not supports_color():
        return ["GUARDRAILS"]
    return ["".join(background(pixel) if pixel else "  " for pixel in row).rstrip() for row in LOGO_PIXELS]


def banner(subtitle: str = "Local IDE extension scanner") -> str:
    if terminal_width() < 58 or not supports_color():
        return color("GUARDRAILS", "brand_blue") + "\n" + color(f"{subtitle}  ·  v{__version__}", "gray")
    mark = logo_lines()
    copy = [
        "",
        color("GUARDRAILS", "white"),
        color(subtitle, "gray"),
        color(f"v{__version__}", "brand_cyan"),
    ]
    midpoint = 3
    lines: list[str] = []
    for index, line in enumerate(mark):
        suffix_index = index - midpoint
        suffix = f"   {copy[suffix_index]}" if 0 <= suffix_index < len(copy) else ""
        lines.append(line + suffix)
    return "\n".join(lines)


def _wrap_panel_line(line: str, width: int) -> list[str]:
    if visible_len(line) <= width:
        return [line]
    if ANSI_RE.search(line):
        return [truncate(line, width)]
    return textwrap.wrap(line, width=width, break_long_words=True, break_on_hyphens=False) or [""]


def panel(title: str, body: str = "", *, subtitle: str = "") -> str:
    raw_content = [line.rstrip() for line in body.splitlines()] if body else []
    header = f" {title} " + (f"- {subtitle} " if subtitle else "")
    max_width = max(36, terminal_width() - 4)
    content: list[str] = []
    for line in raw_content:
        content.extend(_wrap_panel_line(line, max_width))
    header = truncate(header, max_width)
    width = min(max_width, max(36, visible_len(header), *(visible_len(line) for line in content), 0))
    top = "╭" + "─" * (width + 2) + "╮"
    title_line = "│ " + color(header, "brand") + " " * max(width - visible_len(header), 0) + " │"
    lines = [top, title_line, "├" + "─" * (width + 2) + "┤"]
    for line in content:
        lines.append("│ " + line + " " * max(width - visible_len(line), 0) + " │")
    lines.append("╰" + "─" * (width + 2) + "╯")
    return "\n".join(lines)


def section(title: str) -> str:
    width = min(terminal_width(), 96)
    label = f" {truncate(title, max(8, width - 10))} "
    side = max(0, (width - visible_len(label)) // 2)
    return "\n" + color("─" * side + label + "─" * side, "brand")
