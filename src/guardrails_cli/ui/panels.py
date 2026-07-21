from __future__ import annotations

import textwrap

from guardrails_cli import __version__

from .tables import ANSI_RE, terminal_width, truncate, visible_len
from .theme import RESET, color, rgb, supports_color


# A 20×20 resampling of the exact PNG currently rendered by website BrandMark.
# Half-block cells preserve the mark's square geometry in terminal character cells.
LOGO_PIXELS: tuple[tuple[str | None, ...], ...] = (
    (None, None, "#e7456e", "#eb406e", "#ec406e", "#e9476e", None, None, None, None, None, None, None, None, None, None, None, None, None, None),
    (None, "#eb416f", "#f03c71", "#f13b72", "#f13b72", "#f13d71", "#eb456e", None, None, None, None, None, None, None, None, None, None, None, None, None),
    ("#e6466d", "#f03b71", "#f13a72", "#f13b72", "#f13b72", "#f23b72", "#f23d72", "#f14171", None, None, None, None, None, None, None, None, None, None, None, None),
    ("#e9436d", "#f23a72", "#f23a72", "#f13b72", "#f23b72", "#f33b71", "#ea3c76", "#e53e77", "#d8457c", None, None, None, None, None, None, None, None, None, None, None),
    ("#e7456a", "#f13a71", "#f23b72", "#f33b71", "#e13d79", "#95419a", "#6644ae", "#5e44b2", "#5a46b4", "#3171d4", "#18acf7", "#17b1f8", "#17b0f8", "#17b0f8", "#17affa", "#17affa", "#16affb", "#16b2f8", "#16b7f3", None),
    ("#e8456b", "#f13a71", "#f23b72", "#e93c76", "#7942a6", "#3845c1", "#3846c2", "#3845c2", "#3845c1", "#3a49c3", "#2a77de", "#19a9fb", "#17aefd", "#18adfd", "#17adfc", "#17adfc", "#17adfc", "#17aefc", "#18b1fa", "#17b8f1"),
    ("#e8456b", "#f13a71", "#f43a70", "#c13f87", "#4044be", "#3a45c1", "#3b46c2", "#3a45c1", "#3a45c1", "#3b45c0", "#3a47c1", "#2c74dc", "#19a8fa", "#18aefd", "#18adfc", "#18adfc", "#17adfc", "#17adfc", "#18aefc", "#17b2f7"),
    ("#e8456b", "#f13a71", "#f53a70", "#b43f8d", "#3c45c0", "#3b45c1", "#3b45c1", "#3a45c1", "#3a45c1", "#3a44c0", "#3a44c0", "#3b46c1", "#2c71da", "#19a7f9", "#17adfd", "#17adfc", "#17adfc", "#17adfc", "#17aefc", "#17b1fa"),
    ("#e7446b", "#f13a72", "#f33a71", "#d73d7e", "#5344b7", "#3945c2", "#3b45c0", "#3a45c0", "#3a45c0", "#3a44c0", "#3a45c1", "#3a44c0", "#3a45c0", "#2d6ed8", "#1aa6f9", "#16aefd", "#16adfc", "#16adfc", "#17aefc", "#17b0fa"),
    ("#e7446b", "#f13a72", "#f13a72", "#f23b71", "#b33f8d", "#4a44ba", "#3945c1", "#3b44c0", "#3a45c0", "#3a45c0", "#3a45c1", "#3a45c1", "#3a45c0", "#3b46c0", "#2e6cd7", "#1aa5f8", "#16aefd", "#17adfc", "#17aefc", "#17b1fa"),
    ("#e7456c", "#f13a72", "#f13a72", "#f13a72", "#f23a71", "#b53e8c", "#4c44b9", "#3944c0", "#3b45c0", "#3b45c0", "#3b45c0", "#3b45c1", "#3b45c0", "#3b45c0", "#3b45c0", "#2f6ad6", "#1aa5f8", "#16aefd", "#17aefc", "#17b1fa"),
    ("#e7456b", "#f13a71", "#f13972", "#f13a72", "#f13971", "#f33a70", "#bb3e8a", "#5044b7", "#3945c1", "#3b45c0", "#3b45c0", "#3b45c0", "#3b45c0", "#3b45c0", "#3b46c0", "#3b45c0", "#2978de", "#16aefc", "#17aefc", "#18b1fa"),
    ("#e8446b", "#f13970", "#f13972", "#f13a72", "#f13972", "#f13a71", "#f33a71", "#bf3e88", "#5243b6", "#3844c0", "#3b44c0", "#3b44c0", "#3b44c0", "#3b45c0", "#3b46c1", "#3b45c0", "#335ccd", "#19a8f9", "#17aefc", "#17b1fa"),
    ("#ea416d", "#f13970", "#f13971", "#f13972", "#f13971", "#f13971", "#f13971", "#f33a71", "#c33d86", "#5543b5", "#3844c1", "#3b45c0", "#3b45c1", "#3b45c1", "#3b46c1", "#3b44c0", "#335ece", "#18a8f9", "#17aefc", "#18b1fa"),
    ("#e2456a", "#ee3a6f", "#f13870", "#f13971", "#f13971", "#f13870", "#f13971", "#f13971", "#f33970", "#c83c83", "#5a43b3", "#3944c1", "#3b44c0", "#3a44c0", "#3b44c0", "#3b47c1", "#2681e3", "#16aefd", "#17adfc", "#18b0fa"),
    (None, "#e6426a", "#ed3b6e", "#ef396f", "#ee3a6e", "#ee3a6d", "#ee3a6e", "#ee3a6e", "#ee3a6e", "#f13b6d", "#c73e81", "#5248b5", "#354dc5", "#374ec5", "#3457ca", "#277de1", "#17a9fa", "#16adfc", "#17adfc", "#17b0fa"),
    (None, None, None, None, "#dd4964", "#dc4963", "#dd4964", "#dc4964", "#dc4a65", "#dc4c66", "#eb485e", "#5a71b6", "#1d98ee", "#1c9df2", "#19a4f7", "#15adfc", "#15acfc", "#15acfc", "#16adfc", "#17b0f9"),
    (None, None, None, None, None, None, None, None, None, None, None, None, "#14b6f9", "#16aefb", "#16acfc", "#16acfc", "#15acfc", "#16adfc", "#17aefc", "#18b2f5"),
    (None, None, None, None, None, None, None, None, None, None, None, None, None, None, "#16adf9", "#16acfc", "#16acfc", "#16adfc", "#17b0f9", None),
    (None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, "#15aff6", "#15aef8", "#14b1f6", None, None),
)


def _half_cell(top: str | None, bottom: str | None) -> str:
    if top and bottom:
        return f"{rgb(top)}{rgb(bottom, background=True)}▀{RESET}"
    if top:
        return f"{rgb(top)}▀{RESET}"
    if bottom:
        return f"{rgb(bottom)}▄{RESET}"
    return " "


def logo_lines() -> list[str]:
    # Many capable terminals omit COLORTERM. The interface already uses 24-bit
    # ANSI colours, so that missing hint should never make the brand disappear.
    if not supports_color():
        return []
    return [
        "".join(_half_cell(top, bottom) for top, bottom in zip(LOGO_PIXELS[index], LOGO_PIXELS[index + 1])).rstrip()
        for index in range(0, len(LOGO_PIXELS), 2)
    ]


def banner(subtitle: str = "Local IDE extension scanner") -> str:
    mark = logo_lines()
    if not mark:
        width = terminal_width()
        return color("Guardrails", "bold") + "\n" + color(truncate(f"{subtitle}  ·  v{__version__}", width), "gray")
    if terminal_width() < 62:
        return "\n".join(
            [
                *mark,
                color("Guardrails", "bold"),
                color(truncate(f"{subtitle}  ·  v{__version__}", terminal_width()), "gray"),
            ]
        )
    copy = [
        color("Guardrails", "bold"),
        color(subtitle, "gray"),
        color(f"v{__version__}", "brand"),
    ]
    lines: list[str] = []
    for index, line in enumerate(mark):
        suffix_index = index - 3
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
    outer_width = terminal_width()
    content_cap = max(20, outer_width - 4)
    raw_content = [line.rstrip() for line in body.splitlines()] if body else []
    header = f" {title} " + (f"· {subtitle} " if subtitle else "")
    content: list[str] = []
    for line in raw_content:
        content.extend(_wrap_panel_line(line, content_cap))
    header = truncate(header, content_cap)
    width = min(content_cap, max(20, visible_len(header), *(visible_len(line) for line in content), 0))
    top = "╭" + "─" * (width + 2) + "╮"
    title_line = "│ " + color(header, "brand") + " " * max(width - visible_len(header), 0) + " │"
    lines = [top, title_line, "├" + "─" * (width + 2) + "┤"]
    for line in content:
        lines.append("│ " + line + " " * max(width - visible_len(line), 0) + " │")
    lines.append("╰" + "─" * (width + 2) + "╯")
    return "\n".join(lines)


def section(title: str) -> str:
    width = min(terminal_width(), 96)
    label = f" {truncate(title, max(8, width - 5))} "
    return "\n" + color(label + "─" * max(0, width - visible_len(label)), "brand")
