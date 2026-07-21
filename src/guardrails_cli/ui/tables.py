from __future__ import annotations

import re
import shutil
import textwrap
from typing import Iterable

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
ELLIPSIS = "..."

try:
    from wcwidth import wcswidth
except Exception:  # pragma: no cover - fallback for minimal installs
    def wcswidth(value: str) -> int:
        return len(value)


def visible_len(value: object) -> int:
    width = wcswidth(ANSI_RE.sub("", str(value)))
    return max(width, 0)


def _plain(value: object) -> str:
    return ANSI_RE.sub("", str(value))


def truncate(value: object, width: int) -> str:
    plain = _plain(value)
    if visible_len(plain) <= width:
        return str(value)
    if width <= 1:
        return ""
    suffix = ELLIPSIS if width >= visible_len(ELLIPSIS) + 1 else "."
    limit = max(1, width - visible_len(suffix))
    out = ""
    used = 0
    for char in plain:
        char_width = max(wcswidth(char), 0)
        if used + char_width > limit:
            break
        out += char
        used += char_width
    return out + suffix


def terminal_width(default: int = 100) -> int:
    return max(40, shutil.get_terminal_size((default, 24)).columns)


def _fit_widths(headers: list[str], rows: list[list[str]], max_widths: list[int], width: int) -> list[int]:
    count = len(headers)
    frame = 3 * (count - 1) + 4
    available = width - frame
    desired: list[int] = []
    minimums: list[int] = []
    for index, header in enumerate(headers):
        values = [visible_len(row[index]) for row in rows if index < len(row)]
        natural = max([visible_len(header), *values], default=visible_len(header))
        cap = max_widths[index] if index < len(max_widths) else 28
        target = min(natural, cap)
        desired.append(max(4, target))
        minimums.append(min(max(3, min(visible_len(header), 8)), target))

    total = sum(desired)
    if total <= available:
        return desired
    if available < sum(minimums):
        return []

    widths = desired[:]
    overflow = total - available
    while overflow > 0:
        candidates = [index for index, value in enumerate(widths) if value > minimums[index]]
        if not candidates:
            break
        index = max(candidates, key=lambda item: widths[item] - minimums[item])
        widths[index] -= 1
        overflow -= 1
    return widths


def _wrap_cell(value: object, width: int) -> list[str]:
    raw = str(value)
    text = _plain(value)
    if not text:
        return [""]
    if ANSI_RE.search(raw) and visible_len(raw) <= width:
        return [raw]
    wrapped: list[str] = []
    for line in text.splitlines() or [""]:
        if visible_len(line) <= width:
            wrapped.append(line)
        elif " " not in line:
            wrapped.extend(_split_long_token(line, width))
        else:
            parts = textwrap.wrap(line, width=width, break_long_words=False, break_on_hyphens=False) or [""]
            for part in parts:
                if visible_len(part) > width:
                    wrapped.extend(_split_long_token(part, width))
                else:
                    wrapped.append(part)
    return wrapped


def _pad(value: object, width: int) -> str:
    raw = truncate(value, width)
    return raw + " " * max(width - visible_len(raw), 0)


def _simple_wrap(value: object, width: int) -> list[str]:
    width = max(8, width)
    raw = str(value)
    if ANSI_RE.search(raw) and visible_len(raw) <= width:
        return [raw]
    lines: list[str] = []
    for line in _plain(value).splitlines() or [""]:
        if visible_len(line) <= width:
            lines.append(line)
            continue
        if " " not in line:
            lines.extend(_split_long_token(line, width))
            continue
        lines.extend(textwrap.wrap(line, width=width, break_long_words=True, break_on_hyphens=False) or [""])
    return lines or [""]


def _split_long_token(value: str, width: int) -> list[str]:
    chunks: list[str] = []
    remaining = value
    separators = {"/", ".", "_", "-"}
    while remaining:
        if visible_len(remaining) <= width:
            chunks.append(remaining)
            break

        current = ""
        last_break = -1
        for index, char in enumerate(remaining):
            if visible_len(current + char) > width:
                break
            current += char
            if char in separators:
                last_break = index + 1

        if last_break >= max(4, min(width - 1, width // 3)):
            chunks.append(remaining[:last_break])
            remaining = remaining[last_break:]
            continue

        if current:
            chunks.append(current)
            remaining = remaining[len(current):]
        else:
            chunks.append(remaining[:1])
            remaining = remaining[1:]
    return chunks or [""]


def _stacked_table(headers: list[str], rows: list[list[str]], width: int) -> str:
    width = max(40, width)
    key_width = min(max((visible_len(header) for header in headers), default=0), 14)
    value_width = max(12, width - key_width - 3)
    rule = "─" * min(width, max(12, width))
    lines: list[str] = []
    for row_index, row in enumerate(rows, start=1):
        if row_index > 1:
            lines.append(rule)
        for index, header in enumerate(headers):
            value = row[index] if index < len(row) else ""
            wrapped = _simple_wrap(value, value_width)
            label = truncate(header, key_width)
            continuation = " " * (visible_len(label) + 2)
            lines.append(f"{label}: {wrapped[0]}")
            for extra in wrapped[1:]:
                lines.append(f"{continuation}{extra}")
    return "\n".join(truncate(line, width) for line in lines)


def table(headers: list[str], rows: Iterable[Iterable[object]], *, max_widths: list[int] | None = None, width: int | None = None) -> str:
    row_list = [[str(cell) for cell in row] for row in rows]
    max_widths = max_widths or [28] * len(headers)
    target_width = width or terminal_width()
    if (len(headers) >= 5 and target_width < 72) or (len(headers) >= 3 and target_width < 50):
        return _stacked_table(headers, row_list, target_width)

    widths = _fit_widths(headers, row_list, max_widths, target_width)
    if not widths:
        return _stacked_table(headers, row_list, target_width)

    def fmt_line(values: list[object]) -> str:
        cells = []
        for index, width in enumerate(widths):
            cells.append(_pad(values[index] if index < len(values) else "", width))
        return "| " + " | ".join(cells) + " |"

    def fmt_row(values: list[object]) -> list[str]:
        wrapped = [_wrap_cell(values[index] if index < len(values) else "", width) for index, width in enumerate(widths)]
        height = max((len(cell) for cell in wrapped), default=1)
        lines = []
        for line_index in range(height):
            cells = []
            for index, width in enumerate(widths):
                raw = wrapped[index][line_index] if line_index < len(wrapped[index]) else ""
                cells.append(_pad(raw, width))
            lines.append("| " + " | ".join(cells) + " |")
        return lines

    top = "╭─" + "─┬─".join("─" * width for width in widths) + "─╮"
    sep = "├─" + "─┼─".join("─" * width for width in widths) + "─┤"
    bottom = "╰─" + "─┴─".join("─" * width for width in widths) + "─╯"
    lines = [top, fmt_line(headers).replace("|", "│"), sep]
    for row in row_list:
        lines.extend(fmt_row(row))
    lines.append(bottom)
    return "\n".join(line.replace("|", "│") for line in lines)


def key_values(items: list[tuple[str, object]], *, key_width: int = 16, width: int | None = None) -> str:
    value_width = max(12, (width or terminal_width()) - key_width - 8)
    lines = []
    for key, value in items:
        values = _simple_wrap(value, value_width)
        lines.append(f"{key:<{key_width}} {values[0] if values else ''}")
        for extra in values[1:]:
            lines.append(f"{'':<{key_width}} {extra}")
    return "\n".join(lines)


def score_bar(value: int | float, *, width: int = 24) -> str:
    value = max(0, min(100, int(value or 0)))
    width = max(4, min(width, max(4, terminal_width() - 24)))
    filled = round(width * value / 100)
    return "█" * filled + "░" * (width - filled) + f"  {value:>3}/100"


def count_bar(value: int, maximum: int, *, width: int = 12) -> str:
    maximum = max(maximum, 1)
    width = max(4, min(width, max(4, terminal_width() - 28)))
    filled = round(width * max(value, 0) / maximum)
    return "█" * filled + "░" * (width - filled)
