from __future__ import annotations

import os
import sys


RESET = "\033[0m"
STYLES = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "cyan": "\033[36m",
    "blue": "\033[34m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "orange": "\033[38;5;208m",
    "red": "\033[31m",
    "violet": "\033[35m",
    "brand_pink": "\033[38;2;241;59;113m",
    "brand_cyan": "\033[38;2;23;174;253m",
    "brand_blue": "\033[38;2;58;69;193m",
    "brand": "\033[38;2;58;69;193m",
    "gray": "\033[90m",
    "white": "\033[97m",
}

SEVERITY_ICON = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}


def supports_color() -> bool:
    if "NO_COLOR" in os.environ:
        return False
    if os.environ.get("FORCE_COLOR", "").lower() not in {"", "0", "false", "no"}:
        return True
    return sys.stdout.isatty()


def truecolor() -> bool:
    if not supports_color():
        return False
    return os.environ.get("COLORTERM", "").lower() in {"truecolor", "24bit"} or bool(os.environ.get("WT_SESSION"))


def background(hex_color: str, value: str = "  ") -> str:
    """Render one sampled logo pixel using its original RGB value."""
    if not supports_color():
        return value
    red, green, blue = (int(hex_color[index:index + 2], 16) for index in (1, 3, 5))
    return f"\033[48;2;{red};{green};{blue}m{value}{RESET}"


def color(text: object, style: str) -> str:
    value = str(text)
    code = STYLES.get(style, "")
    if not code or not supports_color():
        return value
    return f"{code}{value}{RESET}"


def badge(text: str, style: str) -> str:
    return color(f" {text.upper()} ", style)


def verdict_style(verdict: str, state: str = "") -> str:
    value = (state or verdict or "").lower()
    if "block" in value or "malicious" in value:
        return "red"
    if "suspicious" in value:
        return "orange"
    if "review" in value:
        return "yellow"
    if "allow" in value or "safe" in value or "clean" in value:
        return "green"
    if "incomplete" in value:
        return "violet"
    return "blue"


def severity_style(severity: str) -> str:
    value = severity.upper()
    if value in {"CRITICAL", "HIGH"}:
        return "red"
    if value == "MEDIUM":
        return "yellow"
    if value == "LOW":
        return "cyan"
    return "blue"


def severity_label(severity: str) -> str:
    value = severity.upper()
    return SEVERITY_ICON.get(value, value or "INFO")


def rule() -> str:
    return color("-" * 78, "gray")
