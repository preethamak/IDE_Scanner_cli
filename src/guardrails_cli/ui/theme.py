from __future__ import annotations

import os
import sys


RESET = "\033[0m"
STYLES = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "cyan": "\033[36m",
    "blue": "\033[34m",
    "green": "\033[38;2;31;138;76m",
    "yellow": "\033[38;2;154;101;18m",
    "orange": "\033[38;2;154;101;18m",
    "red": "\033[38;2;180;55;61m",
    "violet": "\033[38;2;103;81;155m",
    "brand_pink": "\033[38;2;241;59;113m",
    "brand_cyan": "\033[38;2;23;174;253m",
    "brand_blue": "\033[38;2;58;69;193m",
    "brand": "\033[38;2;201;255;69m",
    "brand_ink": "\033[38;2;93;120;0m",
    "ink": "\033[38;2;20;32;43m",
    "gray": "\033[38;2;117;129;140m",
    "white": "\033[97m",
}

SEVERITY_ICON = {
    "CRITICAL": "● CRITICAL",
    "HIGH": "● HIGH",
    "MEDIUM": "● MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}


def supports_color() -> bool:
    if "NO_COLOR" in os.environ:
        return False
    if os.environ.get("FORCE_COLOR", "").lower() not in {"", "0", "false", "no"}:
        return True
    return sys.stdout.isatty()


def rgb(hex_color: str, *, background: bool = False) -> str:
    red, green, blue = (int(hex_color[index:index + 2], 16) for index in (1, 3, 5))
    layer = 48 if background else 38
    return f"\033[{layer};2;{red};{green};{blue}m"


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
    if "suspicious" in value or "review" in value:
        return "yellow"
    if "allow" in value or "safe" in value or "clean" in value:
        return "green"
    if "incomplete" in value:
        return "violet"
    return "gray"


def severity_style(severity: str) -> str:
    value = severity.upper()
    if value in {"CRITICAL", "HIGH"}:
        return "red"
    if value == "MEDIUM":
        return "yellow"
    if value == "LOW":
        return "cyan"
    return "gray"


def severity_label(severity: str) -> str:
    value = severity.upper()
    return SEVERITY_ICON.get(value, value or "INFO")


def rule() -> str:
    return color("-" * 78, "gray")
