from __future__ import annotations

import re
from typing import Any


# This module deliberately analyzes semantic *families*, not extension IDs,
# publishers, domains, or malware hashes.  It is intended to recognize the
# same packaged behavior when names and infrastructure change.
_CREDENTIAL_FAMILIES: dict[str, re.Pattern[str]] = {
    "ssh": re.compile(r"\.ssh(?:[/\\]|\b)|id_(?:rsa|ed25519|ecdsa|dsa)\b", re.I),
    "cloud": re.compile(
        r"\.aws(?:[/\\]|\b)|aws[/\\](?:credentials|config)\b|"
        r"\.kube[/\\]config\b|\.docker[/\\]config(?:\.json)?\b|"
        r"application_default_credentials",
        re.I,
    ),
    "package-registry": re.compile(r"\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b", re.I),
    "wallet": re.compile(
        r"wallet\.dat\b|(?:seed[_ -]?phrase|mnemonic)(?:\.(?:txt|json|bin)|\b)|"
        r"(?:private[_ -]?key)(?:\.(?:txt|json|pem)|\b)",
        re.I,
    ),
    "environment": re.compile(
        r"(?:^|[/\\])\\?\.env(?:\.(?:local|production|development|staging|backup))?\b",
        re.I | re.M,
    ),
    "shell-history": re.compile(r"\.(?:bash_history|zsh_history|zhistory)\b", re.I),
    "password-store": re.compile(r"\.(?:password-store|1password|bitwarden)(?:[/\\]|\b)", re.I),
}

_COLLECTION_SIGNALS: dict[str, re.Pattern[str]] = {
    "file-read": re.compile(r"\breadFile(?:Sync)?\b|\bcreateReadStream\b", re.I),
    "directory-enumeration": re.compile(r"\breaddir(?:Sync)?\b", re.I),
    "home-directory": re.compile(r"\b(?:homedir|userInfo)\b", re.I),
}

_EXFILTRATION_SIGNALS: dict[str, re.Pattern[str]] = {
    "network-client": re.compile(r"\b(?:https?|request|fetch|axios|websocket)\b", re.I),
    "outbound-write": re.compile(r"\b(?:write|send|post)\b", re.I),
    "payload-packaging": re.compile(r"\b(?:stringify|form-data|createGzip|createCipheriv|archiver)\b", re.I),
}

_OBFUSCATED_IDENTIFIER_RE = re.compile(r"\b_0x[0-9a-f]{4,}\b", re.I)
_HEX_INTEGER_RE = re.compile(r"\b0x[0-9a-f]+\b", re.I)
_COMPUTED_IDENTIFIER_RE = re.compile(r"\[[A-Za-z_$][\w$]*\]")
_ENCODED_CHARACTER_RE = re.compile(r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4}", re.I)
_ROTATION_LOOP_RE = re.compile(r"while\s*\(\s*(?:!!\[\]|true)\s*\)", re.I)
_ARRAY_PUSH_RE = re.compile(r"(?:\.push|\[\s*['\"]push['\"]\s*\])\s*\(", re.I)
_ARRAY_SHIFT_RE = re.compile(r"(?:\.shift|\[\s*['\"]shift['\"]\s*\])\s*\(", re.I)
_ROTATION_WINDOW_BYTES = 4_096


def analyze_generated_bundle(text: str) -> dict[str, Any]:
    """Return bounded, explainable signals for a generated JavaScript bundle.

    No source is executed and no general JavaScript expression is evaluated.
    The profile combines structural obfuscation with credential collection and
    exfiltration semantics that survive common string-array obfuscators.
    """
    obfuscated_identifiers = _bounded_unique_count(_OBFUSCATED_IDENTIFIER_RE, text, limit=50_000)
    hex_integer_count = _bounded_count(_HEX_INTEGER_RE, text, limit=100_000)
    computed_member_count = _bounded_count(_COMPUTED_IDENTIFIER_RE, text, limit=10_000)
    encoded_character_count = _bounded_count(_ENCODED_CHARACTER_RE, text, limit=100_000)
    array_rotation = _has_local_array_rotation(text)

    obfuscation_indicators: list[str] = []
    if obfuscated_identifiers >= 25:
        obfuscation_indicators.append("systematic-hex-identifiers")
    if hex_integer_count >= 50:
        obfuscation_indicators.append("dense-hex-integers")
    if computed_member_count >= 25:
        obfuscation_indicators.append("dense-computed-members")
    if encoded_character_count >= 100:
        obfuscation_indicators.append("encoded-string-density")
    if array_rotation:
        obfuscation_indicators.append("rotating-string-array")

    credential_families = sorted(
        name for name, pattern in _CREDENTIAL_FAMILIES.items() if pattern.search(text)
    )
    collection_signals = sorted(
        name for name, pattern in _COLLECTION_SIGNALS.items() if pattern.search(text)
    )
    exfiltration_signals = sorted(
        name for name, pattern in _EXFILTRATION_SIGNALS.items() if pattern.search(text)
    )

    # Encoding and computed-member density are common in ordinary webpack
    # output (including large, reputable extensions).  Require a structural
    # obfuscator primitive before this profile can influence a verdict.
    strong_obfuscation = len(obfuscation_indicators) >= 3 and bool(
        {"systematic-hex-identifiers", "rotating-string-array"}
        & set(obfuscation_indicators)
    )
    harvesting_exfiltration = (
        strong_obfuscation
        and len(credential_families) >= 3
        and {"file-read", "directory-enumeration", "home-directory"}.issubset(collection_signals)
        and {"network-client", "outbound-write", "payload-packaging"}.issubset(exfiltration_signals)
    )

    return {
        "strong_obfuscation": strong_obfuscation,
        "harvesting_exfiltration": harvesting_exfiltration,
        "obfuscation_indicators": obfuscation_indicators,
        "credential_families": credential_families,
        "collection_signals": collection_signals,
        "exfiltration_signals": exfiltration_signals,
        "metrics": {
            "obfuscated_identifier_count": obfuscated_identifiers,
            "hex_integer_count": hex_integer_count,
            "computed_member_count": computed_member_count,
            "encoded_character_count": encoded_character_count,
        },
    }


def _bounded_count(pattern: re.Pattern[str], text: str, *, limit: int) -> int:
    count = 0
    for _match in pattern.finditer(text):
        count += 1
        if count >= limit:
            break
    return count


def _bounded_unique_count(pattern: re.Pattern[str], text: str, *, limit: int) -> int:
    values: set[str] = set()
    for match in pattern.finditer(text):
        values.add(match.group(0).lower())
        if len(values) >= limit:
            break
    return len(values)


def _has_local_array_rotation(text: str) -> bool:
    """Recognize a rotation scaffold without correlating unrelated bundle code.

    Large legitimate bundles can contain a polling ``while (true)`` loop plus
    unrelated Array.push/shift calls megabytes away.  A string-array
    obfuscator keeps all three operations in one compact initialization
    scaffold, so require locality before treating this as structural
    obfuscation.
    """
    for loop in _ROTATION_LOOP_RE.finditer(text):
        start = max(0, loop.start() - 256)
        end = min(len(text), loop.end() + _ROTATION_WINDOW_BYTES)
        window = text[start:end]
        if _ARRAY_PUSH_RE.search(window) and _ARRAY_SHIFT_RE.search(window):
            return True
    return False
