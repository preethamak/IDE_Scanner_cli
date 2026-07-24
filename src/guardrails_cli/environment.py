from __future__ import annotations

import importlib.util
import shutil
import sys
from typing import Any

from .scanner_adapter import analysis_provider_diagnostics, engine_identity, installed_extensions
from .ui.theme import supports_color


DoctorCheck = tuple[str, str, str]


def doctor_checks() -> list[DoctorCheck]:
    installed = installed_extensions()
    engine = engine_identity()
    providers = analysis_provider_diagnostics(probe=True)
    return [
        ("Python", "OK", sys.version.split()[0]),
        (
            "Scanner",
            "OK" if importlib.util.find_spec("ide_scanner") else "FAIL",
            f"engine {engine['version']} · build {engine['build'][:12]}",
        ),
        ("Node AST", "OK" if shutil.which("node") else "FAIL", shutil.which("node") or "node not found"),
        _provider_check("Semgrep", providers["semgrep"]),
        _provider_check("YARA", providers["yara"]),
        ("Installed extensions", "OK" if installed else "WARN", f"{len(installed)} detected"),
        (
            "Color terminal",
            "OK" if supports_color() else "WARN",
            "enabled" if supports_color() else "plain-text mode",
        ),
    ]


def _provider_check(label: str, diagnostic: dict[str, Any]) -> DoctorCheck:
    status = str(diagnostic.get("status") or "unavailable")
    if status == "available":
        executable = str(diagnostic.get("executable") or "available")
        ruleset = str(diagnostic.get("ruleset_hash") or "")
        version = str(diagnostic.get("version") or "")
        readiness = f"version {version}" if version else "runtime ready"
        rule_state = "rules packaged" if label == "Semgrep" else "rules validated"
        return label, "OK", f"{executable} · {readiness} · {rule_state} {ruleset[:12]}"
    detail = str(diagnostic.get("error") or "optional; install Guardrails with the analysis extra")
    return label, "WARN", detail
