from __future__ import annotations

import hashlib
import importlib.util
import os
import signal
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator


_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SEMGREP_RULES = _PACKAGE_ROOT / "provider_rules" / "semgrep"
YARA_RULES = _PACKAGE_ROOT / "provider_rules" / "yara" / "ide-scanner.yar"
SEMGREP_MAX_TARGET_BYTES = 256 * 1024
SEMGREP_RULE_TIMEOUT_SECONDS = 15


def semgrep_timeout_seconds() -> int:
    try:
        configured = int(os.environ.get("GUARDRAILS_SEMGREP_TIMEOUT", "90"))
    except ValueError:
        configured = 90
    return max(15, min(configured, 600))


def find_runtime_executable(name: str) -> str | None:
    """Find a provider installed beside Guardrails before consulting global PATH."""
    environment_bin = Path(sys.executable).parent
    adjacent = shutil.which(name, path=str(environment_bin))
    return adjacent or shutil.which(name)


def run_bounded_process(
    command: list[str],
    *,
    timeout: int | float,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a provider without allowing timed-out descendants to survive."""
    popen_options: dict[str, Any] = {}
    if os.name == "posix":
        popen_options["start_new_session"] = True
    elif os.name == "nt":
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        **popen_options,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(process)
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            return
        except (OSError, subprocess.SubprocessError):
            pass
    process.kill()


@contextmanager
def semgrep_runtime_environment() -> Iterator[dict[str, str]]:
    runtime_dir = Path(tempfile.mkdtemp(prefix="guardrails-semgrep-"))
    environment = os.environ.copy()
    environment["SEMGREP_SETTINGS_FILE"] = str(runtime_dir / "settings.yml")
    environment["SEMGREP_LOG_FILE"] = str(runtime_dir / "semgrep.log")
    environment["SEMGREP_SEND_METRICS"] = "off"
    try:
        yield environment
    finally:
        shutil.rmtree(runtime_dir, ignore_errors=True)


def semgrep_config_arguments() -> list[str]:
    """Return explicit local rule paths so Semgrep never resolves a registry alias."""
    rules = sorted(
        path
        for pattern in ("*.yml", "*.yaml")
        for path in SEMGREP_RULES.rglob(pattern)
        if path.is_file()
    )
    return [value for path in rules for value in ("--config", str(path))]


def provider_diagnostics(*, probe: bool = False) -> dict[str, dict[str, Any]]:
    diagnostics = {
        "semgrep": semgrep_diagnostic(),
        "yara": yara_diagnostic(),
    }
    if probe:
        _probe_semgrep(diagnostics["semgrep"])
        _probe_yara(diagnostics["yara"])
    return diagnostics


def semgrep_diagnostic() -> dict[str, Any]:
    executable = find_runtime_executable("semgrep")
    ruleset_hash = _ruleset_hash(SEMGREP_RULES)
    missing: list[str] = []
    if not executable:
        missing.append("Semgrep executable is not installed")
    if not ruleset_hash:
        missing.append("bundled Semgrep rules are unavailable")
    version = ""
    if not missing and executable:
        version, version_error = _semgrep_runtime_version(executable)
        if version_error:
            missing.append(version_error)
    return {
        "provider": "semgrep",
        "status": "available" if not missing else "unavailable",
        "executable": executable or "",
        "version": version,
        "rules_path": str(SEMGREP_RULES),
        "ruleset_hash": ruleset_hash,
        "error": "; ".join(missing),
        "required": False,
    }


def yara_diagnostic() -> dict[str, Any]:
    executable = find_runtime_executable("yara")
    python_available = importlib.util.find_spec("yara") is not None
    runtime = executable or ("yara-python" if python_available else "")
    ruleset_hash = _ruleset_hash(YARA_RULES)
    missing: list[str] = []
    if not runtime:
        missing.append("YARA runtime is not installed")
    if not ruleset_hash:
        missing.append("bundled YARA rules are unavailable")
    version = ""
    if not missing and runtime:
        version, version_error = _yara_runtime_version(runtime)
        if version_error:
            missing.append(version_error)
    return {
        "provider": "yara",
        "status": "available" if not missing else "unavailable",
        "executable": runtime,
        "version": version,
        "rules_path": str(YARA_RULES),
        "ruleset_hash": ruleset_hash,
        "error": "; ".join(missing),
        "required": False,
    }


def _probe_semgrep(status: dict[str, Any]) -> None:
    if status["status"] != "available":
        return
    version, error = _semgrep_runtime_version(str(status["executable"]))
    if error:
        status.update({"status": "failed", "error": error})
    else:
        status["version"] = version


def _probe_yara(status: dict[str, Any]) -> None:
    if status["status"] != "available":
        return
    if status["executable"] == "yara-python":
        try:
            import yara  # type: ignore[import-not-found]

            yara.compile(filepath=str(YARA_RULES))
        except Exception as exc:
            status.update({"status": "failed", "error": str(exc)})
        return
    version, error = _yara_runtime_version(str(status["executable"]))
    if error:
        status.update({"status": "failed", "error": error})
    else:
        status["version"] = version


@lru_cache(maxsize=8)
def _semgrep_runtime_version(executable: str) -> tuple[str, str]:
    try:
        with semgrep_runtime_environment() as environment:
            result = run_bounded_process(
                [executable, "scan", "--disable-version-check", "--version"],
                timeout=min(semgrep_timeout_seconds(), 20),
                env=environment,
            )
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"Semgrep version probe failed: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return "", detail[:500] or "Semgrep version probe failed"
    version = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    return (version, "") if version else ("", "Semgrep version probe returned no version")


@lru_cache(maxsize=8)
def _yara_runtime_version(runtime: str) -> tuple[str, str]:
    if runtime == "yara-python":
        try:
            import yara  # type: ignore[import-not-found]

            version = str(getattr(yara, "__version__", "") or "")
        except Exception as exc:
            return "", f"YARA version probe failed: {exc}"
        return (version, "") if version else ("", "YARA version probe returned no version")
    try:
        result = run_bounded_process([runtime, "--version"], timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"YARA version probe failed: {exc}"
    if result.returncode != 0:
        return "", result.stderr.strip()[:500] or "YARA version probe failed"
    version = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    return (version, "") if version else ("", "YARA version probe returned no version")


def _ruleset_hash(path: Path) -> str:
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if not path.is_dir():
        return ""
    digest = hashlib.sha256()
    found = False
    for rule in sorted(path.rglob("*")):
        if not rule.is_file():
            continue
        found = True
        digest.update(rule.relative_to(path).as_posix().encode("utf-8"))
        digest.update(rule.read_bytes())
    return digest.hexdigest() if found else ""
