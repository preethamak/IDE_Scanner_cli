from __future__ import annotations

import hashlib
import importlib.util
import os
import selectors
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

try:
    import resource
except ImportError:  # pragma: no cover - Windows has no resource module
    resource = None  # type: ignore[assignment]


_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SEMGREP_RULES = _PACKAGE_ROOT / "provider_rules" / "semgrep"
YARA_RULES = _PACKAGE_ROOT / "provider_rules" / "yara" / "ide-scanner.yar"
SEMGREP_MAX_TARGET_BYTES = 256 * 1024
SEMGREP_RULE_TIMEOUT_SECONDS = 15
# Semgrep's native runtime reserves a large virtual address space. Applying a
# process-wide RLIMIT_AS makes semgrep-core abort even when its resident memory
# is modest, so use Semgrep's per-file memory guard for this provider instead.
SEMGREP_MEMORY_LIMIT_MB = 1536
PROVIDER_MEMORY_LIMIT_MB = 1536
PROVIDER_FILE_SIZE_LIMIT_MB = 64
PROVIDER_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024
PROVIDER_OUTPUT_CHUNK_BYTES = 64 * 1024
PROVIDER_OUTPUT_LIMIT_MARKER = "GUARDRAILS_PROVIDER_OUTPUT_LIMIT"

# Provider implementations parse attacker-controlled extension content. They
# must not receive marketplace/CI credentials or arbitrary process settings.
# Keep only variables needed to locate the runtime and preserve text/temp-file
# behavior. The small set of provider settings created in a disposable
# directory by ``semgrep_runtime_environment`` is safe to pass through; broad
# SEMGREP_* inheritance is deliberately avoided because Semgrep also supports
# credential-bearing environment variables.
_SAFE_CHILD_ENV_KEYS = frozenset({
    "PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "VIRTUAL_ENV",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "WINDIR",
    "PATHEXT",
})
_SAFE_SEMGREP_ENV_KEYS = frozenset({
    "SEMGREP_SETTINGS_FILE",
    "SEMGREP_LOG_FILE",
    "SEMGREP_SEND_METRICS",
})


def safe_child_environment(environment: dict[str, str] | None = None) -> dict[str, str]:
    """Return the minimal environment allowed for an untrusted-content parser."""
    source = os.environ if environment is None else environment
    return {
        key: value
        for key, value in source.items()
        if key in _SAFE_CHILD_ENV_KEYS or key in _SAFE_SEMGREP_ENV_KEYS
    }


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
    memory_limit_mb: int | None = None,
    file_size_limit_mb: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a provider without allowing timed-out descendants to survive."""
    process_env = safe_child_environment(env)
    # Source checkouts invoke the bounded workers before the package is
    # installed. Preserve that supported execution mode by making the local
    # package importable to the child, while retaining caller-provided values.
    source_root = str(Path(__file__).resolve().parents[2])
    pythonpath = process_env.get("PYTHONPATH", "")
    if source_root not in pythonpath.split(os.pathsep):
        process_env["PYTHONPATH"] = os.pathsep.join(item for item in (source_root, pythonpath) if item)
    popen_options: dict[str, Any] = {}
    if os.name == "posix":
        popen_options["start_new_session"] = True
        if resource is not None and (memory_limit_mb or file_size_limit_mb):
            popen_options["preexec_fn"] = _resource_limiter(memory_limit_mb, file_size_limit_mb)
    elif os.name == "nt":
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=process_env,
        **popen_options,
    )
    # Keep a small compatibility path for callers that replace Popen with a
    # minimal test double. Real provider processes always expose both pipes.
    if not hasattr(process, "stdout") or not hasattr(process, "stderr"):
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process)
            stdout, stderr = process.communicate()
            raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

    stdout_bytes, stderr_bytes, output_limited = _communicate_bounded(process, command, timeout)
    if output_limited:
        # A truncated provider payload is never a successful analysis. Force a
        # non-zero status even if the child exited between the final read and
        # the parent enforcing the cap.
        stderr_bytes += ("\n" + PROVIDER_OUTPUT_LIMIT_MARKER + "\n").encode("utf-8")
    returncode = process.returncode if not output_limited else -9
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
    )


def _communicate_bounded(
    process: subprocess.Popen[bytes],
    command: list[str],
    timeout: int | float,
) -> tuple[bytes, bytes, bool]:
    """Read provider pipes with a hard parent-memory ceiling."""
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)

    deadline = time.monotonic() + float(timeout)
    output_limited = False

    try:
        while selector.get_map():
            remaining = max(0.0, deadline - time.monotonic())
            if remaining == 0.0:
                _terminate_process_tree(process)
                _close_process_pipes(selector, streams)
                raise subprocess.TimeoutExpired(
                    command,
                    timeout,
                    output=bytes(streams[process.stdout]).decode("utf-8", errors="replace"),
                    stderr=bytes(streams[process.stderr]).decode("utf-8", errors="replace"),
                )
            ready = selector.select(remaining)
            if not ready:
                _terminate_process_tree(process)
                _close_process_pipes(selector, streams)
                raise subprocess.TimeoutExpired(
                    command,
                    timeout,
                    output=bytes(streams[process.stdout]).decode("utf-8", errors="replace"),
                    stderr=bytes(streams[process.stderr]).decode("utf-8", errors="replace"),
                )
            for key, _ in ready:
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), PROVIDER_OUTPUT_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer = streams[stream]
                remaining_bytes = PROVIDER_OUTPUT_LIMIT_BYTES - len(buffer)
                if len(chunk) > remaining_bytes:
                    buffer.extend(chunk[:max(0, remaining_bytes)])
                    output_limited = True
                    _terminate_process_tree(process)
                    break
                buffer.extend(chunk)
            if output_limited:
                break
    finally:
        if output_limited:
            _terminate_process_tree(process)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        _close_process_pipes(selector, streams)
        selector.close()

    return bytes(streams[process.stdout]), bytes(streams[process.stderr]), output_limited


def _close_process_pipes(selector: selectors.BaseSelector, streams: dict[Any, bytearray]) -> None:
    for stream in streams:
        try:
            selector.unregister(stream)
        except (KeyError, ValueError):
            pass
        if not stream.closed:
            stream.close()


def _resource_limiter(memory_limit_mb: int | None, file_size_limit_mb: int | None):
    def apply_limits() -> None:
        if resource is None:
            return
        if memory_limit_mb:
            limit = int(memory_limit_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        if file_size_limit_mb:
            limit = int(file_size_limit_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    return apply_limits


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
    environment = safe_child_environment()
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
        "output_limit_bytes": PROVIDER_OUTPUT_LIMIT_BYTES,
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
        "output_limit_bytes": PROVIDER_OUTPUT_LIMIT_BYTES,
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
