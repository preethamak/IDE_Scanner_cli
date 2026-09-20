from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import os
import selectors
import signal
import shutil
import re
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from .jsonc import loads_jsonc
from .runtime_dependencies import provision_for_extension

try:
    import resource
except ImportError:  # pragma: no cover - Windows has no resource module
    resource = None  # type: ignore[assignment]

CANARY_VALUE = "IDE_SCANNER_CANARY_SECRET_DO_NOT_EXFILTRATE"
CANARY_FILES = (
    ".env",
    ".npmrc",
    ".ssh/id_ed25519",
    ".aws/credentials",
)
MAX_RUNTIME_FILES = 100_000
MAX_RUNTIME_BYTES = 2 * 1024 * 1024 * 1024
MAX_RUNTIME_FILE_BYTES = 512 * 1024 * 1024
MAX_RUNTIME_TIMEOUT_SECONDS = 300
MAX_RUNTIME_MEMORY_BYTES = 1536 * 1024 * 1024
MAX_RUNTIME_OPEN_FILES = 4096
MAX_RUNTIME_OUTPUT_BYTES = 4 * 1024 * 1024
RUNTIME_OUTPUT_CHUNK_BYTES = 64 * 1024
MAX_EXTERNAL_TRACE_BYTES = 8 * 1024 * 1024
EXTERNAL_TRACE_ENV = "GUARDRAILS_RUNTIME_EXTERNAL_TRACE"
RUNTIME_BWRAP_SUDO_ENV = "GUARDRAILS_RUNTIME_BWRAP_SUDO"
RUNTIME_EVENT_HANDSHAKE = "GUARDRAILS_RUNTIME_HANDSHAKE_V1:"
RUNTIME_EVENT_PREFIX = "GUARDRAILS_RUNTIME_EVENT_V1:"
RUNTIME_EVENT_OUTPUT_LIMIT_MARKER = "GUARDRAILS_RUNTIME_EVENT_OUTPUT_LIMIT"
# Bubblewrap itself creates these relative mount/namespace paths before the
# extension process starts. They are infrastructure evidence, not extension
# behavior; retaining them creates dozens of misleading INFO findings in an
# otherwise clean runtime report.
_SANDBOX_SETUP_RELATIVE_PATHS = frozenset({
    "uid_map", "gid_map", "setgroups", "newroot", "oldroot", "proc", "dev",
    "usr", "local", "bin", "sbin", "lib", "lib64", "etc", "null", "zero",
    "full", "random", "urandom", "shm", "pts", "ptmx", "tmp", "home",
    "guardrails", "workspace", "target", "runner", "node-runtime-hook.js",
    "activate-entrypoint.js",
})


def _external_trace_requested() -> bool:
    return os.environ.get(EXTERNAL_TRACE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _external_trace_executable() -> str | None:
    return shutil.which("strace")


def _bwrap_command() -> list[str]:
    """Return Bubblewrap with an explicit managed-runner privilege boundary."""
    if os.environ.get(RUNTIME_BWRAP_SUDO_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
        if shutil.which("sudo") is None:
            raise ValueError(f"{RUNTIME_BWRAP_SUDO_ENV}=1 requires sudo for the Bubblewrap namespace boundary.")
        return ["sudo", "-n", "bwrap"]
    return ["bwrap"]


def external_trace_available() -> bool:
    """Return whether the production external-trace contract is enabled."""
    return _external_trace_requested() and _external_trace_executable() is not None


def sandbox_preflight(timeout_seconds: int = 10) -> dict[str, Any]:
    """Verify that the production runtime can create the required namespace.

    Bubblewrap being installed is not sufficient: managed workers can still
    lack the kernel capability needed to create a network or PID namespace.
    A tiny ``/bin/true`` probe exercises the same isolation boundary used for
    extension execution and never runs extension code. Callers should refuse
    runtime-enabled publication when this returns ``status != ready``.
    """
    if not 1 <= timeout_seconds <= 60:
        raise ValueError("Sandbox preflight timeout must be between 1 and 60 seconds")
    if shutil.which("bwrap") is None:
        return {
            "schema_version": "guardrails.sandbox-preflight.v1",
            "status": "unavailable",
            "backend": "bubblewrap",
            "execution": "controlled-bubblewrap",
            "isolation": {"network": "disabled", "process": "isolated-pid-namespace"},
            "error": "Bubblewrap (bwrap) is not installed.",
        }
    external_trace = _external_trace_executable()
    if _external_trace_requested() and external_trace is None:
        return {
            "schema_version": "guardrails.sandbox-preflight.v1",
            "status": "unavailable",
            "backend": "bubblewrap",
            "execution": "controlled-bubblewrap",
            "isolation": {"network": "disabled", "process": "isolated-pid-namespace"},
            "error": f"{EXTERNAL_TRACE_ENV}=1 requires strace for external syscall evidence, but strace is not installed.",
        }

    try:
        bwrap_command = _bwrap_command()
    except ValueError as exc:
        return {
            "schema_version": "guardrails.sandbox-preflight.v1",
            "status": "unavailable",
            "backend": "bubblewrap",
            "execution": "controlled-bubblewrap",
            "isolation": {"network": "disabled", "process": "isolated-pid-namespace"},
            "error": str(exc),
        }
    command = [
        *bwrap_command,
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--unshare-user",
        "--uid", "65534",
        "--gid", "65534",
        "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/usr/local", "/usr/local",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/sbin", "/sbin",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64",
        "--ro-bind", "/etc", "/etc",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--clearenv",
        "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--",
        "/bin/true",
    ]
    external_trace_path: Path | None = None
    external_trace_dir: Path | None = None
    if _external_trace_requested() and external_trace:
        external_trace_dir = Path(tempfile.mkdtemp(prefix="guardrails-preflight-"))
        external_trace_path = external_trace_dir / "preflight.strace"
        external_trace_path.touch(mode=0o666)
        os.chmod(external_trace_path, 0o666)
    if _external_trace_requested() and external_trace:
        trace_prefix = [external_trace]
        if os.environ.get(RUNTIME_BWRAP_SUDO_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
            if shutil.which("sudo") is None:
                raise ValueError(f"{RUNTIME_BWRAP_SUDO_ENV}=1 requires sudo for the Bubblewrap namespace boundary.")
            trace_prefix = ["sudo", "-n", external_trace]
        command = [
            *trace_prefix,
            "-f",
            "-qq",
            "-o",
            str(external_trace_path),
            "-e",
            "trace=file,process,network",
            "--",
            *command,
        ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "schema_version": "guardrails.sandbox-preflight.v1",
            "status": "unavailable",
            "backend": "bubblewrap",
            "execution": "controlled-bubblewrap",
            "isolation": {"network": "disabled", "process": "isolated-pid-namespace"},
            "error": f"Bubblewrap preflight timed out after {timeout_seconds}s.",
        }
    except OSError as exc:
        return {
            "schema_version": "guardrails.sandbox-preflight.v1",
            "status": "unavailable",
            "backend": "bubblewrap",
            "execution": "controlled-bubblewrap",
            "isolation": {"network": "disabled", "process": "isolated-pid-namespace"},
            "error": f"Bubblewrap preflight could not start: {exc}",
        }
    finally:
        if external_trace_path is not None:
            external_trace_path.unlink(missing_ok=True)
        if external_trace_dir is not None:
            shutil.rmtree(external_trace_dir, ignore_errors=True)

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "Bubblewrap exited unsuccessfully").strip()
        return {
            "schema_version": "guardrails.sandbox-preflight.v1",
            "status": "unavailable",
            "backend": "bubblewrap",
            "execution": "controlled-bubblewrap",
            "isolation": {"network": "disabled", "process": "isolated-pid-namespace"},
            "returncode": result.returncode,
            "error": detail[-500:],
        }
    return {
        "schema_version": "guardrails.sandbox-preflight.v1",
        "status": "ready",
        "backend": "bubblewrap",
        "execution": "controlled-bubblewrap",
        "isolation": {"network": "disabled", "process": "isolated-pid-namespace"},
        "returncode": 0,
    }


def run_sandbox(path: Path, allow_execute: bool = False, timeout_seconds: int = 15) -> dict[str, Any]:
    if not 1 <= timeout_seconds <= MAX_RUNTIME_TIMEOUT_SECONDS:
        raise ValueError(f"Sandbox timeout must be between 1 and {MAX_RUNTIME_TIMEOUT_SECONDS} seconds")
    source = path.expanduser().resolve()
    if allow_execute and shutil.which("bwrap") is None:
        raise ValueError(
            "Executable sandbox mode requires the Bubblewrap (bwrap) OS isolation backend; execution was refused."
        )
    external_trace_requested = _external_trace_requested()
    external_trace = _external_trace_executable()
    if allow_execute and external_trace_requested and external_trace is None:
        raise ValueError(
            f"{EXTERNAL_TRACE_ENV}=1 requires strace for external syscall evidence; execution was refused."
        )
    with tempfile.TemporaryDirectory(prefix="ide-scanner-sandbox-") as tmp:
        root = Path(tmp)
        target = _prepare_target(source, root / "target")
        manifest = _read_manifest(target / "package.json")
        runtime_dependencies = provision_for_extension(target, manifest)
        extension_id = f"{manifest.get('publisher') or 'unknown'}.{manifest.get('name') or target.name}"
        home = root / "home"
        workspace = root / "workspace"
        trace_file = root / "trace.jsonl"
        hook_file = root / "node-runtime-hook.js"
        entrypoint_runner = root / "activate-entrypoint.js"
        entrypoint = _extension_main(manifest)
        home.mkdir()
        workspace.mkdir()
        if os.environ.get(RUNTIME_BWRAP_SUDO_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
            # A privileged Bubblewrap process maps itself to UID 65534 before
            # resolving bind sources. Make only this disposable scan tree
            # traversable so the mapped child can read its prepared inputs.
            for directory in (root, root / "target", home, workspace):
                directory.chmod(0o755)
        canaries = _write_canaries(home)
        _seed_runtime_workspace(workspace, manifest)
        _write_node_hook(hook_file, trace_file, home)
        _write_entrypoint_runner(entrypoint_runner, manifest)
        observations: list[dict[str, Any]] = []
        plan = {
            "extension_id": extension_id,
            "source": str(source),
            "target": str(target),
            "allow_execute": allow_execute,
            "backend": "bubblewrap" if allow_execute else "plan-only",
            "isolation": {
                "network": "disabled",
                "filesystem": "copied-artifact-plus-synthetic-home-and-workspace",
                "process": "isolated-pid-namespace",
                "uid": 65534,
            },
            "sandbox_home": str(home),
            "sandbox_workspace": str(workspace),
            "trace_file": None,
            "runtime_event_transport": "authenticated-stderr-v1",
            "instrumentation": {
                "node_require_hook": str(hook_file),
                "entrypoint_runner": str(entrypoint_runner),
                "entrypoint": entrypoint or "",
                "entrypoint_status": "declared" if entrypoint else "not-applicable",
                "captures": [
                    "fs",
                    "child_process",
                    "http",
                    "https",
                    "net",
                    "dns",
                    "registered_commands",
                    "webview_messages",
                ],
                "external_syscall_trace": {
                    "requested": external_trace_requested,
                    "available": bool(external_trace),
                    "backend": "strace" if external_trace_requested and external_trace else "not-requested",
                    "scope": "file,process,network syscalls outside the extension process",
                },
            },
            "runtime_probes": {
                "registered_commands": "invoke up to 50 handlers with a synthetic canary argument",
                "webview_messages": "deliver one synthetic canary message to each registered handler",
            },
            "runtime_dependencies": runtime_dependencies,
            "resource_limits": {
                "max_files": MAX_RUNTIME_FILES,
                "max_total_bytes": MAX_RUNTIME_BYTES,
                "max_file_bytes": MAX_RUNTIME_FILE_BYTES,
                "max_memory_bytes": MAX_RUNTIME_MEMORY_BYTES,
                "timeout_seconds_per_action": timeout_seconds,
            },
            "canary_files": canaries,
            "commands": _planned_commands(manifest),
        }
        if allow_execute:
            observations.extend(_execute_planned_commands(
                target,
                plan["commands"],
                home,
                workspace,
                timeout_seconds,
                hook_file,
                trace_file,
                entrypoint_runner,
                canaries,
            ))
            observations.extend(_execute_entrypoint(
                entrypoint_runner,
                home,
                workspace,
                timeout_seconds,
                hook_file,
                trace_file,
                target,
                entrypoint=entrypoint,
                canary_files=canaries,
            ))
        return {
            "schema_version": "0.1.0",
            "mode": "executed" if allow_execute else "plan-only",
            "canary": {
                "value_sha256_hint": "present-in-sandbox-only",
                "files": canaries,
            },
            "plan": plan,
            "extensions": {
                extension_id: observations,
            },
        }


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        parsed = loads_jsonc(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _write_canaries(home: Path) -> list[str]:
    written: list[str] = []
    for rel in CANARY_FILES:
        file = home / rel
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(f"IDE_SCANNER_CANARY={CANARY_VALUE}\n", encoding="utf-8")
        written.append(str(file))
    return written


def _seed_runtime_workspace(workspace: Path, manifest: dict[str, Any]) -> None:
    """Provide a minimal, non-secret project for language-aware extensions.

    A VS Code extension is normally activated with the user's workspace open.
    An empty synthetic workspace makes language servers that require project
    discovery fail before they can be observed. Seed only the fixture that
    the extension declares support for; the files contain no credentials,
    network endpoints, or package dependencies.
    """
    languages: set[str] = set()
    for contribution in (manifest.get("contributes") or {}).get("languages", []) or []:
        if isinstance(contribution, dict):
            language_id = contribution.get("id")
            if isinstance(language_id, str):
                languages.add(language_id.lower())
    if "rust" not in languages:
        return
    source = workspace / "src" / "lib.rs"
    source.parent.mkdir(parents=True, exist_ok=True)
    (workspace / "Cargo.toml").write_text(
        "[package]\n"
        "name = \"guardrails_runtime_fixture\"\n"
        "version = \"0.1.0\"\n"
        "edition = \"2021\"\n",
        encoding="utf-8",
    )
    source.write_text(
        "pub fn guardrails_runtime_fixture() -> u32 { 42 }\n",
        encoding="utf-8",
    )


def _planned_commands(manifest: dict[str, Any]) -> list[dict[str, str]]:
    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    commands: list[dict[str, str]] = []
    for name in ("preinstall", "install", "postinstall", "vscode:uninstall"):
        command = scripts.get(name)
        if isinstance(command, str) and command.strip():
            commands.append({"kind": "lifecycle", "name": name, "command": command})
    return commands


def _extension_main(manifest: dict[str, Any]) -> str | None:
    # Desktop extensions normally declare `main`; browser-targeted VS Code
    # extensions declare `browser`. Execute the latter through the same
    # instrumented Node harness so a capability-heavy web extension cannot be
    # reported as dynamically covered while its only entrypoint was skipped.
    main = str(manifest.get("main") or manifest.get("browser") or "").strip()
    return main or None


def _execute_planned_commands(
    target: Path,
    commands: list[dict[str, str]],
    home: Path,
    workspace: Path,
    timeout_seconds: int,
    hook_file: Path,
    trace_file: Path,
    entrypoint_runner: Path,
    canary_files: list[str],
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    before = _snapshot(home, workspace, target)
    for command in commands:
        try:
            result = _run_isolated(
                ["/bin/sh", "-lc", command["command"]],
                target=target,
                home=home,
                workspace=workspace,
                hook_file=hook_file,
                trace_file=trace_file,
                entrypoint_runner=entrypoint_runner,
                cwd="/target",
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            combined = f"{result.stdout}\n{result.stderr}"
            events, transport_ok = _verified_runtime_events(result.stderr)
            observations.extend(_observations_from_events(events, canary_files))
            external_observations, external_trace_ok = _external_trace_observations(
                result,
                canary_files,
            )
            observations.extend(external_observations)
            if _command_uses_node(command["command"]) and not transport_ok:
                observations.append({
                    "kind": "sandbox_error",
                    "phase": "lifecycle",
                    "script": command["name"],
                    "evidence": "runtime event transport failed integrity validation",
                })
            if _external_trace_requested() and not external_trace_ok:
                observations.append({
                    "kind": "sandbox_error",
                    "phase": "lifecycle",
                    "script": command["name"],
                    "evidence": "external syscall trace was requested but could not be validated",
                })
            if result.returncode != 0:
                observations.append({
                    # The lifecycle command itself failed, but that does not
                    # invalidate the separate activation probe below. Keep
                    # the failed command visible without downgrading the
                    # whole dynamic provider to incomplete.
                    "kind": "runtime_lifecycle_error",
                    "phase": "lifecycle",
                    "script": command["name"],
                    "returncode": result.returncode,
                    "evidence": "lifecycle script exited unsuccessfully",
                })
            observations.append({
                "kind": "lifecycle_executed",
                "script": command["name"],
                "returncode": result.returncode,
                "stdout_bytes": len(result.stdout.encode("utf-8", errors="replace")),
                "stderr_bytes": len(result.stderr.encode("utf-8", errors="replace")),
            })
            if CANARY_VALUE in combined:
                observations.append({
                    "kind": "canary_exposed",
                    "script": command["name"],
                    "destination": "stdout-or-stderr",
                    "evidence": "synthetic canary appeared in process output; no external transfer was observed",
                })
        except subprocess.TimeoutExpired:
            observations.append({
                "kind": "runtime_timeout",
                "script": command["name"],
                "phase": "lifecycle",
                "evidence": f"script timed out after {timeout_seconds}s",
            })
    after = _snapshot(home, workspace, target)
    for path in sorted(after - before):
        observations.append({
            "kind": "filesystem_write",
            "path": path,
        })
    return observations


def _execute_entrypoint(
    runner: Path,
    home: Path,
    workspace: Path,
    timeout_seconds: int,
    hook_file: Path,
    trace_file: Path,
    target: Path,
    *,
    entrypoint: str | None = "./extension.js",
    canary_files: list[str] | None = None,
) -> list[dict[str, Any]]:
    if not entrypoint:
        return [{
            "kind": "entrypoint_not_applicable",
            "phase": "activation",
            "evidence": "manifest declares no Node activation entrypoint",
        }]
    try:
        result = _run_isolated(
            ["node", "/runner/activate-entrypoint.js"],
            target=target,
            home=home,
            workspace=workspace,
            hook_file=hook_file,
            trace_file=trace_file,
            entrypoint_runner=runner,
            cwd="/workspace",
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        combined = f"{result.stdout}\n{result.stderr}"
        events, transport_ok = _verified_runtime_events(result.stderr)
        external_observations, external_trace_ok = _external_trace_observations(result, canary_files or [])
        succeeded = result.returncode == 0
        # A controlled extension process can exit nonzero after it has already
        # executed and emitted authenticated observations. Network denial,
        # platform-specific child binaries, and optional host integrations are
        # common examples. Preserve that exit as evidence instead of treating
        # it as a harness failure; missing trace, invalid transport, and
        # timeout remain hard coverage failures below.
        executed_with_error = not succeeded and bool(events or external_observations)
        observations: list[dict[str, Any]] = [{
            "kind": "entrypoint_executed" if succeeded else ("runtime_entrypoint_error" if executed_with_error else "sandbox_error"),
            "phase": "activation" if not succeeded else None,
            "returncode": result.returncode,
            "stdout_bytes": len(result.stdout.encode("utf-8", errors="replace")),
            "stderr_bytes": len(result.stderr.encode("utf-8", errors="replace")),
        }]
        observations[0] = {key: value for key, value in observations[0].items() if value is not None}
        if result.returncode != 0 and result.stderr:
            observations[0]["stderr_excerpt"] = result.stderr[-2000:]
        observations.extend(_observations_from_events(events, canary_files or []))
        observations.extend(external_observations)
        if not transport_ok:
            observations.append({
                "kind": "sandbox_error",
                "phase": "activation",
                "evidence": "runtime event transport failed integrity validation",
            })
        if _external_trace_requested() and not external_trace_ok:
            observations.append({
                "kind": "sandbox_error",
                "phase": "activation",
                "evidence": "external syscall trace was requested but could not be validated",
            })
        if CANARY_VALUE in combined:
            observations.append({
                "kind": "canary_exposed",
                "destination": "stdout-or-stderr",
                "evidence": "synthetic canary appeared in process output; no external transfer was observed",
            })
        return observations
    except FileNotFoundError:
        return [{
            "kind": "sandbox_error",
            "evidence": "node executable was not found; entrypoint runtime instrumentation was skipped",
        }]
    except subprocess.TimeoutExpired:
        return [{
            "kind": "runtime_timeout",
            "phase": "activation",
            "evidence": f"entrypoint timed out after {timeout_seconds}s",
        }]


def _run_isolated(
    command: list[str],
    *,
    target: Path,
    home: Path,
    workspace: Path,
    hook_file: Path,
    trace_file: Path,
    entrypoint_runner: Path,
    cwd: str,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """Run an extension command in a fail-closed Bubblewrap namespace.

    The host artifact is copied before this function is reached. Only the
    copied artifact, synthetic home/workspace, the instrumentation files, and
    read-only runtime libraries are mounted into the child namespace. Network
    and the process namespace are isolated, and the child is mapped to nobody.
    """
    if shutil.which("bwrap") is None:
        raise ValueError(
            "Executable sandbox mode requires the Bubblewrap (bwrap) OS isolation backend; execution was refused."
        )
    args = [
        *_bwrap_command(),
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--unshare-user",
        "--uid", "65534",
        "--gid", "65534",
        "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/usr/local", "/usr/local",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/sbin", "/sbin",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64",
        "--ro-bind", "/etc", "/etc",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--dir", "/home",
        "--bind", str(home), "/home/guardrails",
        "--dir", "/workspace",
        "--bind", str(workspace), "/workspace",
        "--dir", "/target",
        "--bind", str(target), "/target",
        "--dir", "/runner",
        "--ro-bind", str(hook_file), "/runner/node-runtime-hook.js",
        "--ro-bind", str(entrypoint_runner), "/runner/activate-entrypoint.js",
        "--clearenv",
        "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--setenv", "HOME", "/home/guardrails",
        "--setenv", "USERPROFILE", "/home/guardrails",
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "IDE_SCANNER_SANDBOX", "1",
        "--setenv", "IDE_SCANNER_CANARY", CANARY_VALUE,
        "--setenv", "VSCODE_CWD", "/workspace",
        # Node derives an extremely small V8 heap from the inherited virtual
        # address-space cap unless an explicit bounded heap is supplied. That
        # makes ordinary bundled extensions fail with an OOM before activate()
        # runs, which is a harness failure rather than extension evidence.
        "--setenv", "NODE_OPTIONS", "--max-old-space-size=512 --require=/runner/node-runtime-hook.js",
        "--chdir", cwd,
        "--",
        *command,
    ]
    external_trace_prefix: Path | None = None
    if _external_trace_requested():
        external_trace = _external_trace_executable()
        if external_trace is None:
            raise ValueError(
                f"{EXTERNAL_TRACE_ENV}=1 requires strace for external syscall evidence; execution was refused."
            )
        external_trace_prefix = trace_file.parent / f"{trace_file.name}.{time.monotonic_ns()}.strace"
        external_trace_prefix.touch(mode=0o666)
        os.chmod(external_trace_prefix, 0o666)
        trace_prefix = [external_trace]
        if os.environ.get(RUNTIME_BWRAP_SUDO_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
            if shutil.which("sudo") is None:
                raise ValueError(f"{RUNTIME_BWRAP_SUDO_ENV}=1 requires sudo for the Bubblewrap namespace boundary.")
            trace_prefix = ["sudo", "-n", external_trace]
        args = [
            *trace_prefix,
            "-f",
            "-qq",
            "-s",
            "256",
            "-o",
            str(external_trace_prefix),
            "-e",
            "trace=file,process,network",
            "--",
            *args,
        ]
    if os.name == "posix":
        timeout = int(kwargs.get("timeout", MAX_RUNTIME_TIMEOUT_SECONDS))
        kwargs["preexec_fn"] = _runtime_resource_limiter(
            timeout,
            max_file_bytes=MAX_EXTERNAL_TRACE_BYTES if external_trace_prefix is not None else None,
        )
    result = _run_bounded_capture(args, **kwargs)
    if external_trace_prefix is not None:
        setattr(result, "_guardrails_external_trace_prefix", str(external_trace_prefix))
    return result


def _run_bounded_capture(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Capture isolated-process output without allowing unbounded parent memory use."""
    capture_output = bool(kwargs.pop("capture_output", False))
    text_output = bool(kwargs.pop("text", False))
    check = bool(kwargs.pop("check", False))
    timeout = kwargs.pop("timeout", None)
    if not capture_output:
        raise ValueError("Runtime execution requires bounded captured output")
    if kwargs.pop("input", None) is not None:
        raise ValueError("Runtime execution does not accept stdin input")

    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=(os.name == "posix"),
        **kwargs,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)

    deadline = time.monotonic() + float(timeout) if timeout is not None else None
    output_limited = False
    timed_out = False

    def stop_process() -> None:
        if process.poll() is not None:
            return
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
                return
            except (ProcessLookupError, PermissionError):
                pass
        try:
            process.kill()
        except ProcessLookupError:
            pass

    try:
        while selector.get_map():
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            if remaining == 0.0:
                timed_out = True
                stop_process()
                break
            ready = selector.select(remaining)
            if not ready:
                timed_out = True
                stop_process()
                break
            for key, _ in ready:
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), RUNTIME_OUTPUT_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer = streams[stream]
                remaining_bytes = MAX_RUNTIME_OUTPUT_BYTES - len(buffer)
                if len(chunk) > remaining_bytes:
                    buffer.extend(chunk[:max(0, remaining_bytes)])
                    output_limited = True
                    stop_process()
                    break
                buffer.extend(chunk)
            if output_limited:
                break
    finally:
        if timed_out or output_limited:
            stop_process()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            stop_process()
            process.wait(timeout=1)
        for stream in streams:
            try:
                selector.unregister(stream)
            except (KeyError, ValueError):
                pass
            if not stream.closed:
                stream.close()
        selector.close()

    stdout_bytes = bytes(streams[process.stdout])
    stderr_bytes = bytes(streams[process.stderr])
    if output_limited:
        stderr_bytes += ("\n" + RUNTIME_EVENT_OUTPUT_LIMIT_MARKER + "\n").encode("utf-8")
    stdout = stdout_bytes.decode("utf-8", errors="replace") if text_output else stdout_bytes
    stderr = stderr_bytes.decode("utf-8", errors="replace") if text_output else stderr_bytes
    if timed_out:
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr)
    result = subprocess.CompletedProcess(command, process.returncode, stdout=stdout, stderr=stderr)
    if check and result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command, output=stdout, stderr=stderr)
    return result


def _command_uses_node(command: str) -> bool:
    words = {"node", "nodejs", "npm", "npx", "yarn", "pnpm"}
    return any(token in words for token in command.replace(";", " ").split())


def _runtime_resource_limiter(timeout_seconds: int, *, max_file_bytes: int | None = None):
    """Apply inherited limits to Bubblewrap and the extension process tree.

    Wall-clock timeouts alone do not protect a production worker from an
    extension that consumes memory or fills the writable sandbox. The limits
    are inherited by the isolated child and are intentionally conservative;
    a limit breach becomes a visible runtime error and therefore cannot turn
    into a completed approval.
    """
    def apply_limits() -> None:
        if resource is None:  # pragma: no cover - POSIX always imports it
            return
        # RLIMIT_AS is a virtual-address cap. Node/V8 and native extension
        # loaders reserve address space far beyond their resident memory; a
        # 1.5 GiB RLIMIT_AS therefore makes ordinary bundled extensions fail
        # with a false OOM at ~20 MiB. RLIMIT_DATA bounds process data without
        # breaking those legitimate virtual reservations. Keep an AS fallback
        # only for platforms that do not expose RLIMIT_DATA.
        memory_limit = MAX_RUNTIME_MEMORY_BYTES
        memory_limit_applied = False
        if hasattr(resource, "RLIMIT_DATA"):
            try:
                resource.setrlimit(resource.RLIMIT_DATA, (memory_limit, memory_limit))
                memory_limit_applied = True
            except (OSError, ValueError):
                pass
        if not memory_limit_applied and hasattr(resource, "RLIMIT_AS"):
            try:
                resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
            except (OSError, ValueError):
                pass
        try:
            file_limit = min(max_file_bytes or MAX_RUNTIME_FILE_BYTES, MAX_RUNTIME_BYTES)
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
        except (OSError, ValueError):
            pass
        try:
            cpu_limit = max(1, timeout_seconds + 1)
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
        except (OSError, ValueError):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_RUNTIME_OPEN_FILES, MAX_RUNTIME_OPEN_FILES))
        except (OSError, ValueError):
            pass

    return apply_limits


def _sandbox_env(home: Path, workspace: Path, hook_file: Path, trace_file: Path) -> dict[str, str]:
    env = os.environ.copy()
    existing_node_options = env.get("NODE_OPTIONS", "")
    require_hook = f"--require={hook_file}"
    env.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "IDE_SCANNER_SANDBOX": "1",
        "IDE_SCANNER_CANARY": CANARY_VALUE,
        "VSCODE_CWD": str(workspace),
        "NODE_OPTIONS": f"{require_hook} {existing_node_options}".strip(),
    })
    return env


def _write_node_hook(path: Path, trace_file: Path, home: Path) -> None:
    path.write_text(
        r"""
const fs = require('fs');
const crypto = require('crypto');
const Module = require('module');
const sandboxHome = process.env.HOME || '';
const transportWrite = process.stderr.write.bind(process.stderr);
const transportSecret = crypto.randomBytes(32).toString('hex');

function writeTransport(line) {
  try { transportWrite(line + '\n'); } catch (_) {}
}

writeTransport('GUARDRAILS_RUNTIME_HANDSHAKE_V1:' + transportSecret);

function safeString(value) {
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  if (value && value.href) return String(value.href);
  try { return JSON.stringify(value); } catch (_) { return String(value); }
}

const canaryValue = process.env.IDE_SCANNER_CANARY || '';
const canaryEncodings = [
  canaryValue,
  Buffer.from(canaryValue, 'utf8').toString('base64'),
  Buffer.from('IDE_SCANNER_CANARY=' + canaryValue + '\n', 'utf8').toString('base64'),
].filter(Boolean);
function containsCanary(value) {
  const text = safeString(value);
  return canaryEncodings.some((encoded) => text.includes(encoded));
}

function record(event) {
  const payload = JSON.stringify(Object.assign({ts: Date.now()}, event));
  const mac = crypto.createHmac('sha256', transportSecret).update(payload).digest('hex');
  writeTransport('GUARDRAILS_RUNTIME_EVENT_V1:' + Buffer.from(payload, 'utf8').toString('base64') + '.' + mac);
}

const commandHandlers = new Map();
const webviewMessageHandlers = [];
global.__guardrailsProbe = {
  async run() {
    let count = 0;
    for (const [name, handler] of commandHandlers.entries()) {
      if (count >= 50) break;
      count += 1;
      record({kind: 'command_probe', command: name});
      try {
        await Promise.resolve(handler({guardrailsCanary: process.env.IDE_SCANNER_CANARY}));
      } catch (error) {
        record({kind: 'command_probe_error', command: name, error: safeString(error && error.message ? error.message : error)});
      }
    }
    for (const handler of webviewMessageHandlers) {
      record({kind: 'webview_message_probe'});
      try {
        await Promise.resolve(handler({type: 'guardrails.canary', value: process.env.IDE_SCANNER_CANARY}));
      } catch (error) {
        record({kind: 'webview_message_probe_error', error: safeString(error && error.message ? error.message : error)});
      }
    }
  },
};

function patchFunction(object, name, handler) {
  const original = object[name];
  if (typeof original !== 'function') return;
  object[name] = function(...args) {
    try { handler(args); } catch (_) {}
    return original.apply(this, args);
  };
}

for (const name of ['readFileSync', 'readFile', 'createReadStream']) {
  patchFunction(fs, name, (args) => record({kind: 'fs_read', api: name, path: safeString(args[0])}));
}
for (const name of ['writeFileSync', 'writeFile', 'appendFileSync', 'appendFile', 'createWriteStream', 'rmSync', 'rm', 'unlinkSync', 'unlink', 'renameSync', 'rename', 'copyFileSync', 'copyFile']) {
  patchFunction(fs, name, (args) => record({kind: 'fs_write', api: name, path: safeString(args[0])}));
}
try {
  const promises = require('fs/promises');
  for (const name of ['readFile', 'open', 'access', 'readdir', 'stat', 'lstat']) {
    patchFunction(promises, name, (args) => record({kind: 'fs_read', api: 'fs.promises.' + name, path: safeString(args[0])}));
  }
  for (const name of ['writeFile', 'appendFile', 'rm', 'unlink', 'rename', 'copyFile', 'mkdir', 'chmod']) {
    patchFunction(promises, name, (args) => record({kind: 'fs_write', api: 'fs.promises.' + name, path: safeString(args[0])}));
  }
} catch (_) {}

try {
  const child_process = require('child_process');
  for (const name of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
    patchFunction(child_process, name, (args) => record({kind: 'process_exec', api: name, command: safeString(args[0])}));
  }
} catch (_) {}

function fakeRequest(destination) {
  const events = {};
  return {
    write(value) {
      const text = safeString(value);
      record({kind: 'network_write', target: destination || 'unknown', contains_canary: containsCanary(text), bytes: text.length});
      return true;
    },
    end() { if (events.response) setImmediate(() => events.response({ statusCode: 204, on() {} })); return undefined; },
    on(name, handler) { events[name] = handler; return this; },
    once(name, handler) { events[name] = handler; return this; },
    setTimeout() { return this; },
    abort() {},
    destroy() {}
  };
}

function patchNetwork(moduleName) {
  try {
    const mod = require(moduleName);
    for (const name of ['request', 'get']) {
      mod[name] = function(...args) {
        const destination = safeString(args[0]);
        record({kind: 'network', api: moduleName + '.' + name, target: destination});
        const callback = args.find((arg) => typeof arg === 'function');
        const request = fakeRequest(destination);
        if (callback) setImmediate(() => callback({ statusCode: 204, on() {} }));
        return request;
      };
    }
  } catch (_) {}
}
patchNetwork('http');
patchNetwork('https');

// Node's global fetch and newer HTTP clients bypass the legacy http/https
// wrappers above. Keep the runtime observation contract consistent across
// CommonJS, ESM-transpiled, and undici-backed extensions.
try {
  if (typeof globalThis.fetch === 'function') {
    globalThis.fetch = function(...args) {
      const destination = safeString(args[0]);
      record({kind: 'network', api: 'global.fetch', target: destination});
      const init = args[1];
      if (init && typeof init === 'object' && init.body !== undefined) {
        const body = safeString(init.body);
        record({kind: 'network_write', target: destination, contains_canary: containsCanary(body), bytes: body.length});
      }
      return Promise.resolve({
        status: 204,
        ok: true,
        headers: { get() { return null; } },
        text: async () => '',
        json: async () => ({}),
        arrayBuffer: async () => new ArrayBuffer(0),
      });
    };
  }
} catch (_) {}

try {
  const http2 = require('http2');
  if (typeof http2.connect === 'function') {
    http2.connect = function(...args) {
      const destination = safeString(args[0]);
      record({kind: 'network', api: 'http2.connect', target: destination});
      return { request: () => fakeRequest(destination), close() {}, destroy() {} };
    };
  }
} catch (_) {}

try {
  const tls = require('tls');
  for (const name of ['connect', 'createConnection']) {
    if (typeof tls[name] !== 'function') continue;
    tls[name] = function(...args) {
      const destination = safeString(args[0]);
      record({kind: 'network', api: 'tls.' + name, target: destination});
      return fakeRequest(destination);
    };
  }
} catch (_) {}

try {
  const net = require('net');
  net.connect = function(...args) { const destination = safeString(args[0]); record({kind: 'network', api: 'net.connect', target: destination}); return fakeRequest(destination); };
  net.createConnection = function(...args) { const destination = safeString(args[0]); record({kind: 'network', api: 'net.createConnection', target: destination}); return fakeRequest(destination); };
} catch (_) {}

try {
  const dns = require('dns');
  for (const name of ['lookup', 'resolve', 'resolve4', 'resolve6']) {
    patchFunction(dns, name, (args) => record({kind: 'dns', api: 'dns.' + name, target: safeString(args[0])}));
  }
} catch (_) {}

const originalLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === 'vscode') return createVscodeStub();
  return originalLoad.apply(this, arguments);
};

function createVscodeStub() {
  const disposable = { dispose() {} };
  const noop = () => disposable;
  const asyncNoop = async () => undefined;
  const namespace = (seed = {}) => new Proxy(seed, {
    get(target, property) {
      if (property in target) return target[property];
      target[property] = asyncNoop;
      return target[property];
    },
  });
  // Extensions commonly import VS Code's model classes at module load time,
  // before activate() is reached. A missing class would make every runtime
  // probe look like a sandbox failure even though the package was safely
  // loaded and instrumented. These inert constructors keep the harness from
  // inventing host behavior while allowing observation to proceed.
  const inertClass = new Proxy(function(...args) {
    if (new.target) Object.assign(this, args[0] && typeof args[0] === 'object' ? args[0] : {});
    return disposable;
  }, {
    get(target, property) {
      if (property in target) return target[property];
      return 0;
    },
  });
  const inertEnum = new Proxy({}, { get: () => 0 });
  const fileSystemError = class extends Error {};
  fileSystemError.FileNotFound = () => Object.assign(new fileSystemError('File not found'), { code: 'FileNotFound' });
  fileSystemError.FileExists = () => Object.assign(new fileSystemError('File exists'), { code: 'FileExists' });
  fileSystemError.NoPermissions = () => Object.assign(new fileSystemError('No permissions'), { code: 'NoPermissions' });
  fileSystemError.FileIsADirectory = () => Object.assign(new fileSystemError('File is a directory'), { code: 'FileIsADirectory' });
  fileSystemError.FileNotADirectory = () => Object.assign(new fileSystemError('File is not a directory'), { code: 'FileNotADirectory' });
  const markdownString = class {
    constructor(value = '') { this.value = String(value); this.isTrusted = false; }
    appendText(value) { this.value += String(value); return this; }
    appendMarkdown(value) { this.value += String(value); return this; }
    appendCodeblock(value) { this.value += String(value); return this; }
    toString() { return this.value; }
  };
  const codeActionKind = class {
    constructor(value = '') { this.value = String(value); }
    append(...parts) {
      const suffix = parts.filter((part) => part !== undefined && part !== null && String(part) !== '')
        .map((part) => String(part.value || part));
      return new codeActionKind([this.value, ...suffix].filter(Boolean).join('.'));
    }
    toString() { return this.value; }
  };
  codeActionKind.Empty = new codeActionKind('');
  codeActionKind.QuickFix = new codeActionKind('quickfix');
  codeActionKind.Refactor = new codeActionKind('refactor');
  codeActionKind.RefactorExtract = new codeActionKind('refactor.extract');
  codeActionKind.RefactorInline = new codeActionKind('refactor.inline');
  codeActionKind.RefactorRewrite = new codeActionKind('refactor.rewrite');
  codeActionKind.Source = new codeActionKind('source');
  codeActionKind.SourceOrganizeImports = new codeActionKind('source.organizeImports');
  const makeFileUri = (p) => {
    const fsPath = String(p);
    return { fsPath, path: fsPath, scheme: 'file', toString: () => 'file://' + fsPath };
  };
  inertClass.file = makeFileUri;
  inertClass.parse = (p) => makeFileUri(String(p).startsWith('file://') ? String(p).slice(7) : p);
  inertClass.from = (...items) => ({
    dispose() { for (const item of items) { try { item?.dispose?.(); } catch (_) {} } },
  });
  inertClass.joinPath = (base, ...parts) => {
    const fsPath = require('path').posix.normalize([base && (base.fsPath || base.path), ...parts].filter(Boolean).join('/'));
    return {
      fsPath,
      path: fsPath,
      scheme: 'file',
      toString() { return 'file://' + this.fsPath; },
    };
  };
  const registerCommand = (name, handler) => {
    const command = String(name || '');
    record({kind: 'command_registered', command});
    if (command && typeof handler === 'function') commandHandlers.set(command, handler);
    return disposable;
  };
  const executeCommand = async (name, ...args) => {
    const command = String(name || '');
    record({kind: 'command_execute', command});
    const handler = commandHandlers.get(command);
    return handler ? handler(...args) : undefined;
  };
  const createWebviewPanel = () => {
    record({kind: 'webview_created'});
    return {
      webview: {
        html: '',
        onDidReceiveMessage(handler) {
          record({kind: 'webview_message_handler_registered'});
          if (typeof handler === 'function') webviewMessageHandlers.push(handler);
          return disposable;
        },
        postMessage: async () => true,
      },
      onDidDispose: noop,
    };
  };
  const createQuickInput = () => {
    const listeners = new Map();
    const event = (name) => (handler) => {
      const callbacks = listeners.get(name) || [];
      callbacks.push(handler);
      listeners.set(name, callbacks);
      return { dispose() {} };
    };
    const fire = (name, value) => {
      for (const handler of listeners.get(name) || []) {
        try { handler(value); } catch (_) {}
      }
    };
    return {
      title: '', step: 0, totalSteps: 0, placeholder: '', ignoreFocusOut: false,
      items: [], activeItems: [], buttons: [], value: '', enabled: true, busy: false,
      onDidTriggerButton: event('button'), onDidChangeSelection: event('selection'),
      onDidHide: event('hide'), onDidAccept: event('accept'), onDidChangeValue: event('value'),
      show() { setImmediate(() => fire('hide')); }, hide() { fire('hide'); }, dispose() {},
    };
  };
  const extensionList = new Proxy([], {
    get(target, property) {
      if (property === 'find') return () => ({ id: '', packageJSON: {} });
      return target[property];
    },
  });
  const vscode = {
    // Keep CommonJS __importStar interop correct. Returning a synthetic
    // truthy value for an unknown __esModule property makes bundled
    // extensions skip their default namespace and then fail on
    // `vscode.default.EventEmitter`-style imports.
    __esModule: false,
    version: '1.99.0',
    commands: { registerCommand, executeCommand },
    debug: {
      activeDebugSession: undefined,
      onDidReceiveDebugSessionCustomEvent: noop,
      onDidStartDebugSession: noop,
      onDidTerminateDebugSession: noop,
      onDidChangeActiveDebugSession: noop,
      registerDebugConfigurationProvider: () => disposable,
      startDebugging: async () => false,
      stopDebugging: async () => false,
      addBreakpoints() {},
      removeBreakpoints() {},
    },
    tasks: {
      registerTaskProvider: () => disposable,
      executeTask: async () => undefined,
      fetchTasks: async () => [],
    },
    lm: {
      registerTool: () => disposable,
      registerLanguageModelChatProvider: () => disposable,
      selectChatModels: async () => [],
      onDidChangeChatModels: noop,
    },
    window: {
      showInformationMessage: async () => undefined,
      showWarningMessage: async () => undefined,
      showErrorMessage: async () => undefined,
      createWebviewPanel,
      createQuickPick: createQuickInput,
      createInputBox: createQuickInput,
      createTreeView: () => ({
        onDidExpandElement: noop,
        onDidCollapseElement: noop,
        onDidChangeSelection: noop,
        onDidChangeVisibility: noop,
        reveal() {},
        dispose() {},
      }),
      createOutputChannel: () => ({
        append() {}, appendLine() {},
        clear() {}, dispose() {}, hide() {}, show() {},
        info() {}, error() {}, warn() {}, debug() {}, trace() {},
      }),
      createStatusBarItem: () => ({
        text: '', tooltip: '', command: undefined, show() {}, hide() {}, dispose() {},
      }),
      createTextEditorDecorationType: () => disposable,
      registerTreeDataProvider: () => disposable,
      registerWebviewViewProvider: () => disposable,
      onDidChangeVisibleTextEditors: noop,
      onDidChangeActiveTextEditor: noop,
      onDidChangeTextEditorSelection: noop,
      onDidChangeTextEditorVisibleRanges: noop,
      onDidChangeTextEditorOptions: noop,
      onDidChangeTextEditorViewColumn: noop,
      onDidChangeActiveColorTheme: noop,
      onDidChangeTabs: noop,
      tabGroups: { all: [], onDidChangeTabs: noop, close: async () => undefined },
      activeTextEditor: undefined,
      visibleTextEditors: [],
    },
    workspace: {
      workspaceFolders: [{
        uri: makeFileUri(process.env.VSCODE_CWD || process.cwd()),
        name: 'guardrails-runtime',
      }],
      workspaceFile: undefined,
      isTrusted: true,
      textDocuments: [],
      fs: namespace({
        readFile: async (uri) => {
          const path = String(uri && (uri.fsPath || uri.path) || '');
          if (path.endsWith('/eventLog.json') || path.endsWith('\\eventLog.json')) {
            return Buffer.from(JSON.stringify({id: 'memento', data: {}}));
          }
          return Buffer.from('{}');
        },
        stat: async () => ({ type: 1 }),
      }),
      getConfiguration: () => ({
      get: (_section, defaultValue) => defaultValue,
      has: () => false,
      inspect: (section) => ({
        key: String(section || ''),
        defaultValue: undefined,
        globalValue: undefined,
        workspaceValue: undefined,
        workspaceFolderValue: undefined,
        defaultLanguageValue: undefined,
        globalLanguageValue: undefined,
        workspaceLanguageValue: undefined,
        workspaceFolderLanguageValue: undefined,
      }),
        update: async () => undefined,
      }),
      onDidChangeConfiguration: noop,
      onDidChangeTextDocument: noop,
      onDidOpenTextDocument: noop,
      onDidCloseTextDocument: noop,
      getWorkspaceFolder: () => undefined,
      createFileSystemWatcher: () => ({ onDidCreate: noop, onDidChange: noop, onDidDelete: noop, dispose() {} }),
    },
    env: {
      uiKind: 1,
      appName: 'GuardRails Runtime',
      appRoot: '',
      machineId: 'guardrails-runtime-machine',
      sessionId: 'guardrails-runtime-session',
      language: 'en',
      remoteName: undefined,
      createTelemetryLogger: () => ({
        logUsage() {},
        logError() {},
        dispose() {},
      }),
    },
    extensions: {
      getExtension: () => ({ packageJSON: {}, extensionPath: '/target', exports: {}, isActive: false, activate: async () => undefined }),
      all: extensionList,
    },
    l10n: { t: (key) => String(key) },
    ConfigurationTarget: inertEnum,
    FileSystemError: fileSystemError,
    languages: new Proxy({
      getLanguages: async () => [],
      registerCompletionItemProvider: () => disposable,
      registerLanguageProvider: () => disposable,
      registerCodeActionsProvider: () => disposable,
      registerCodeLensProvider: () => disposable,
      registerDefinitionProvider: () => disposable,
      registerDeclarationProvider: () => disposable,
      registerDocumentFormattingEditProvider: () => disposable,
      registerDocumentRangeFormattingEditProvider: () => disposable,
      registerDocumentHighlightProvider: () => disposable,
      registerDocumentLinkProvider: () => disposable,
      registerDocumentSymbolProvider: () => disposable,
      registerHoverProvider: () => disposable,
      registerImplementationProvider: () => disposable,
      registerInlayHintsProvider: () => disposable,
      registerInlineValuesProvider: () => disposable,
      registerReferenceProvider: () => disposable,
      registerRenameProvider: () => disposable,
      registerSelectionRangeProvider: () => disposable,
      registerSignatureHelpProvider: () => disposable,
      registerTypeDefinitionProvider: () => disposable,
      registerTypeHierarchyProvider: () => disposable,
      registerWorkspaceSymbolProvider: () => disposable,
      registerFoldingRangeProvider: () => disposable,
      registerDocumentSemanticTokensProvider: () => disposable,
      registerDocumentRangeSemanticTokensProvider: () => disposable,
    }, {
      get(target, property) {
        if (property in target) return target[property];
        if (String(property).startsWith('register')) return () => disposable;
        return asyncNoop;
      },
    }),
    tests: {
      createTestController: () => ({
        items: { add() {}, delete() {}, replace() {}, forEach() {} },
        createTestItem: (id, label) => ({ id: String(id), label: String(label), children: { add() {}, delete() {}, forEach() {} } }),
        createRunProfile: () => disposable,
        createTestRun: () => ({
          enqueued() {}, started() {}, passed() {}, failed() {}, skipped() {}, errored() {},
          appendOutput() {}, end() {},
        }),
        dispose() {},
      }),
    },
    Uri: inertClass,
    RelativePattern: inertClass,
    ExtensionContext: inertClass,
    Disposable: inertClass,
    EventEmitter: class { constructor() { this.event = noop; } fire() {} dispose() {} },
    CompletionItem: inertClass,
    CodeAction: inertClass,
    CodeLens: inertClass,
    DocumentLink: inertClass,
    Diagnostic: inertClass,
    CallHierarchyItem: inertClass,
    TypeHierarchyItem: inertClass,
    SymbolInformation: inertClass,
    InlayHint: inertClass,
    CancellationError: inertClass,
    Task: inertClass,
    Position: inertClass,
    Range: inertClass,
    Location: inertClass,
    TreeItem: inertClass,
    ThemeIcon: inertClass,
    ThemeColor: inertClass,
    MarkdownString: markdownString,
    TreeItemCollapsibleState: inertEnum,
    TaskScope: inertEnum,
    TaskGroup: inertEnum,
    ViewColumn: inertEnum,
    StatusBarAlignment: inertEnum,
    CompletionItemKind: inertEnum,
    SymbolKind: inertEnum,
    DiagnosticSeverity: inertEnum,
    FileType: inertEnum,
    MarkupKind: inertEnum,
    FoldingRangeKind: inertEnum,
    SemanticTokenTypes: inertEnum,
    UIKind: inertEnum,
    OverviewRulerLane: { Left: 1, Center: 2, Right: 4, Full: 7 },
    NotebookCellStatusBarAlignment: { Left: 1, Right: 2 },
    StatusBarAlignment: { Left: 1, Right: 2 },
    ColorThemeKind: { Light: 1, Dark: 2, HighContrast: 3, HighContrastLight: 4 },
    LogLevel: inertEnum,
    TestRunProfileKind: inertEnum,
    TestTag: inertClass,
    TestMessage: inertClass,
    CodeActionKind: codeActionKind,
    IndentAction: inertEnum,
    TextEditorRevealType: inertEnum,
  };
  // Preserve the explicitly modeled APIs above while letting ordinary event
  // registration calls from host-heavy extensions remain inert. Missing host
  // events must not turn a safe package into a synthetic activation failure;
  // the capability hooks above still record filesystem, process, and network
  // behavior independently.
  for (const api of ['window', 'workspace', 'languages', 'commands', 'extensions', 'env', 'l10n', 'debug', 'tasks', 'lm']) {
    vscode[api] = new Proxy(vscode[api], {
      get(target, property) {
        if (property in target) return target[property];
        target[property] = noop;
        return target[property];
      },
    });
  }
  // Keep unknown VS Code classes inert rather than failing module loading on
  // an API that is irrelevant to the package's activation path. The fallback
  // is intentionally top-level only; it does not fabricate filesystem,
  // network, or process behavior inside the declared namespaces above.
  return new Proxy(vscode, {
    get(target, property) {
      if (property in target) return target[property];
      target[property] = inertClass;
      return target[property];
    },
  });
}

record({kind: 'instrumentation_started', home: sandboxHome});
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_entrypoint_runner(path: Path, manifest: dict[str, Any]) -> None:
    main = _extension_main(manifest)
    if not main:
        path.write_text(
            "// This package has no Node activation entrypoint.\n",
            encoding="utf-8",
        )
        return
    safe_main = main.lstrip("/\\")
    path.write_text(
        f"""
    const path = require('path');
    const {{ pathToFileURL }} = require('url');
    const target = '/target';
global.__guardrailsFinishing = false;
process.on('uncaughtException', (err) => {{
  if (global.__guardrailsFinishing) return;
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
}});
process.on('unhandledRejection', (err) => {{
  if (global.__guardrailsFinishing) return;
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
}});
    // VSIX manifests in the wild sometimes write a leading slash even
    // though the entrypoint is package-relative. Never let a manifest turn
    // that spelling into a host-absolute path outside the mounted artifact.
    const mainFile = path.resolve(target, {json.dumps(safe_main)});
async function run() {{
  let mod;
  try {{
    mod = require(mainFile);
  }} catch (error) {{
    if (!error || !['ERR_REQUIRE_ESM', 'ERR_REQUIRE_ASYNC_MODULE'].includes(error.code)) throw error;
    mod = await import(pathToFileURL(mainFile).href);
  }}
  const context = {{
    subscriptions: [],
    extensionPath: target,
    extensionUri: {{ fsPath: target, path: target, scheme: 'file', toString: () => target }},
    asAbsolutePath: (relativePath) => path.resolve(target, String(relativePath || '')),
    extensionMode: 1,
    extension: {{ id: 'guardrails.runtime', extensionPath: target, packageJSON: {{}} }},
    globalState: {{ get: (_key, defaultValue) => defaultValue, keys: () => [], update: async () => undefined }},
    workspaceState: {{ get: (_key, defaultValue) => defaultValue, keys: () => [], update: async () => undefined }},
    environmentVariableCollection: {{
      persistent: false,
      description: undefined,
      replace() {{}}, append() {{}}, prepend() {{}}, delete() {{}}, clear() {{}},
    }},
    globalStorageUri: {{ fsPath: path.join(process.env.HOME || target, '.globalStorage'), path: path.join(process.env.HOME || target, '.globalStorage'), scheme: 'file' }},
    storageUri: {{ fsPath: path.join(process.env.HOME || target, '.workspaceStorage'), path: path.join(process.env.HOME || target, '.workspaceStorage'), scheme: 'file' }},
    secrets: {{ get: async () => undefined, store: async () => undefined, delete: async () => undefined }}
  }};
  const activate = mod && (mod.activate || (mod.default && mod.default.activate));
  if (typeof activate === 'function') {{
    await Promise.resolve(activate(context));
  }}
  // Activation has returned successfully. Background language servers may
  // reject pending protocol requests when this disposable probe host is
  // torn down; those teardown errors are not activation failures.
  global.__guardrailsFinishing = true;
  if (global.__guardrailsProbe && typeof global.__guardrailsProbe.run === 'function') {{
    await global.__guardrailsProbe.run();
  }}
  // An extension host normally stays alive for the lifetime of VS Code and
  // may leave language servers or timers attached to the event loop. The
  // scanner's contract is activation plus the bounded probe window, so end
  // the host after those observations instead of treating a healthy
  // long-lived child as an activation timeout. Bubblewrap's die-with-parent
  // policy cleans up the child process tree with the host.
  await new Promise((resolve) => setImmediate(resolve));
  process.exit(0);
}}
run().catch((err) => {{
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
}});
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _verified_runtime_events(output: str) -> tuple[list[dict[str, Any]], bool]:
    """Decode only hook events authenticated by the hook's per-process secret.

    Extension code shares the Node process and can write to stderr. Runtime
    observations therefore must not trust that raw channel. The hook emits a
    random handshake before the extension loads and HMACs each event; forged
    or truncated transport makes the runtime evidence incomplete instead of
    silently becoming trusted evidence.
    """
    secret = ""
    events: list[dict[str, Any]] = []
    valid = True
    for line in output.splitlines():
        if line.startswith(RUNTIME_EVENT_HANDSHAKE):
            candidate = line[len(RUNTIME_EVENT_HANDSHAKE):].strip()
            if secret:
                valid = False
                continue
            if len(candidate) != 64 or any(char not in "0123456789abcdefABCDEF" for char in candidate):
                valid = False
                continue
            secret = candidate
            continue
        if RUNTIME_EVENT_OUTPUT_LIMIT_MARKER in line:
            valid = False
            continue
        if not line.startswith(RUNTIME_EVENT_PREFIX):
            continue
        if not secret:
            valid = False
            continue
        encoded_mac = line[len(RUNTIME_EVENT_PREFIX):]
        encoded, separator, supplied_mac = encoded_mac.rpartition(".")
        if not separator or not supplied_mac:
            valid = False
            continue
        try:
            payload = base64.b64decode(encoded, validate=True).decode("utf-8")
            expected_mac = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
            event = json.loads(payload)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            valid = False
            continue
        if not hmac.compare_digest(expected_mac, supplied_mac) or not isinstance(event, dict):
            valid = False
            continue
        events.append(event)
    return (events if valid else []), valid


def _external_trace_observations(
    result: subprocess.CompletedProcess[str],
    canary_files: list[str],
) -> tuple[list[dict[str, Any]], bool]:
    """Normalize parent-owned strace output without trusting extension text."""
    prefix = str(getattr(result, "_guardrails_external_trace_prefix", "") or "")
    if not prefix:
        return [], not _external_trace_requested()
    trace_path = Path(prefix)
    if not trace_path.exists():
        return [], False
    try:
        with trace_path.open("r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(MAX_EXTERNAL_TRACE_BYTES + 1)
    except OSError:
        trace_path.unlink(missing_ok=True)
        return [], False
    trace_path.unlink(missing_ok=True)
    if len(text.encode("utf-8", errors="replace")) > MAX_EXTERNAL_TRACE_BYTES:
        return [], False

    canary_set = {str(Path(item)) for item in canary_files}
    observations: list[dict[str, Any]] = []
    sensitive_suffixes = ("/.env", "/.npmrc", "/.ssh/id_ed25519", "/.aws/credentials")
    for line in text.splitlines():
        syscall_match = re.search(r"\b([A-Za-z][A-Za-z0-9_]*)\(", line)
        if not syscall_match:
            continue
        syscall = syscall_match.group(1)
        lower = line.lower()
        path = _first_strace_string(line)
        if path.replace("\\", "/").strip("/") in _SANDBOX_SETUP_RELATIVE_PATHS and "/" not in path.strip("/"):
            continue
        if syscall in {"open", "openat", "openat2", "creat"} and path:
            if path in canary_set or any(path.endswith(suffix) for suffix in sensitive_suffixes):
                observations.append({
                    "kind": "secret_read",
                    "path": path,
                    "api": f"strace.{syscall}",
                })
            if any(flag in lower for flag in ("o_wronly", "o_rdwr", "o_creat")):
                observations.append({
                    "kind": "filesystem_write",
                    "path": path,
                    "api": f"strace.{syscall}",
                })
        elif syscall in {"connect", "sendto", "sendmsg", "sendmmsg", "bind"}:
            observations.append({
                "kind": "network_attempt",
                "destination": "external-syscall",
                "api": f"strace.{syscall}",
            })
        elif syscall in {"execve", "execveat"}:
            observations.append({
                "kind": "process_exec",
                "command": path or "external-syscall",
                "api": f"strace.{syscall}",
            })
        elif syscall in {
            "chmod", "chmodat", "mkdir", "mkdirat", "rename", "renameat",
            "renameat2", "rmdir", "symlink", "symlinkat", "truncate", "unlink",
            "unlinkat",
        } and path:
            observations.append({
                "kind": "filesystem_write",
                "path": path,
                "api": f"strace.{syscall}",
            })
    return _dedupe_observations(observations), True


def _first_strace_string(line: str) -> str:
    match = re.search(r'"(?:\\.|[^"\\])*"', line)
    if not match:
        return ""
    try:
        value = ast.literal_eval(match.group(0))
    except (SyntaxError, ValueError):
        return ""
    return value if isinstance(value, str) else ""


def _observations_from_trace(trace_file: Path, canary_files: list[str]) -> list[dict[str, Any]]:
    if not trace_file.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in trace_file.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return _observations_from_events(events, canary_files)


def _observations_from_events(events: list[dict[str, Any]], canary_files: list[str]) -> list[dict[str, Any]]:
    canary_set = {str(Path(item)) for item in canary_files}
    observations: list[dict[str, Any]] = []
    for event in events:
        kind = event.get("kind")
        if kind == "fs_read":
            path = str(event.get("path") or "")
            if path in canary_set or any(path.endswith(suffix) for suffix in ("/.env", "/.npmrc", "/.ssh/id_ed25519", "/.aws/credentials")):
                observations.append({
                    "kind": "secret_read",
                    "path": path,
                    "api": event.get("api"),
                })
        elif kind in {"network", "dns"}:
            observations.append({
                "kind": "network_attempt",
                "destination": event.get("target") or event.get("api") or "unknown",
                "api": event.get("api"),
            })
        elif kind == "network_write":
            contains_canary = bool(event.get("contains_canary"))
            observations.append({
                "kind": "runtime_network_write",
                "contains_canary": contains_canary,
                "bytes": event.get("bytes"),
                "destination": event.get("target") or "unknown",
            })
            if contains_canary:
                observations.append({
                    "kind": "secret_exfil",
                    "destination": event.get("target") or "unknown",
                    "evidence": "runtime trace observed the canary value in a network request body",
                })
        elif kind == "process_exec":
            command = str(event.get("command") or "")
            observations.append({
                "kind": "process_exec",
                "command": command,
                "api": event.get("api"),
            })
            if any(token in command.lower() for token in ("curl", "wget", "powershell", "bash", "sh ")) and any(token in command.lower() for token in ("http://", "https://")):
                observations.append({
                    "kind": "download_execute",
                    "command": command,
                    "api": event.get("api"),
                })
        elif kind == "fs_write":
            path = str(event.get("path") or "")
            observations.append({
                "kind": "filesystem_write",
                "path": path,
                "api": event.get("api"),
            })
            if any(marker in path.lower() for marker in (".bashrc", ".zshrc", ".profile", "launchagents", "startup", "systemd")):
                observations.append({
                    "kind": "persistence",
                    "path": path,
                    "api": event.get("api"),
                })
        elif kind in {
            "command_registered",
            "command_execute",
            "command_probe",
            "command_probe_error",
            "webview_created",
            "webview_message_handler_registered",
            "webview_message_probe",
            "webview_message_probe_error",
        }:
            observation = {"kind": f"runtime_{kind}"}
            for key in ("command", "error"):
                if key in event:
                    observation[key] = event[key]
            observations.append(observation)
    return _dedupe_observations(observations)


def _dedupe_observations(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = json.dumps(item, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _snapshot(*roots: Path) -> set[str]:
    files: set[str] = set()
    for root in roots:
        for item in root.rglob("*"):
            if item.is_file():
                files.add(str(item))
    return files


def _prepare_target(source: Path, destination: Path) -> Path:
    if source.is_file() and source.suffix.lower() == ".vsix":
        destination.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(source) as archive:
            members = archive.infolist()
            if len(members) > MAX_RUNTIME_FILES:
                raise ValueError(f"Sandbox archive exceeds the {MAX_RUNTIME_FILES}-file limit")
            total_bytes = 0
            for member in members:
                name = member.filename.replace("\\", "/")
                if not name or name.endswith("/"):
                    continue
                if member.flag_bits & 0x1:
                    raise ValueError("Sandbox refuses encrypted VSIX members")
                if member.file_size < 0 or member.file_size > MAX_RUNTIME_FILE_BYTES:
                    raise ValueError(f"Sandbox archive member exceeds the {MAX_RUNTIME_FILE_BYTES}-byte limit")
                total_bytes += member.file_size
                if total_bytes > MAX_RUNTIME_BYTES:
                    raise ValueError(f"Sandbox archive exceeds the {MAX_RUNTIME_BYTES}-byte extraction limit")
                target = (destination / name).resolve()
                if destination.resolve() not in target.parents and target != destination.resolve():
                    raise ValueError("Sandbox archive contains a path traversal member")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, target.open("wb") as dst:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        dst.write(chunk)
        preferred = destination / "extension" / "package.json"
        if preferred.exists():
            return preferred.parent
        for package_json in destination.rglob("package.json"):
            if "node_modules" not in package_json.parts:
                return package_json.parent
    if source.is_dir():
        _validate_source_tree(source)
        shutil.copytree(source, destination, symlinks=True)
        return destination
    raise ValueError("Sandbox target must be an extension directory or VSIX file")


def _validate_source_tree(source: Path) -> None:
    file_count = 0
    total_bytes = 0
    for item in source.rglob("*"):
        if item.is_symlink() or not item.is_file():
            continue
        file_count += 1
        if file_count > MAX_RUNTIME_FILES:
            raise ValueError(f"Sandbox artifact exceeds the {MAX_RUNTIME_FILES}-file limit")
        size = item.stat().st_size
        if size > MAX_RUNTIME_FILE_BYTES:
            raise ValueError(f"Sandbox artifact file exceeds the {MAX_RUNTIME_FILE_BYTES}-byte limit")
        total_bytes += size
        if total_bytes > MAX_RUNTIME_BYTES:
            raise ValueError(f"Sandbox artifact exceeds the {MAX_RUNTIME_BYTES}-byte limit")
