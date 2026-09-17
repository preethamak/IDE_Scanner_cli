from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .jsonc import loads_jsonc

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


def run_sandbox(path: Path, allow_execute: bool = False, timeout_seconds: int = 15) -> dict[str, Any]:
    if not 1 <= timeout_seconds <= MAX_RUNTIME_TIMEOUT_SECONDS:
        raise ValueError(f"Sandbox timeout must be between 1 and {MAX_RUNTIME_TIMEOUT_SECONDS} seconds")
    source = path.expanduser().resolve()
    if allow_execute and shutil.which("bwrap") is None:
        raise ValueError(
            "Executable sandbox mode requires the Bubblewrap (bwrap) OS isolation backend; execution was refused."
        )
    with tempfile.TemporaryDirectory(prefix="ide-scanner-sandbox-") as tmp:
        root = Path(tmp)
        target = _prepare_target(source, root / "target")
        manifest = _read_manifest(target / "package.json")
        extension_id = f"{manifest.get('publisher') or 'unknown'}.{manifest.get('name') or target.name}"
        home = root / "home"
        workspace = root / "workspace"
        trace_file = root / "trace.jsonl"
        hook_file = root / "node-runtime-hook.js"
        entrypoint_runner = root / "activate-entrypoint.js"
        trace_file.touch()
        home.mkdir()
        workspace.mkdir()
        canaries = _write_canaries(home)
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
            "trace_file": str(trace_file),
            "instrumentation": {
                "node_require_hook": str(hook_file),
                "entrypoint_runner": str(entrypoint_runner),
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
            },
            "runtime_probes": {
                "registered_commands": "invoke up to 50 handlers with a synthetic canary argument",
                "webview_messages": "deliver one synthetic canary message to each registered handler",
            },
            "resource_limits": {
                "max_files": MAX_RUNTIME_FILES,
                "max_total_bytes": MAX_RUNTIME_BYTES,
                "max_file_bytes": MAX_RUNTIME_FILE_BYTES,
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
            ))
            observations.extend(_execute_entrypoint(
                entrypoint_runner,
                home,
                workspace,
                timeout_seconds,
                hook_file,
                trace_file,
                target,
            ))
            observations.extend(_observations_from_trace(trace_file, canaries))
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


def _planned_commands(manifest: dict[str, Any]) -> list[dict[str, str]]:
    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    commands: list[dict[str, str]] = []
    for name in ("preinstall", "install", "postinstall", "vscode:uninstall"):
        command = scripts.get(name)
        if isinstance(command, str) and command.strip():
            commands.append({"kind": "lifecycle", "name": name, "command": command})
    return commands


def _extension_main(manifest: dict[str, Any]) -> str:
    main = str(manifest.get("main") or "").strip()
    return main or "./extension.js"


def _execute_planned_commands(
    target: Path,
    commands: list[dict[str, str]],
    home: Path,
    workspace: Path,
    timeout_seconds: int,
    hook_file: Path,
    trace_file: Path,
    entrypoint_runner: Path,
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
            observations.append({
                "kind": "lifecycle_executed",
                "script": command["name"],
                "returncode": result.returncode,
                "stdout_bytes": len(result.stdout.encode("utf-8", errors="replace")),
                "stderr_bytes": len(result.stderr.encode("utf-8", errors="replace")),
            })
            if CANARY_VALUE in combined:
                observations.append({
                    "kind": "secret_exfil",
                    "script": command["name"],
                    "destination": "stdout-or-stderr",
                    "evidence": "canary appeared in process output",
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
) -> list[dict[str, Any]]:
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
        observations: list[dict[str, Any]] = [{
            "kind": "entrypoint_executed",
            "returncode": result.returncode,
            "stdout_bytes": len(result.stdout.encode("utf-8", errors="replace")),
            "stderr_bytes": len(result.stderr.encode("utf-8", errors="replace")),
        }]
        if CANARY_VALUE in combined:
            observations.append({
                "kind": "secret_exfil",
                "destination": "stdout-or-stderr",
                "evidence": "canary appeared in entrypoint process output",
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
        "bwrap",
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
        "--dir", "/trace",
        "--bind", str(trace_file), "/trace/trace.jsonl",
        "--clearenv",
        "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--setenv", "HOME", "/home/guardrails",
        "--setenv", "USERPROFILE", "/home/guardrails",
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "IDE_SCANNER_SANDBOX", "1",
        "--setenv", "IDE_SCANNER_CANARY", CANARY_VALUE,
        "--setenv", "IDE_SCANNER_TRACE_FILE", "/trace/trace.jsonl",
        "--setenv", "VSCODE_CWD", "/workspace",
        "--setenv", "NODE_OPTIONS", "--require=/runner/node-runtime-hook.js",
        "--chdir", cwd,
        "--",
        *command,
    ]
    return subprocess.run(args, **kwargs)


def _sandbox_env(home: Path, workspace: Path, hook_file: Path, trace_file: Path) -> dict[str, str]:
    env = os.environ.copy()
    existing_node_options = env.get("NODE_OPTIONS", "")
    require_hook = f"--require={hook_file}"
    env.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "IDE_SCANNER_SANDBOX": "1",
        "IDE_SCANNER_CANARY": CANARY_VALUE,
        "IDE_SCANNER_TRACE_FILE": str(trace_file),
        "VSCODE_CWD": str(workspace),
        "NODE_OPTIONS": f"{require_hook} {existing_node_options}".strip(),
    })
    return env


def _write_node_hook(path: Path, trace_file: Path, home: Path) -> None:
    path.write_text(
        r"""
const fs = require('fs');
const Module = require('module');
const traceFile = process.env.IDE_SCANNER_TRACE_FILE;
const sandboxHome = process.env.HOME || '';
const traceAppend = fs.appendFileSync.bind(fs);

function safeString(value) {
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  if (value && value.href) return String(value.href);
  try { return JSON.stringify(value); } catch (_) { return String(value); }
}

function record(event) {
  if (!traceFile) return;
  try {
    traceAppend(traceFile, JSON.stringify(Object.assign({ts: Date.now()}, event)) + '\n');
  } catch (_) {}
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
for (const name of ['writeFileSync', 'writeFile', 'appendFileSync', 'appendFile', 'createWriteStream']) {
  patchFunction(fs, name, (args) => record({kind: 'fs_write', api: name, path: safeString(args[0])}));
}

try {
  const child_process = require('child_process');
  for (const name of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']) {
    patchFunction(child_process, name, (args) => record({kind: 'process_exec', api: name, command: safeString(args[0])}));
  }
} catch (_) {}

function fakeRequest(destination) {
  const events = {};
  return {
    write(value) {
      const text = safeString(value);
      record({kind: 'network_write', target: destination || 'unknown', contains_canary: text.includes(process.env.IDE_SCANNER_CANARY || ''), bytes: text.length});
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
  return {
    commands: { registerCommand, executeCommand },
    window: {
      showInformationMessage: async () => undefined,
      showWarningMessage: async () => undefined,
      showErrorMessage: async () => undefined,
      createWebviewPanel,
    },
    workspace: {
      workspaceFolders: [{ uri: { fsPath: process.env.VSCODE_CWD || process.cwd() } }],
      fs: {},
      getConfiguration: () => ({ get: () => undefined, update: async () => undefined }),
      onDidChangeConfiguration: noop,
      onDidChangeTextDocument: noop,
      onDidOpenTextDocument: noop
    },
    Uri: { file: (p) => ({ fsPath: p, toString: () => String(p) }), parse: (p) => ({ fsPath: p, toString: () => String(p) }) },
    ExtensionContext: class {},
    Disposable: class { dispose() {} }
  };
}

record({kind: 'instrumentation_started', home: sandboxHome});
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_entrypoint_runner(path: Path, manifest: dict[str, Any]) -> None:
    main = _extension_main(manifest)
    path.write_text(
        f"""
const path = require('path');
const target = '/target';
const mainFile = path.resolve(target, {json.dumps(main)});
async function run() {{
  const mod = require(mainFile);
  const context = {{
    subscriptions: [],
    extensionPath: target,
    extensionUri: {{ fsPath: target, toString: () => target }},
    globalStorageUri: {{ fsPath: path.join(process.env.HOME || target, '.globalStorage') }},
    storageUri: {{ fsPath: path.join(process.env.HOME || target, '.workspaceStorage') }},
    secrets: {{ get: async () => undefined, store: async () => undefined, delete: async () => undefined }}
  }};
  if (mod && typeof mod.activate === 'function') {{
    await Promise.resolve(mod.activate(context));
  }}
  if (global.__guardrailsProbe && typeof global.__guardrailsProbe.run === 'function') {{
    await global.__guardrailsProbe.run();
  }}
}}
run().catch((err) => {{
  console.error(err && err.stack ? err.stack : String(err));
  process.exitCode = 1;
}});
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _observations_from_trace(trace_file: Path, canary_files: list[str]) -> list[dict[str, Any]]:
    if not trace_file.exists():
        return []
    canary_set = {str(Path(item)) for item in canary_files}
    observations: list[dict[str, Any]] = []
    for line in trace_file.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
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
