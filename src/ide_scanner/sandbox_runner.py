from __future__ import annotations

import json
import os
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


def run_sandbox(path: Path, allow_execute: bool = False, timeout_seconds: int = 15) -> dict[str, Any]:
    if allow_execute:
        raise ValueError(
            "Executable sandbox mode is disabled until OS-level filesystem, process, and network isolation is available."
        )
    source = path.expanduser().resolve()
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
        home.mkdir()
        workspace.mkdir()
        canaries = _write_canaries(home)
        _write_node_hook(hook_file, trace_file, home)
        _write_entrypoint_runner(entrypoint_runner, target, manifest)
        observations: list[dict[str, Any]] = []
        plan = {
            "extension_id": extension_id,
            "source": str(source),
            "target": str(target),
            "allow_execute": allow_execute,
            "sandbox_home": str(home),
            "sandbox_workspace": str(workspace),
            "trace_file": str(trace_file),
            "instrumentation": {
                "node_require_hook": str(hook_file),
                "entrypoint_runner": str(entrypoint_runner),
                "captures": ["fs", "child_process", "http", "https", "net", "dns"],
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
            ))
            observations.extend(_execute_entrypoint(
                entrypoint_runner,
                home,
                workspace,
                timeout_seconds,
                hook_file,
                trace_file,
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
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    env = _sandbox_env(home, workspace, hook_file, trace_file)
    before = _snapshot(home, workspace)
    for command in commands:
        try:
            result = subprocess.run(
                command["command"],
                cwd=target,
                env=env,
                shell=True,
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
                "kind": "unexpected_network",
                "script": command["name"],
                "destination": "unknown",
                "evidence": f"script timed out after {timeout_seconds}s",
            })
    after = _snapshot(home, workspace)
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
) -> list[dict[str, Any]]:
    env = _sandbox_env(home, workspace, hook_file, trace_file)
    try:
        result = subprocess.run(
            ["node", str(runner)],
            cwd=workspace,
            env=env,
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
            "kind": "unexpected_network",
            "destination": "unknown",
            "evidence": f"entrypoint timed out after {timeout_seconds}s",
        }]


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

function fakeRequest() {
  const events = {};
  return {
    write() { return true; },
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
        record({kind: 'network', api: moduleName + '.' + name, target: safeString(args[0])});
        const callback = args.find((arg) => typeof arg === 'function');
        const request = fakeRequest();
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
  net.connect = function(...args) { record({kind: 'network', api: 'net.connect', target: safeString(args[0])}); return fakeRequest(); };
  net.createConnection = function(...args) { record({kind: 'network', api: 'net.createConnection', target: safeString(args[0])}); return fakeRequest(); };
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
  return {
    commands: { registerCommand: noop, executeCommand: async () => undefined },
    window: {
      showInformationMessage: async () => undefined,
      showWarningMessage: async () => undefined,
      showErrorMessage: async () => undefined,
      createWebviewPanel: () => ({ webview: { html: '', onDidReceiveMessage: noop, postMessage: async () => true }, onDidDispose: noop })
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


def _write_entrypoint_runner(path: Path, target: Path, manifest: dict[str, Any]) -> None:
    main = _extension_main(manifest)
    path.write_text(
        f"""
const path = require('path');
const target = {json.dumps(str(target))};
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
    secret_read = False
    network_seen = False
    for line in trace_file.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = event.get("kind")
        if kind == "fs_read":
            path = str(event.get("path") or "")
            if path in canary_set or any(path.endswith(suffix) for suffix in ("/.env", "/.npmrc", "/.ssh/id_ed25519", "/.aws/credentials")):
                secret_read = True
                observations.append({
                    "kind": "secret_read",
                    "path": path,
                    "api": event.get("api"),
                })
        elif kind == "network":
            network_seen = True
            observations.append({
                "kind": "unexpected_network",
                "destination": event.get("target") or event.get("api") or "unknown",
                "api": event.get("api"),
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
            if any(marker in path.lower() for marker in (".bashrc", ".zshrc", ".profile", "launchagents", "startup", "systemd")):
                observations.append({
                    "kind": "persistence",
                    "path": path,
                    "api": event.get("api"),
                })
    if secret_read and network_seen:
        observations.append({
            "kind": "secret_exfil",
            "destination": "observed-network-after-canary-read",
            "evidence": "runtime trace observed canary credential read and network activity in the same sandbox run",
        })
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
            for member in archive.infolist():
                name = member.filename.replace("\\", "/")
                if not name or name.endswith("/"):
                    continue
                target = (destination / name).resolve()
                if destination.resolve() not in target.parents and target != destination.resolve():
                    continue
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
    return source
