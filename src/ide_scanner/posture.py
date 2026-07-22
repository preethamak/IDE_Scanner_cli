from __future__ import annotations

import json
import os
import platform
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .jsonc import loads_jsonc
from .models import PostureMetric


@dataclass(frozen=True)
class ClientLayout:
    id: str
    label: str
    settings_files: list[Path]
    extension_roots: list[Path]
    state_files: list[Path]


def scan_posture(home: Path | None = None) -> list[PostureMetric]:
    """Scan local IDE/client security posture.

    These metrics answer a different question than extension malware scanning:
    "Can this IDE/client configuration let otherwise-normal extensions, tasks, or
    agents operate with risky defaults?"
    """
    metrics: list[PostureMetric] = []
    for layout in _client_layouts(home):
        settings = _load_first_jsonc(layout.settings_files)
        extensions = _load_installed_extensions(layout.extension_roots)
        manifests = _load_extension_manifests(layout.extension_roots)
        trusted_paths = _trusted_paths_from_state(layout.state_files)

        if settings is None and not extensions and not manifests:
            continue

        metrics.append(_client_detected(layout, settings, extensions, manifests))
        metrics.extend(_settings_metrics(layout, settings, trusted_paths))
        metrics.extend(_extension_metrics(layout, extensions, manifests))

    if not metrics:
        return [
            PostureMetric(
                "clients-found",
                "skipped",
                "No VS Code-compatible clients, user settings, or extension inventories were found.",
                category="client-discovery",
                recommendation="Install VS Code, Cursor, Windsurf, VSCodium, or provide explicit extension paths to scan.",
            )
        ]

    return [_summary_metric(metrics), *metrics]


def summarize_posture(metrics: list[PostureMetric] | list[dict[str, Any]]) -> dict[str, Any]:
    normalized = [_metric_dict(metric) for metric in metrics]
    actionable = [metric for metric in normalized if metric.get("id") != "client-risk-summary"]
    counts = {"failure": 0, "warning": 0, "success": 0, "skipped": 0}
    for metric in actionable:
        status = str(metric.get("status") or "skipped")
        if status in counts:
            counts[status] += 1
    max_score = max((int(metric.get("score") or 0) for metric in actionable), default=0)
    weighted = _weighted_score(actionable)
    status = _status_from_score(max(max_score, weighted))
    clients = sorted({str(metric.get("client")) for metric in actionable if metric.get("client") and metric.get("client") != "system"})
    return {
        "status": status,
        "score": max(max_score, weighted),
        "max_metric_score": max_score,
        "weighted_score": weighted,
        "counts": counts,
        "clients": clients,
        "total_metrics": len(actionable),
        "top_findings": [
            {
                "id": metric.get("id"),
                "client": metric.get("client"),
                "status": metric.get("status"),
                "score": metric.get("score"),
                "reason": metric.get("reason"),
                "recommendation": metric.get("recommendation"),
            }
            for metric in sorted(actionable, key=lambda item: (int(item.get("score") or 0), str(item.get("id"))), reverse=True)
            if int(metric.get("score") or 0) > 0
        ][:5],
    }


def _client_detected(
    layout: ClientLayout,
    settings: dict[str, Any] | None,
    extensions: list[dict[str, Any]],
    manifests: dict[str, dict[str, Any]],
) -> PostureMetric:
    return PostureMetric(
        "client-detected",
        "success",
        f"{layout.label} local configuration was found.",
        {
            "settings_found": settings is not None,
            "installed_extensions": len(extensions) if extensions else len(manifests),
        },
        client=layout.id,
        category="client-discovery",
        score=0,
    )


def _settings_metrics(
    layout: ClientLayout,
    settings: dict[str, Any] | None,
    trusted_paths: list[str],
) -> list[PostureMetric]:
    if settings is None:
        return [
            PostureMetric(
                "settings-found",
                "skipped",
                f"No {layout.label} user settings file was found.",
                client=layout.id,
                category="configuration",
                recommendation="Scanner can still inspect installed extensions, but client posture is incomplete without settings.json.",
            )
        ]

    broad_paths = [path for path in trusted_paths if _is_broad_path(path)]
    trust_enabled = settings.get("security.workspace.trust.enabled", True)
    startup_prompt = settings.get("security.workspace.trust.startupPrompt", "once")
    untrusted_files = settings.get("security.workspace.trust.untrustedFiles", "prompt")
    if trust_enabled is False:
        workspace_status, workspace_score = "failure", 92
        workspace_reason = "Workspace Trust is disabled, so unfamiliar folders can run with fewer guardrails."
    elif broad_paths:
        workspace_status, workspace_score = "failure", 88
        workspace_reason = f"{len(broad_paths)} broad trusted path(s) reduce Restricted Mode protection."
    elif untrusted_files == "open":
        workspace_status, workspace_score = "warning", 54
        workspace_reason = "Untrusted files open without prompting."
    elif startup_prompt == "never":
        workspace_status, workspace_score = "warning", 48
        workspace_reason = "Workspace Trust startup prompts are disabled."
    else:
        workspace_status, workspace_score = "success", 0
        workspace_reason = "Workspace Trust is enabled with normal prompts and no broad trusted paths found."

    auto_tasks = settings.get("task.allowAutomaticTasks", "off")
    auto_tasks_on = auto_tasks == "on"
    auto_task_score = 82 if auto_tasks_on and broad_paths else 48 if auto_tasks_on else 36 if broad_paths else 0
    auto_task_status = "failure" if auto_task_score >= 80 else "warning" if auto_task_score else "success"

    agent_enabled = settings.get("chat.agent.enabled", True)
    global_auto = settings.get("chat.tools.global.autoApprove") is True or settings.get("chat.tools.autoApprove") is True
    terminal_rules = settings.get("chat.tools.terminal.autoApprove")
    terminal_ignore_defaults = settings.get("chat.tools.terminal.ignoreDefaultAutoApproveRules") is True
    dangerous_terminal = _dangerous_terminal_rules(terminal_rules)
    url_rules = settings.get("chat.tools.urls.autoApprove")
    dangerous_urls = _dangerous_url_rules(url_rules)
    overrides = _risky_trust_overrides(settings.get("extensions.supportUntrustedWorkspaces"))

    return [
        PostureMetric(
            "workspace-trust",
            workspace_status,
            workspace_reason,
            {
                "security.workspace.trust.enabled": trust_enabled,
                "security.workspace.trust.untrustedFiles": untrusted_files,
                "security.workspace.trust.startupPrompt": startup_prompt,
                "trusted_paths": trusted_paths,
                "broad_trusted_paths": broad_paths,
            },
            client=layout.id,
            category="filesystem-isolation",
            score=workspace_score,
            weight=2.5,
            recommendation="Enable Workspace Trust, keep prompts active, and remove broad trusted paths such as home, Downloads, Desktop, or filesystem roots.",
        ),
        PostureMetric(
            "automatic-tasks",
            auto_task_status,
            "Automatic tasks are enabled with broad trust paths." if auto_tasks_on and broad_paths else "Automatic tasks are enabled." if auto_tasks_on else "Broad trusted paths exist, but automatic tasks are not globally enabled." if broad_paths else "Automatic tasks are not globally enabled.",
            {"task.allowAutomaticTasks": auto_tasks, "broad_trusted_paths": broad_paths},
            client=layout.id,
            category="execution-controls",
            score=auto_task_score,
            weight=2.0,
            recommendation="Set task.allowAutomaticTasks to off unless you have strong workspace trust hygiene.",
        ),
        PostureMetric(
            "agent-global-auto-approve",
            "failure" if agent_enabled and global_auto else "success",
            "Agent mode has global tool auto-approval enabled." if agent_enabled and global_auto else "Global agent tool auto-approval is disabled or agent mode is disabled.",
            {
                "chat.agent.enabled": agent_enabled,
                "chat.tools.global.autoApprove": settings.get("chat.tools.global.autoApprove"),
                "chat.tools.autoApprove": settings.get("chat.tools.autoApprove"),
            },
            client=layout.id,
            category="agent-execution-controls",
            score=95 if agent_enabled and global_auto else 0,
            weight=3.0,
            recommendation="Disable global auto-approval so tool, terminal, URL, and workspace actions require explicit confirmation.",
        ),
        PostureMetric(
            "terminal-auto-approve",
            "failure" if agent_enabled and global_auto and (terminal_ignore_defaults or dangerous_terminal) else "warning" if _has_items(terminal_rules) else "success",
            "Terminal auto-approval allows risky command patterns or ignores built-in defaults." if agent_enabled and global_auto and (terminal_ignore_defaults or dangerous_terminal) else "Terminal auto-approval has custom rules; review scope." if _has_items(terminal_rules) else "No custom terminal auto-approval rules found.",
            {
                "chat.tools.terminal.autoApprove": terminal_rules,
                "chat.tools.terminal.ignoreDefaultAutoApproveRules": terminal_ignore_defaults,
                "dangerous_rules": dangerous_terminal,
            },
            client=layout.id,
            category="agent-execution-controls",
            score=90 if agent_enabled and global_auto and (terminal_ignore_defaults or dangerous_terminal) else 45 if _has_items(terminal_rules) else 0,
            weight=2.5,
            recommendation="Keep terminal auto-approval empty or strictly read-only; never ignore the built-in deny rules for destructive commands.",
        ),
        PostureMetric(
            "url-auto-approve",
            "failure" if agent_enabled and global_auto and dangerous_urls else "warning" if _has_items(url_rules) else "success",
            "URL auto-approval includes broad or external URL patterns." if dangerous_urls else "URL auto-approval has custom rules; review scope." if _has_items(url_rules) else "No custom URL auto-approval rules found.",
            {"chat.tools.urls.autoApprove": url_rules, "dangerous_rules": dangerous_urls},
            client=layout.id,
            category="external-content-security",
            score=72 if agent_enabled and global_auto and dangerous_urls else 36 if _has_items(url_rules) else 0,
            weight=1.5,
            recommendation="Keep URL auto-approval empty or limited to explicit internal hosts; avoid wildcards and public domains.",
        ),
        PostureMetric(
            "extension-trust-overrides",
            "failure" if overrides else "success",
            f"{len(overrides)} extension trust override(s) allow extensions to run in Restricted Mode." if overrides else "No extension trust overrides found.",
            {"extensions.supportUntrustedWorkspaces": settings.get("extensions.supportUntrustedWorkspaces"), "risky_overrides": overrides},
            client=layout.id,
            category="extension-controls",
            score=76 if overrides else 0,
            weight=1.5,
            recommendation="Remove extension trust overrides unless each extension has been explicitly reviewed for Restricted Mode safety.",
        ),
    ]


def _extension_metrics(
    layout: ClientLayout,
    extensions: list[dict[str, Any]],
    manifests: dict[str, dict[str, Any]],
) -> list[PostureMetric]:
    if not extensions and not manifests:
        return [
            PostureMetric(
                "extensions-found",
                "skipped",
                f"No {layout.label} extension inventory was found.",
                client=layout.id,
                category="extension-controls",
            )
        ]

    installed_by_folder = {
        str(item.get("relativeLocation") or item.get("identifier", {}).get("uuid") or ""): item
        for item in extensions
        if isinstance(item, dict)
    }
    startup: list[dict[str, Any]] = []
    agentic: list[dict[str, Any]] = []
    native_or_packed: list[dict[str, Any]] = []

    for folder, manifest in manifests.items():
        extension_id = _manifest_extension_id(manifest)
        activation = [str(item) for item in manifest.get("activationEvents") or []]
        if "*" in activation or "onStartupFinished" in activation:
            startup.append({"id": extension_id, "folder": folder, "activation_events": activation})

        contributes = manifest.get("contributes") if isinstance(manifest.get("contributes"), dict) else {}
        agent_keys = [
            key for key in ("languageModelTools", "chatParticipants", "mcpServers", "mcpServerDefinitionProviders")
            if key in contributes
        ]
        if agent_keys:
            agentic.append({"id": extension_id, "folder": folder, "contributes": agent_keys})

        root = _manifest_root(manifests, folder)
        artifacts = _risky_artifact_names(root) if root else []
        if artifacts:
            native_or_packed.append({"id": extension_id, "folder": folder, "artifacts": artifacts[:12]})

    sideloaded = []
    for item in extensions:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        if metadata.get("source") == "vsix":
            sideloaded.append({
                "id": (item.get("identifier") or {}).get("id", "unknown"),
                "version": item.get("version", "unknown"),
                "source": "vsix",
            })

    return [
        PostureMetric(
            "extension-startup",
            "warning" if startup else "success",
            f"{len(startup)} extension(s) activate at startup or for every workspace." if startup else "No startup or wildcard activation extensions found.",
            {"startup_extensions": startup},
            client=layout.id,
            category="extension-controls",
            score=44 if startup else 0,
            weight=1.5,
            recommendation="Review startup and wildcard activation extensions; disable ones that are not required for daily work.",
        ),
        PostureMetric(
            "sideloaded-extensions",
            "failure" if sideloaded else "success",
            f"{len(sideloaded)} sideloaded VSIX extension(s) bypass marketplace update and vetting flows." if sideloaded else "No sideloaded VSIX extensions found in the inventory.",
            {"sideloaded_extensions": sideloaded},
            client=layout.id,
            category="supply-chain-posture",
            score=78 if sideloaded else 0,
            weight=2.0,
            recommendation="Remove untrusted sideloaded extensions or replace them with reviewed, signed, marketplace/internal-registry builds.",
        ),
        PostureMetric(
            "agentic-extensions",
            "warning" if agentic else "success",
            f"{len(agentic)} extension(s) expose agent-facing tools, chat participants, or MCP surfaces." if agentic else "No agent-facing extension contribution points found.",
            {"agentic_extensions": agentic},
            client=layout.id,
            category="agent-surface",
            score=52 if agentic else 0,
            weight=1.5,
            recommendation="Review agent-facing extensions for tool permissions, approval prompts, and data boundaries.",
        ),
        PostureMetric(
            "native-or-packed-extension-artifacts",
            "warning" if native_or_packed else "success",
            f"{len(native_or_packed)} extension(s) include native binaries or packed archives." if native_or_packed else "No native or packed extension artifacts found in posture inventory.",
            {"extensions": native_or_packed},
            client=layout.id,
            category="supply-chain-posture",
            score=38 if native_or_packed else 0,
            weight=1.0,
            recommendation="Confirm native binaries and packed archives are expected, signed, reproducible, and shipped by trusted publishers.",
        ),
    ]


def _summary_metric(metrics: list[PostureMetric]) -> PostureMetric:
    summary = summarize_posture(metrics)
    return PostureMetric(
        "client-risk-summary",
        summary["status"],
        _summary_reason(summary),
        summary,
        category="summary",
        score=int(summary["score"]),
        weight=3.0,
        recommendation="Fix failure metrics first, then warnings that increase execution or agent autonomy.",
    )


def _summary_reason(summary: dict[str, Any]) -> str:
    counts = summary["counts"]
    if counts["failure"]:
        return f"IDE/client posture has {counts['failure']} failure metric(s) and {counts['warning']} warning metric(s)."
    if counts["warning"]:
        return f"IDE/client posture has {counts['warning']} warning metric(s)."
    return "IDE/client posture did not find risky client configuration metrics."


def _weighted_score(metrics: list[dict[str, Any]]) -> int:
    weighted = [
        (int(metric.get("score") or 0), float(metric.get("weight") or 1.0))
        for metric in metrics
        if metric.get("status") not in {"skipped", None}
    ]
    total_weight = sum(weight for _, weight in weighted)
    if not total_weight:
        return 0
    return int(round(sum(score * weight for score, weight in weighted) / total_weight))


def _status_from_score(score: int) -> str:
    if score >= 70:
        return "failure"
    if score >= 25:
        return "warning"
    return "success"


def _metric_dict(metric: PostureMetric | dict[str, Any]) -> dict[str, Any]:
    return metric.to_dict() if isinstance(metric, PostureMetric) else dict(metric)


def _client_layouts(home: Path | None = None) -> list[ClientLayout]:
    home = (home or Path.home()).expanduser()
    system = platform.system().lower()
    appdata = Path(os.environ["APPDATA"]) if system == "windows" and os.environ.get("APPDATA") else None
    local = Path(os.environ["LOCALAPPDATA"]) if system == "windows" and os.environ.get("LOCALAPPDATA") else None

    linux_config = home / ".config"
    mac_config = home / "Library" / "Application Support"
    layouts = [
        _layout("vscode", "VS Code", home, linux_config, mac_config, appdata, local, "Code", ".vscode"),
        _layout("vscode-insiders", "VS Code Insiders", home, linux_config, mac_config, appdata, local, "Code - Insiders", ".vscode-insiders"),
        _layout("vscodium", "VSCodium", home, linux_config, mac_config, appdata, local, "VSCodium", ".vscodium"),
        _layout("cursor", "Cursor", home, linux_config, mac_config, appdata, local, "Cursor", ".cursor"),
        _layout("windsurf", "Windsurf", home, linux_config, mac_config, appdata, local, "Windsurf", ".windsurf"),
    ]
    return layouts


def _layout(
    client_id: str,
    label: str,
    home: Path,
    linux_config: Path,
    mac_config: Path,
    appdata: Path | None,
    local: Path | None,
    config_name: str,
    dot_dir: str,
) -> ClientLayout:
    settings = [
        linux_config / config_name / "User" / "settings.json",
        mac_config / config_name / "User" / "settings.json",
        home / dot_dir / "User" / "settings.json",
    ]
    extension_roots = [
        home / dot_dir / "extensions",
        mac_config / config_name / "extensions",
    ]
    state_files = [
        linux_config / config_name / "User" / "globalStorage" / "state.vscdb",
        mac_config / config_name / "User" / "globalStorage" / "state.vscdb",
    ]
    if appdata:
        settings.append(appdata / config_name / "User" / "settings.json")
        extension_roots.append(appdata / config_name / "extensions")
        state_files.append(appdata / config_name / "User" / "globalStorage" / "state.vscdb")
    if local:
        state_files.append(local / config_name / "User" / "globalStorage" / "state.vscdb")
    return ClientLayout(client_id, label, settings, extension_roots, state_files)


def _load_first_jsonc(files: list[Path]) -> dict[str, Any] | None:
    for file in files:
        if not file.exists():
            continue
        try:
            parsed = loads_jsonc(file.read_text(encoding="utf-8"))
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return None


def _load_installed_extensions(extension_roots: list[Path]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in extension_roots:
        inventory = root / "extensions.json"
        if not inventory.exists():
            continue
        try:
            parsed = json.loads(inventory.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        items = parsed if isinstance(parsed, list) else parsed.get("extensions") if isinstance(parsed, dict) else []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            key = json.dumps(item.get("identifier") or item.get("relativeLocation") or item, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out


def _load_extension_manifests(extension_roots: list[Path]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    roots_by_folder: dict[str, Path] = {}
    for root in extension_roots:
        if not root.exists() or not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            manifest_file = child / "package.json"
            if not child.is_dir() or not manifest_file.exists():
                continue
            try:
                parsed = json.loads(manifest_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(parsed, dict):
                out.setdefault(child.name, parsed)
                roots_by_folder.setdefault(child.name, child)
    _MANIFEST_ROOTS.clear()
    _MANIFEST_ROOTS.update(roots_by_folder)
    return out


_MANIFEST_ROOTS: dict[str, Path] = {}


def _manifest_root(_manifests: dict[str, dict[str, Any]], folder: str) -> Path | None:
    return _MANIFEST_ROOTS.get(folder)


def _trusted_paths_from_state(state_files: list[Path]) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for file in state_files:
        if not file.exists():
            continue
        for path in _trusted_paths_from_sqlite(file):
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def _trusted_paths_from_sqlite(file: Path) -> list[str]:
    try:
        connection = sqlite3.connect(f"file:{file}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    try:
        rows = connection.execute("select value from ItemTable where key like '%workspace.trust%' or key like '%trusted%'").fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    paths: list[str] = []
    for (value,) in rows:
        if not isinstance(value, str) or "uriTrustInfo" not in value:
            continue
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            continue
        for entry in parsed.get("uriTrustInfo", []):
            if not isinstance(entry, dict) or not entry.get("trusted"):
                continue
            uri = entry.get("uri") if isinstance(entry.get("uri"), dict) else {}
            path = uri.get("fsPath") or uri.get("path")
            if isinstance(path, str) and path:
                paths.append(path)
    return paths


def _is_broad_path(path_str: str) -> bool:
    path = path_str.lower().replace("\\", "/").rstrip("/")
    parts = [part for part in path.split("/") if part]
    if not parts or parts == ["~"]:
        return True
    if len(parts) == 1 and parts[0].endswith(":"):
        return True
    risky_dirs = {"desktop", "downloads", "documents", "public"}
    if parts[-1] in risky_dirs:
        return True
    if parts[0] in {"users", "home"} and len(parts) <= 2:
        return True
    if ":" in parts[0] and len(parts) > 1 and parts[1] == "users" and len(parts) <= 3:
        return True
    return False


def _has_items(value: Any) -> bool:
    return isinstance(value, dict) and bool(value)


def _dangerous_terminal_rules(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    dangerous_terms = ("*", "rm", "del", "sudo", "curl", "wget", "ssh", "eval", "chmod", "chown", "powershell", "pwsh", "bash", "sh", "python", "node", "npm", "npx")
    out: list[str] = []
    for key, rule in value.items():
        text = f"{key} {rule}".lower()
        if any(term in text for term in dangerous_terms):
            out.append(str(key))
    return out


def _dangerous_url_rules(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    out: list[str] = []
    for key, rule in value.items():
        text = f"{key} {rule}".lower()
        if "*" in text or "http://" in text or text in {"true", "allow"}:
            out.append(str(key))
        elif any(domain in text for domain in ("github.com", "raw.githubusercontent.com", "pastebin.com", "gist.github.com")):
            out.append(str(key))
    return out


def _risky_trust_overrides(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    out: list[str] = []
    for extension_id, config in value.items():
        if config is True:
            out.append(str(extension_id))
        elif isinstance(config, dict) and config.get("supported") in {True, "limited"}:
            out.append(str(extension_id))
    return out


def _manifest_extension_id(manifest: dict[str, Any]) -> str:
    publisher = str(manifest.get("publisher") or "unknown")
    name = str(manifest.get("name") or "unknown")
    return f"{publisher}.{name}"


def _risky_artifact_names(root: Path | None) -> list[str]:
    if root is None or not root.exists():
        return []
    risky_suffixes = {".dll", ".dylib", ".exe", ".node", ".so", ".7z", ".asar", ".gz", ".jar", ".rar", ".tar", ".tgz", ".war", ".zip"}
    pruned_dirs = {"node_modules", "media", "themes", "syntaxes", ".git"}
    out: list[str] = []
    try:
        # Prune skipped directories in place so os.walk never descends into
        # node_modules and other large trees. The previous rglob("*") walked
        # every file in those trees just to filter them out afterwards, which
        # made posture scanning of installed extensions take tens of seconds.
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in pruned_dirs]
            for filename in filenames:
                if Path(filename).suffix.lower() not in risky_suffixes:
                    continue
                out.append(Path(dirpath, filename).relative_to(root).as_posix())
                if len(out) >= 25:
                    return out
    except OSError:
        return out
    return out
