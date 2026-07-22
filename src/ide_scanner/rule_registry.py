from __future__ import annotations

from .models import RuleMetadata
from .rules import CODE_RULES

RULESET_VERSION = "2026.07.19"


_RULE_OVERRIDES: dict[str, dict[str, object]] = {
    "untrusted-workspace-input-to-process": {
        "title": "Workspace input reaches process execution",
        "category": "execution",
        "evidence_class": "capability",
        "default_severity": "MEDIUM",
        "description": "Workspace or user configuration reaches a process execution API. This is common in developer tooling and is not malware evidence by itself.",
        "recommendation": "Confirm the command is user initiated, workspace trust is respected, and arguments avoid shell interpolation.",
        "false_positive_notes": "Language servers, linters, formatters, and security tools commonly launch a configured local executable.",
        "benchmark_tags": ["semgrep", "workspace", "execution"],
    },
    "webview-message-to-process": {
        "title": "Webview message reaches execution",
        "category": "webview",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Semgrep taint analysis found webview-controlled message data reaching an execution sink.",
        "recommendation": "Validate message schemas and keep webview data away from command construction.",
        "benchmark_tags": ["semgrep", "webview", "execution"],
    },
    "decoded-payload-execution": {
        "title": "Decoded payload reaches dynamic execution",
        "category": "code",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Semgrep found decoded or deobfuscated data flowing into dynamic execution.",
        "recommendation": "Remove dynamic payload execution or make the decoded artifact immutable and verifiable.",
        "benchmark_tags": ["semgrep", "obfuscation", "execution"],
    },
    "unicode-evasion": {
        "title": "Unicode source-code evasion",
        "category": "code",
        "evidence_class": "weak",
        "default_severity": "MEDIUM",
        "description": "YARA matched bidirectional or invisible Unicode control bytes.",
        "recommendation": "Inspect the matched bytes and remove invisible controls from executable files.",
        "benchmark_tags": ["yara", "unicode", "evasion"],
    },
    "encoded-dynamic-execution": {
        "title": "Encoded dynamic execution",
        "category": "code",
        "evidence_class": "weak",
        "default_severity": "HIGH",
        "description": "YARA matched encoded payload handling and dynamic-execution markers in one file.",
        "recommendation": "Use this as supporting context. Escalate only when a data-flow or runtime rule confirms decoded content reaches execution.",
        "benchmark_tags": ["yara", "obfuscation", "execution"],
    },
    "embedded-pe-artifact": {
        "title": "Embedded portable executable",
        "category": "artifact",
        "evidence_class": "provenance",
        "default_severity": "MEDIUM",
        "description": "YARA found portable executable content embedded inside another artifact.",
        "recommendation": "Extract, hash, sign, and independently inspect the embedded executable.",
        "benchmark_tags": ["yara", "binary", "provenance"],
    },
    "credential-exfiltration-chain": {
        "title": "Credential exfiltration chain",
        "category": "credential-access",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects code paths combining credential references, local file reads, and outbound transfer.",
        "recommendation": "Review source and remove the extension if behavior is unexpected.",
        "false_positive_notes": "May trigger on legitimate cloud tooling or credential helpers.",
        "benchmark_tags": ["credential", "filesystem", "network"],
    },
    "agent-data-exfil-chain": {
        "title": "Agent data exfiltration chain",
        "category": "agentic",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects agent-facing code combined with sensitive references and outbound network behavior.",
        "recommendation": "Review agent tool boundaries and approval prompts before trusting the extension.",
        "benchmark_tags": ["agentic", "credential", "network"],
    },
    "download-and-execute": {
        "title": "Download and execute",
        "category": "execution",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects source files that can download content and execute local processes.",
        "recommendation": "Verify download source, integrity checks, and execution purpose.",
        "benchmark_tags": ["download", "execution", "network"],
    },
    "lifecycle-script": {
        "title": "Lifecycle script",
        "category": "supply-chain",
        "evidence_class": "capability",
        "default_severity": "MEDIUM",
        "description": "Package defines install or uninstall lifecycle scripts.",
        "recommendation": "Inspect lifecycle scripts because they execute outside normal extension UI flows.",
        "false_positive_notes": "Many legitimate packages use install scripts to prepare native components.",
        "benchmark_tags": ["supply-chain", "install"],
    },
    "agentic-tooling": {
        "title": "Agent-facing IDE capability",
        "category": "agentic",
        "evidence_class": "capability",
        "default_severity": "MEDIUM",
        "description": "Extension contributes language model tools, chat participants, or MCP server surfaces.",
        "recommendation": "Review tool permissions and approval behavior before trusting agent-facing extensions.",
        "benchmark_tags": ["agentic", "mcp"],
    },
    "native-or-packed-artifact": {
        "title": "Native or packed artifact",
        "category": "artifact",
        "evidence_class": "capability",
        "default_severity": "MEDIUM",
        "description": "Extension package contains native binaries or packed archives.",
        "recommendation": "Confirm binary provenance and inspect packed artifacts before deployment.",
        "benchmark_tags": ["native", "artifact"],
    },
    "known-bad-artifact": {
        "title": "Known-bad artifact",
        "category": "confirmed-intelligence",
        "evidence_class": "confirmed",
        "default_severity": "CRITICAL",
        "description": "Package or file hash matched configured malicious intelligence.",
        "recommendation": "Block or remove this extension.",
        "benchmark_tags": ["confirmed", "hash"],
    },
    "marketplace-removed-package": {
        "title": "Marketplace removed package",
        "category": "provenance",
        "evidence_class": "provenance",
        "default_severity": "HIGH",
        "description": "Extension appears in a marketplace removed package list.",
        "recommendation": "Review removal reason and avoid the extension unless trust is independently established.",
        "benchmark_tags": ["marketplace", "provenance"],
    },
    "malicious-npm-dependency": {
        "title": "Malicious npm dependency",
        "category": "dependency",
        "evidence_class": "confirmed",
        "default_severity": "CRITICAL",
        "description": "Dependency vulnerability intelligence identifies a malicious package.",
        "recommendation": "Remove the extension or replace the affected dependency before use.",
        "benchmark_tags": ["dependency", "malware"],
    },
    "vulnerable-npm-dependency": {
        "title": "Vulnerable npm dependency",
        "category": "dependency",
        "evidence_class": "dependency",
        "default_severity": "HIGH",
        "description": "Dependency vulnerability intelligence reported vulnerable runtime dependencies.",
        "recommendation": "Upgrade or replace the vulnerable dependency.",
        "benchmark_tags": ["dependency", "vulnerability"],
    },
    "safe-configured-cli-execution": {
        "title": "Configured CLI execution",
        "category": "execution",
        "evidence_class": "weak",
        "default_severity": "INFO",
        "description": "Code executes a configured local CLI through execFile-style process execution.",
        "recommendation": "Treat as contextual when the binary path is user-configured and arguments are explicit.",
        "benchmark_tags": ["execution", "cli"],
    },
    "dynamic-shell-execution": {
        "title": "Dynamic shell execution",
        "category": "execution",
        "evidence_class": "capability",
        "default_severity": "MEDIUM",
        "description": "Code uses shell-style process execution.",
        "recommendation": "Review command construction and avoid shell execution for untrusted input.",
        "benchmark_tags": ["execution", "shell"],
    },
    "untrusted-input-execution": {
        "title": "Untrusted input execution",
        "category": "execution",
        "evidence_class": "capability",
        "default_severity": "MEDIUM",
        "description": "Code appears to combine IDE/workspace input with process execution.",
        "recommendation": "Ensure file paths, document content, and workspace values are passed as arguments without shell interpolation.",
        "benchmark_tags": ["execution", "input"],
    },
    "ast-dynamic-call-target": {
        "title": "AST: dynamic call target",
        "category": "execution",
        "evidence_class": "weak",
        "default_severity": "MEDIUM",
        "description": "The AST analyzer found a function call whose target is resolved through computed member access (e.g. obj[x](...)) rather than a literal property name.",
        "recommendation": "Use this as supporting context only. Escalate only when a separate rule resolves the target to a sensitive sink or establishes attacker control.",
        "false_positive_notes": "Legitimate dynamic dispatch (plugin registries, event handler maps, and minifier output) commonly matches this pattern.",
        "benchmark_tags": ["execution", "ast", "evasion"],
    },
    "ast-bracket-notation-sensitive-access": {
        "title": "AST: bracket-notation access to sensitive global",
        "category": "code",
        "evidence_class": "capability",
        "default_severity": "HIGH",
        "description": "The AST analyzer resolved a bracket-notation member access (e.g. window[\"e\"+\"val\"]) to a sensitive name such as eval, Function, require, or child_process, where the property was built at runtime rather than written as a literal string.",
        "recommendation": "Treat this as a deliberate evasion attempt against plain-text detection and review the surrounding code path closely.",
        "benchmark_tags": ["code", "ast", "evasion", "obfuscation"],
    },
    "ast-constructed-dynamic-argument": {
        "title": "AST: constructed argument to a dynamic sink",
        "category": "code",
        "evidence_class": "capability",
        "default_severity": "HIGH",
        "description": "The AST analyzer found eval/Function/require/exec-family calls whose argument is assembled at runtime (string concatenation or String.fromCharCode) and folds to a suspicious keyword, instead of being passed as a plain string literal.",
        "recommendation": "Review why the executed/required target is not a literal; this is the exact shape used to evade regex-based static analysis.",
        "benchmark_tags": ["code", "ast", "evasion", "obfuscation"],
    },
    "credential-config-key": {
        "title": "Credential configuration key",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "LOW",
        "description": "Detects configuration keys or descriptions that appear credential-related.",
        "recommendation": "Use SecretStorage or an OS credential store instead of extension-readable configuration for secrets.",
        "false_positive_notes": "Can trigger on documentation, examples, or non-secret uses of key/token terminology.",
        "benchmark_tags": ["credential", "configuration", "cross-extension"],
    },
    "credential-global-state-key": {
        "title": "Credential global state key",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "LOW",
        "description": "Detects globalState or workspaceState keys that appear credential-related.",
        "recommendation": "Avoid storing credentials in extension state unless access boundaries and lifetime are understood.",
        "benchmark_tags": ["credential", "globalState", "cross-extension"],
    },
    "credential-inputbox-prompt": {
        "title": "Credential InputBox prompt",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "MEDIUM",
        "description": "Detects InputBox prompts or options that appear to request credentials.",
        "recommendation": "Use explicit secret-entry UX and store captured credentials in SecretStorage.",
        "benchmark_tags": ["credential", "inputBox", "cross-extension"],
    },
    "clipboard-read-near-secret-input": {
        "title": "Clipboard read near secret input",
        "category": "cross-extension-exposure",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects clipboard reads near credential-related input or storage surfaces.",
        "recommendation": "Avoid reading clipboard contents around secret capture flows unless the user explicitly requested it.",
        "benchmark_tags": ["credential", "clipboard", "cross-extension"],
    },
    "credential-command-registration": {
        "title": "Credential command registration",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "LOW",
        "description": "Detects commands whose identifiers or labels appear credential-related.",
        "recommendation": "Ensure credential-related commands require explicit user intent and cannot be abused by another extension.",
        "benchmark_tags": ["credential", "commands", "cross-extension"],
    },
    "credential-command-execution": {
        "title": "Credential command execution",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "MEDIUM",
        "description": "Detects execution of credential-related VS Code commands.",
        "recommendation": "Review command control paths and avoid allowing untrusted input to steer credential operations.",
        "benchmark_tags": ["credential", "commands", "cross-extension"],
    },
    "credential-command-control": {
        "title": "Credential command control",
        "category": "cross-extension-exposure",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects credential-related input near cross-extension command or state-control surfaces.",
        "recommendation": "Manually verify whether another extension can invoke, imitate, or influence the credential flow.",
        "benchmark_tags": ["credential", "commands", "inputBox", "cross-extension"],
    },
    "credential-config-update": {
        "title": "Credential configuration storage",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "HIGH",
        "description": "Detects writes of credential-related values to VS Code configuration.",
        "recommendation": "Do not store credentials in VS Code settings; use SecretStorage or an OS credential store.",
        "benchmark_tags": ["credential", "configuration", "storage"],
    },
    "credential-global-state-storage": {
        "title": "Credential global state storage",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "HIGH",
        "description": "Detects writes of credential-related values to globalState or workspaceState.",
        "recommendation": "Avoid storing raw credentials in extension state; use SecretStorage for secret material.",
        "benchmark_tags": ["credential", "globalState", "storage"],
    },
    "credential-dataflow-to-network": {
        "title": "Credential data flow to network",
        "category": "cross-extension-exposure",
        "evidence_class": "correlated",
        "default_severity": "CRITICAL",
        "description": "Detects credential-related source surfaces in a file that also contains network sinks.",
        "recommendation": "Manually verify the data flow. If credential data reaches network sinks unexpectedly, block the extension.",
        "benchmark_tags": ["credential", "network", "dataflow"],
    },
    "credential-dataflow-to-process": {
        "title": "Credential data flow to process",
        "category": "cross-extension-exposure",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects credential-related source surfaces in a file that also contains process execution.",
        "recommendation": "Manually verify whether credentials can influence process execution or command arguments.",
        "benchmark_tags": ["credential", "process", "dataflow"],
    },
    "credential-dataflow-to-file": {
        "title": "Credential data flow to file",
        "category": "cross-extension-exposure",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects credential-related source surfaces in a file that also contains file writes.",
        "recommendation": "Review file persistence paths and ensure raw secrets are not written to workspace or extension files.",
        "benchmark_tags": ["credential", "filesystem", "dataflow"],
    },
    "credential-source-near-network": {
        "title": "Credential source near network sink",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "HIGH",
        "description": "Native static analysis found a credential-related source within a bounded character window of a network sink.",
        "recommendation": "Review the cited code; proximity alone is not a source-to-sink data flow.",
        "false_positive_notes": "Expected in legitimate login, license activation, and authenticated API clients.",
        "benchmark_tags": ["credential", "network", "proximity"],
    },
    "credential-source-near-process": {
        "title": "Credential source near process sink",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "HIGH",
        "description": "Native static analysis found a credential-related source within a bounded character window of process execution.",
        "recommendation": "Review argument construction; proximity alone does not show credential influence over a process.",
        "benchmark_tags": ["credential", "process", "proximity"],
    },
    "credential-source-near-file": {
        "title": "Credential source near file sink",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "HIGH",
        "description": "Native static analysis found a credential-related source within a bounded character window of a file write.",
        "recommendation": "Review the written value and destination; proximity alone does not show that a credential is persisted.",
        "benchmark_tags": ["credential", "filesystem", "proximity"],
    },
    "agent-sensitive-data-near-network": {
        "title": "Agent-sensitive data near network",
        "category": "agentic",
        "evidence_class": "exposure",
        "default_severity": "MEDIUM",
        "description": "Agent-facing code contains a sensitive reference near outbound networking.",
        "recommendation": "Review data boundaries and require flow or runtime evidence before claiming exfiltration.",
        "false_positive_notes": "Bundled agent clients commonly include environment loading and networking in adjacent modules.",
        "benchmark_tags": ["agentic", "credential", "network", "proximity"],
    },
    "credential-input-near-state": {
        "title": "Credential input near extension state",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "HIGH",
        "description": "Credential-like input appears near globalState or workspaceState storage.",
        "recommendation": "Verify the stored value and prefer SecretStorage for raw credentials.",
        "false_positive_notes": "Proximity does not prove that the input value is the value written to state.",
        "benchmark_tags": ["credential", "state", "proximity"],
    },
    "clipboard-near-credential-surface": {
        "title": "Clipboard read near credential surface",
        "category": "cross-extension-exposure",
        "evidence_class": "exposure",
        "default_severity": "HIGH",
        "description": "A clipboard read appears near credential-related input or storage code.",
        "recommendation": "Confirm clipboard access requires explicit user intent and does not capture unrelated clipboard content.",
        "false_positive_notes": "Credential import and paste workflows legitimately use this pattern.",
        "benchmark_tags": ["credential", "clipboard", "proximity"],
    },
    "unrestricted-workspace-cli-path": {
        "title": "Unrestricted workspace-controlled CLI path",
        "category": "execution",
        "evidence_class": "exposure",
        "default_severity": "HIGH",
        "description": "A workspace setting selects an execFile executable and is not restricted in untrusted workspaces.",
        "recommendation": "Restrict the setting through capabilities.untrustedWorkspaces.restrictedConfigurations or disable execution in untrusted workspaces.",
        "benchmark_tags": ["workspace-trust", "configuration", "execution"],
    },
}


# Native rules that are emitted outside CODE_RULES still need to appear in the
# exported rules catalog. Keep this compact catalog close to the metadata builder;
# tests compare it with literal _finding() emissions from scanner.py.
_NATIVE_RULE_DEFAULTS: dict[str, tuple[str, str, str, str]] = {
    "agent-prompt-injection-sink": ("agentic", "capability", "MEDIUM", "Agent contribution metadata combines untrusted-content surfaces with tool execution terms."),
    "binary-without-origin": ("provenance", "provenance", "MEDIUM", "A packaged native binary has no companion checksum, signature, or documented origin."),
    "broad-activation": ("activation", "capability", "LOW", "The extension declares wildcard activation."),
    "credential-file-read": ("credential-access", "weak", "MEDIUM", "Credential references appear near local file-read capability."),
    "dangerous-github-workflow": ("repository-posture", "posture", "MEDIUM", "A packaged GitHub Actions workflow has a dangerous trigger or write permission."),
    "destructive-transfer-chain": ("destructive-activity", "correlated", "HIGH", "Forceful recursive deletion appears near encoding/archive and network behavior."),
    "entrypoint-ast-unparsed": ("coverage", "posture", "LOW", "A declared entrypoint could not be parsed by the AST layer, so structural evasion detection did not run on the primary code path."),
    "install-download-execute": ("install-time", "correlated", "HIGH", "A lifecycle script combines download and command execution."),
    "install-network-telemetry": ("install-time", "weak", "MEDIUM", "A lifecycle script appears to send install-time telemetry."),
    "install-secret-access": ("install-time", "correlated", "HIGH", "A lifecycle script references credential material."),
    "install-shell-obfuscation": ("install-time", "correlated", "HIGH", "A lifecycle script contains decoded, evaluated, or piped shell execution."),
    "license-missing": ("repository-posture", "reputation", "LOW", "The packaged artifact does not include a recognized license file."),
    "mcp-server-command": ("agentic", "capability", "MEDIUM", "The extension contributes an MCP server command or definition."),
    "mutable-dependency-source": ("dependency", "dependency", "MEDIUM", "A runtime dependency uses a mutable or non-registry source."),
    "obfuscation-execution-network": ("execution", "correlated", "HIGH", "Direct decoded execution appears near network behavior."),
    "packed-artifact": ("provenance", "provenance", "MEDIUM", "The extension contains one or more packed artifacts."),
    "persistence-chain": ("persistence", "correlated", "HIGH", "Persistence-location modification appears near execution or network behavior."),
    "powerful-ide-contribution": ("ide-capability", "capability", "LOW", "The extension contributes debugger, task, or terminal capability."),
    "repo-binary-artifacts": ("repository-posture", "posture", "LOW", "The package contains a committed native binary artifact."),
    "repo-url-missing": ("reputation", "reputation", "LOW", "The extension manifest does not declare a source repository."),
    "security-policy-missing": ("repository-posture", "reputation", "LOW", "The packaged artifact does not include a recognized security policy."),
    "sensitive-activation": ("activation", "capability", "LOW", "The extension activates on a security-sensitive IDE event."),
    "startup-activation": ("activation", "capability", "LOW", "The extension activates automatically after IDE startup."),
    "unpinned-dependency": ("dependency", "dependency", "LOW", "A runtime dependency uses an unpinned version specifier."),
    "webview-csp-missing": ("webview", "capability", "MEDIUM", "A detected webview lacks a Content-Security-Policy meta tag."),
    "webview-csp-unsafe-directive": ("webview", "capability", "MEDIUM", "A webview CSP contains an unsafe directive."),
    "workflow-token-permissions-broad": ("repository-posture", "posture", "LOW", "A workflow grants broad token permissions or relies on implicit defaults."),
}


def rule_registry() -> list[RuleMetadata]:
    rules: dict[str, RuleMetadata] = {}
    for rule in CODE_RULES:
        rules[rule.id] = RuleMetadata(
            rule_id=rule.id,
            title=_title(rule.id),
            category=rule.category,
            evidence_class="weak",
            default_severity=rule.severity,  # type: ignore[arg-type]
            description=rule.summary,
            recommendation="Treat this as review evidence unless it combines with credential, network, download, or destructive behavior.",
            benchmark_tags=[rule.category],
            engine=_engine_for(rule.id, [rule.category]),
            decision_effect=_decision_effect("weak"),
            confidence_basis=_confidence_basis("weak"),
        )

    for rule_id, (category, evidence_class, severity, description) in _NATIVE_RULE_DEFAULTS.items():
        rules[rule_id] = RuleMetadata(
            rule_id=rule_id,
            title=_title(rule_id),
            category=category,
            evidence_class=evidence_class,
            default_severity=severity,  # type: ignore[arg-type]
            description=description,
            recommendation="Review the cited evidence and apply the rule-specific remediation in the finding.",
            benchmark_tags=[category],
            engine=_engine_for(rule_id, [category]),
            decision_effect=_decision_effect(evidence_class),
            confidence_basis=_confidence_basis(evidence_class),
        )

    for rule_id, override in _RULE_OVERRIDES.items():
        rules[rule_id] = RuleMetadata(
            rule_id=rule_id,
            title=str(override["title"]),
            category=str(override["category"]),
            evidence_class=str(override["evidence_class"]),
            default_severity=str(override["default_severity"]),  # type: ignore[arg-type]
            description=str(override["description"]),
            recommendation=str(override["recommendation"]),
            false_positive_notes=str(override.get("false_positive_notes") or ""),
            benchmark_tags=list(override.get("benchmark_tags") or []),
            engine=_engine_for(rule_id, list(override.get("benchmark_tags") or [])),
            decision_effect=_decision_effect(str(override["evidence_class"])),
            confidence_basis=_confidence_basis(str(override["evidence_class"])),
        )
    return sorted(rules.values(), key=lambda item: item.rule_id)


def rules_json() -> dict[str, object]:
    return {
        "ruleset_version": RULESET_VERSION,
        "rules": [rule.to_dict() for rule in rule_registry()],
    }


def _title(rule_id: str) -> str:
    return rule_id.replace("-", " ").replace(":", ": ").title()


def _engine_for(rule_id: str, tags: list[str]) -> str:
    if "semgrep" in tags:
        return "semgrep"
    if "yara" in tags:
        return "yara"
    if rule_id.startswith("ast-"):
        return "javascript-ast"
    if rule_id in {"known-bad-artifact", "marketplace-removed-package"}:
        return "threat-intelligence"
    if rule_id in {"malicious-npm-dependency", "vulnerable-npm-dependency"}:
        return "dependency-intelligence"
    if rule_id in {"agentic-tooling", "lifecycle-script"}:
        return "manifest"
    if rule_id in {"native-or-packed-artifact"}:
        return "artifact-inspection"
    if "dataflow" in tags or len(set(tags) & {"credential", "network", "filesystem", "process"}) > 1:
        return "native-correlation"
    return "native-static"


def _decision_effect(evidence_class: str) -> str:
    if evidence_class == "confirmed":
        return "block-by-default"
    if evidence_class in {"correlated", "dependency", "provenance"}:
        return "review-or-block-by-policy"
    if evidence_class in {"capability", "exposure"}:
        return "review-by-policy"
    return "review-context"


def _confidence_basis(evidence_class: str) -> str:
    return {
        "confirmed": "Authoritative artifact or package intelligence matched an exact identity.",
        "correlated": "Multiple related deterministic signals or a source-to-sink path were connected.",
        "dependency": "Resolved dependency identity matched configured package intelligence.",
        "provenance": "Artifact, marketplace, or release-origin evidence changed trust context.",
        "capability": "Deterministic inspection found a sensitive capability; intent is not inferred.",
        "exposure": "Deterministic inspection found a secret or cross-extension boundary exposure.",
        "observed": "A controlled analysis provider recorded the behavior at runtime.",
        "weak": "Single deterministic static indicator; requires surrounding context.",
    }.get(evidence_class, "Deterministic scanner evidence; review the cited source and limitations.")
