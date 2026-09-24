from __future__ import annotations


TOPICS = ("scan", "brief", "reports", "profiles", "policy", "automation", "shortcuts", "examples")


OVERVIEW = """# Guardrails Local Scan

Scan extensions installed in VS Code, Cursor, Windsurf, VSCodium, and VS Code
Insiders with deterministic static analysis by default. Deep scans add a
capability-gated Bubblewrap runtime for resolvable executable entrypoints and
sensitive capability surfaces; extension code is never executed on the host.

## Start here

  guardrails                 Open the interactive Local Scan application
  guardrails scan --all      Scan every detected installation
  guardrails help scan       Learn how scan targets and filters work
  guardrails doctor          Check analyzers, runtime sandbox, and IDEs

## Command map

  scan       Scan installed extensions, a local package, or Marketplace artifact
  brief      Create an agent-safe pre-recommendation brief for Marketplace candidates
  report     View, verify, or export an existing report
  rules      Browse or search the local detection-rule catalog
  metrics    Explain decisions, scores, evidence, and coverage
  policy     Check installations or published artifact hashes against an enterprise policy
  doctor     Check the scanner engine, analyzers, runtime sandbox, terminal, and IDE discovery
  help       Open this manual or a specific topic
  tui        Explicitly open the interactive Local Scan application
  version    Print the installed Guardrails version

## Command families

  report view PATH                 Display a saved ZIP or JSON report
  report verify PATH               Validate report structure and identities
  report export PATH --format FMT  Convert a saved report without rescanning
  rules list                       List the complete rule catalog
  rules search QUERY               Search rule titles, IDs, and descriptions
  rules show RULE_ID               Explain one detection rule
  metrics [TOPIC]                  Explain result terminology
  help [TOPIC]                     Read scan, reports, profiles, automation,
                                   policy, shortcuts, or examples

Run `guardrails COMMAND --help` for every flag accepted by a command.
Run `guardrails help shortcuts` for interactive controls.
Interactive help opens as a terminal application; piped help remains plain text
so it works with files, scripts, and shell tools.
"""


SECTIONS = {
    "scan": """# Scan targets and filters

Interactive Local Scan:

  guardrails
  guardrails scan

Installed extensions:

  guardrails scan --all --yes
  guardrails scan --ide cursor --all --yes
  guardrails scan --search solidity --select 1
  guardrails scan --extension publisher.extension

Other artifacts:

  guardrails scan --file extension.vsix
  guardrails scan --file ./unpacked-extension
  guardrails scan --marketplace publisher.extension@1.2.3

For deterministic CI or website/CLI parity, replay the exact versioned advisory
snapshot used by the release gate:

  guardrails scan --file extension.vsix \\
    --extension-advisories extension-advisories.json

Deep scans run the executable-capability portion of the exact artifact in a
Bubblewrap namespace with networking disabled. This applies to Marketplace,
local, uploaded, and installed-extension inputs. Purely declarative packages
without an executable entrypoint are recorded as not applicable. Use `--runtime`
to request this pass outside the deep profile.

Installed folders are copied into private temporary snapshots. Local extension
code is not executed by the default local scan. `--online` enables registry and
dependency checks for local inputs.
""",
    "brief": """# Pre-recommendation risk briefs

Use a brief before an agent recommends a Marketplace extension. Guardrails
acquires each exact artifact, scans it without installing anything, and emits
an evidence gate for every candidate. Deep briefs also run the capability-gated
runtime pass in Bubblewrap. A brief never installs an extension and does not
claim that any result is safe.

  guardrails brief --purpose "read and edit plist files" \\
    --marketplace ivhernandez.vscode-plist \\
    --marketplace mariano-g.plist-editor

For an agent or a review system, use JSON:

  guardrails brief --purpose "read plist files" \\
    --marketplace publisher.extension@1.2.3 --format json --output brief.json

Gate meanings:

The same `--extension-advisories ADVISORIES.json` option is available on
`guardrails brief` when comparing candidates against a frozen advisory feed.

  eligible_for_recommendation  Completed analysis found no decision-level evidence.
                               This is not proof that the artifact is safe.
  needs_human_review           Context is required before a recommendation.
  not_recommended              The scan found evidence supporting a block.
  insufficient_evidence        Acquisition, identity, or required analysis is incomplete.

Agents must not recommend or install a candidate that requires review, is not
recommended, or has insufficient evidence. Reputation signals are context, not
proof of safety.

The JSON contract exposes `candidate.agent_handoff.recommendation_permitted`
for the deterministic recommendation gate. Every brief returns
`installation_permitted: false`; a separate user approval and organization
policy are required before installation.

Each candidate also carries observed Marketplace installs/ratings/update date,
GitHub repository activity/archive state, and the OSV dependency-advisory
coverage status. These are transparent comparison signals, not a combined
reputation score or an assurance that a release is safe.
""",
    "reports": """# Reports

Formats:

  terminal   Outcome-first interactive display
  html       Readable, shareable local report
  zip        Canonical verifiable evidence bundle
  json       Automation and integrations
  md         Documentation and review notes

Interactive exports are saved in the directory where Guardrails was started.
After saving, the result screen shows the complete absolute path and provides
Copy path plus Open report/Open folder actions.

Examples:

  guardrails scan --all --yes --format zip --output report.zip
  guardrails report verify report.zip
  guardrails report view report.zip
  guardrails report view report.zip --extension publisher.extension
  guardrails report export report.zip --format html --output report.html

ZIP exports contain engine, build, ruleset, profile, artifact hashes, installation
identities, provider status, decisions, and evidence. Verification does not rescan.
""",
    "profiles": """# Analysis profiles

  standard   Default local analysis using required native and JavaScript providers
  offline    No network checks; suitable for isolated environments
  deep       Website Deep Scan boundary when every required provider is available

Deep requires Semgrep, YARA, and dependency advisory coverage. A missing required
provider produces INCOMPLETE, never ALLOW.

  guardrails scan --all --profile standard --yes
  guardrails scan --file extension.vsix --profile offline
  guardrails scan --extension publisher.extension --profile deep
""",
    "policy": """# Enterprise policy checks

GuardRails workspaces can export a deny-by-default enterprise policy bundle.
The bundle contains exact approved extension versions and their published
artifact SHA-256 values. The VS Code settings inside the bundle enforce the
approved versions; the Guardrails CLI checks local installations against the
same exact-release list.

  guardrails policy check --bundle guardrails-enterprise-policy.json
  guardrails policy check --bundle guardrails-enterprise-policy.json --ide cursor
  guardrails policy check --bundle guardrails-enterprise-policy.json --format json
  guardrails policy verify --bundle guardrails-enterprise-policy.json --artifact extension.vsix

An installed extension directory can be checked for ID and version, but it is
not the original Marketplace VSIX. Such an installation is reported as
version-allowed but unverified, and the policy check is not compliant until
`policy verify` hashes the published artifact. Unknown versions fail closed
because the policy default is DENY.
""",
    "automation": """# Automation

Non-interactive scans require an explicit scope such as `--all`, `--extension`,
or `--select`. Use `--format` and `--output` to avoid prompts.

Policy threshold:

  --fail-on block    Exit 1 for BLOCK (default)
  --fail-on review   Exit 1 for REVIEW or BLOCK
  --fail-on never    Never fail solely because of a completed decision

Exit codes:

  0     Completed and policy threshold passed
  1     Completed but policy threshold reached, or report verification failed
  2     Invalid command, selection, or configuration
  3     Required analysis incomplete
  4     Operational or environment failure
  130   Cancelled
""",
    "shortcuts": """# Interactive shortcuts

  Up/Down       Move through extensions
  Space         Select or clear the highlighted extension
  /             Focus search
  Ctrl+S        Scan selected extensions
  Ctrl+A        Scan every visible match after confirmation
  Ctrl+C        Copy the complete report, or the highlighted extension identity
  ?             Open the help manual
  Escape        Close a dialog or return to extension selection
  Q             Quit when focus is outside a text field

The mouse can select rows, filters, and buttons. Search updates while you type;
there are no search commands to remember.
""",
    "examples": """# Common workflows

Review extensions installed in Cursor:

  guardrails scan --ide cursor --all --yes

Create and verify a canonical report:

  guardrails scan --all --yes --format zip --output local-scan.zip
  guardrails report verify local-scan.zip

Match the website boundary for one installation:

  guardrails scan --extension publisher.extension --profile deep

Use Guardrails in CI:

  guardrails scan --file extension.vsix --format json --output report.json \\
    --fail-on review
""",
}


def manual(topic: str | None = None) -> str:
    return (OVERVIEW if not topic else SECTIONS[topic]).strip() + "\n"


def interactive_manual() -> str:
    sections = [OVERVIEW, SECTIONS["shortcuts"], SECTIONS["profiles"], SECTIONS["reports"]]
    return "\n\n---\n\n".join(section.strip() for section in sections) + "\n"
