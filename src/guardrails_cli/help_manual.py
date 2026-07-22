from __future__ import annotations


TOPICS = ("scan", "reports", "profiles", "automation", "shortcuts", "examples")


OVERVIEW = """# Guardrails Local Scan

Scan extensions installed in VS Code, Cursor, Windsurf, VSCodium, and VS Code
Insiders without executing extension code.

## Start here

  guardrails                 Open the interactive Local Scan application
  guardrails scan --all      Scan every detected installation
  guardrails help scan       Learn how scan targets and filters work
  guardrails doctor          Check analyzers and detected IDEs

## Command map

  scan       Scan installed extensions, a local package, or Marketplace artifact
  report     View, verify, or export an existing report
  rules      Browse or search the local detection-rule catalog
  metrics    Explain decisions, scores, evidence, and coverage
  doctor     Check the scanner engine, analyzers, terminal, and IDE discovery
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
                                   shortcuts, or examples

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

Installed folders are copied into private temporary snapshots. Extension code is
not executed. `--online` enables registry and dependency checks for local inputs.
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
