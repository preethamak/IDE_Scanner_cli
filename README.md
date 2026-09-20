# Guardrails CLI

Scan extensions installed in VS Code, Cursor, Windsurf, VSCodium, and VS Code
Insiders without executing extension code on the host. Standard and offline
scans are static; Deep Scan may execute required capability paths only inside a
network-disabled Bubblewrap namespace. The CLI and scanner runtime are
distributed together as one package.

## Install

```bash
pipx install guardlens
```

The installed command is `guardrails`.

For Deep Scan providers:

```bash
pipx install "guardlens[analysis]"
```

## Use

Open the interactive local scanner:

```bash
guardrails
```

Common commands:

```bash
guardrails scan --ide cursor --all --yes
guardrails scan --extension publisher.extension
guardrails scan --file extension.vsix
guardrails brief --purpose "read and edit plist files" --marketplace ivhernandez.vscode-plist --marketplace mariano-g.plist-editor
guardrails inventory --ide cursor --output team-inventory.json
guardrails report verify report.zip
guardrails help
```

Guardrails reports the decision, risk score, malware evidence score, analysis
coverage, provider status, and detailed findings. Reports can be exported as
HTML, ZIP, JSON, or Markdown.

## Pre-recommendation briefs

Before an agent recommends a Marketplace extension, create a brief for the
exact candidate artifacts. The brief contains an evidence gate, provenance
signals, artifact SHA-256, Marketplace and GitHub maintenance signals, OSV
dependency-advisory coverage, and decision-relevant rules. It does not install
extensions or claim to prove an extension safe.

```bash
guardrails brief --purpose "read and edit plist files" \
  --marketplace ivhernandez.vscode-plist \
  --marketplace mariano-g.plist-editor \
  --format json --output plist-risk-brief.json
```

## Analysis profiles

- `standard`: required local static and JavaScript analysis.
- `offline`: local analysis without network checks.
- `deep`: the website Deep Scan boundary when all required providers and the
  isolated runtime are available. Deep scans require runtime execution;
  `standard` is the static-only diagnostic profile.

If the isolated runtime or any required provider is unavailable, the result is
`INCOMPLETE`, never an apparent `ALLOW`.

Missing required analysis produces `INCOMPLETE`, never `ALLOW`.

## Engine integrity

The scanner runtime remains bundled inside Guardrails. Its exact source
revision and file hashes are recorded in the package, and CI rejects unrecorded
engine drift:

```bash
python scripts/sync_vendored_engine.py --check
```

## Privacy

Installed extensions are analyzed from private temporary snapshots. Extension
code is not executed or uploaded. Files remain local unless a report is
explicitly exported.

Website: [ide-scanner.vercel.app](https://ide-scanner.vercel.app)

## License

Proprietary. Copyright © 2026 Preetham AK. All rights reserved.
