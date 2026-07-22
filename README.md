# Guardrails CLI

Scan extensions installed in VS Code, Cursor, Windsurf, VSCodium, and VS Code
Insiders without executing extension code.

## Install

```bash
pipx install guardlens
```

The installed command is `guardrails`.

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
guardrails report verify report.zip
guardrails help
```

Guardrails reports the decision, risk score, malware evidence score, analysis
coverage, provider status, and detailed findings. Reports can be exported as
HTML, ZIP, JSON, or Markdown.

## Analysis profiles

- `standard`: required local static and JavaScript analysis.
- `offline`: local analysis without network checks.
- `deep`: the website Deep Scan boundary when all required providers are available.

Missing required analysis produces `INCOMPLETE`, never `ALLOW`.

## Privacy

Installed extensions are analyzed from private temporary snapshots. Extension
code is not executed or uploaded. Files remain local unless a report is
explicitly exported.

Website: [ide-scanner.vercel.app](https://ide-scanner.vercel.app)

## License

Proprietary. Copyright © 2026 Preetham AK. All rights reserved.
