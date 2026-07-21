# Guardrails CLI

Scan extensions installed in VS Code, Cursor, Windsurf, VSCodium, and VS Code Insiders from your terminal.

Guardrails analyzes a private temporary snapshot of each selected installation. Extension code is not executed, and files remain on the machine unless a report is explicitly exported.

## Install from GitHub

```bash
pipx install "git+https://github.com/preethamak/IDE_Scanner_cli.git"
```

For a development checkout:

```bash
git clone https://github.com/preethamak/IDE_Scanner_cli.git
cd IDE_Scanner_cli
python -m venv .venv
.venv/bin/python -m pip install -e .
```

On Windows, replace `.venv/bin/` with `.venv\Scripts\`.

## Scan installed extensions

Start the interactive installed-extension picker:

```bash
guardrails scan
```

Search and select from installed extensions:

```bash
guardrails scan --search solidity --select 1
```

Other useful scopes:

```bash
guardrails scan --ide cursor --all --yes
guardrails scan --extension publisher.extension
guardrails scan --file extension.vsix
guardrails scan --marketplace publisher.extension@1.2.3
```

## Analysis profiles

- `standard` requires the native and JavaScript analyzers and is the default.
- `offline` disables network checks.
- `deep` matches the website Deep Scan boundary when Semgrep, YARA, and dependency advisory checks are available. Missing required providers produce `INCOMPLETE`, never `ALLOW`.

Install the optional local analyzers with:

```bash
pipx inject guardrails-ide-scanner semgrep yara-python
```

## Reports

```bash
guardrails scan --extension publisher.extension --format zip --output report.zip
guardrails report verify report.zip
guardrails report view report.zip
guardrails report export report.zip --format html --output report.html
```

Guardrails supports terminal, canonical ZIP, HTML, Markdown, and raw JSON output. Existing ZIP exports are copied without recalculating their evidence.

## Engine relationship

This repository owns the Guardrails terminal product. It consumes the canonical scanner from [IDE_Scanner](https://github.com/preethamak/IDE_Scanner), which keeps CLI and website scans on the same versioned analysis implementation.

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT
