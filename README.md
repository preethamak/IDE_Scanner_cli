<img src="src/guardrails_cli/assets/guardrails-mark.png" width="72" alt="Guardrails mark">

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

The picker displays at most ten installations per page. Search with `/query`, move with `n` and `p`, toggle rows with `1,3-5`, and press `d` to scan the selected installations. `a` explicitly selects every filtered match; Guardrails never dumps the entire installed inventory into the terminal by default.

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
guardrails report view report.zip --extension publisher.extension
```

Guardrails supports terminal, canonical ZIP, HTML, Markdown, and raw JSON output. Existing ZIP exports are copied without recalculating their evidence. Interactive exports show numbered formats and descriptions before asking for a choice. Multi-IDE copies of the same extension version receive distinct installation identities and detail records in verified ZIP reports.

Terminal reports lead with the overall decision and required action. BLOCK, INCOMPLETE, and REVIEW results are shown before ALLOW results; use `--show-all` only when the complete terminal list is needed.

## Automation and exit codes

Use `--fail-on block`, `--fail-on review`, or `--fail-on never` to control policy failure. The default is `block`.

- `0`: analysis completed and the policy threshold passed
- `1`: analysis completed but reached the configured `--fail-on` threshold
- `2`: invalid command, selection, or configuration
- `3`: required analysis was incomplete
- `4`: operational failure
- `130`: cancelled

## Engine relationship

This repository owns the Guardrails terminal product. It consumes the canonical scanner from [IDE_Scanner](https://github.com/preethamak/IDE_Scanner), which keeps CLI and website scans on the same versioned analysis implementation.

## Development

```bash
python -m unittest discover -s tests -v
```

See the [CLI product contract](docs/product-design.md) for interaction, report, security, and release requirements.

## License

MIT
