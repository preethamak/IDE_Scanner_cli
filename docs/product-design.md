# Guardrails CLI product contract

## Product boundary

Guardrails CLI is an installed-extension security scanner first. Marketplace and local package scans are secondary acquisition paths. It uses a pinned canonical scanner-engine commit so an exact artifact analyzed with the same profile and provider set can be compared with the website Deep Scan.

Extension code is never executed. Installed folders are copied into private, bounded temporary snapshots before analysis. Reports record artifact SHA-256, engine build, ruleset, profile, provider status, and installation identity.

## Primary flow

1. Discover supported IDE installations without printing the full inventory.
2. Search as the user types and filter by IDE without entering picker commands.
3. Navigate by keyboard or mouse, toggle one or more installations, then explicitly start the scan.
4. Show the overall decision and required action before metadata or scores.
5. Show BLOCK, INCOMPLETE, and REVIEW results; collapse ALLOW rows by default.
6. Export through a described, numbered format menu or explicit flags.
7. Write reports atomically and verify canonical ZIP output before success.

`guardrails scan --all` is always explicit. Non-interactive scans require `--all`, `--extension`, or `--select`.

## Terminal behavior

- 32–59 columns: stacked content, two-line identities, no wide tables.
- 60–89 columns: compact rows with bounded identities and reasons.
- 90+ columns: one-line picker identities where possible.
- The interactive application virtualizes scrolling through the filtered inventory and never prints the full inventory into shell history.
- `Space` selects, `Ctrl+S` scans, `/` focuses search, and `?` opens the embedded manual.
- The logo appears once per command. Truecolor terminals render a half-block resampling derived from the exact website PNG; HTML reports embed the original PNG.
- `NO_COLOR` produces a clean wordmark without emitting ANSI color.

## Decision and exit contract

- `0`: completed and policy threshold passed
- `1`: completed but reached `--fail-on block|review`
- `2`: invocation, configuration, or selection error
- `3`: required analysis incomplete
- `4`: operational failure
- `130`: cancelled

Provider failure never becomes ALLOW. Scores prioritize review; they are not proof of malicious intent.

## Report contract

Multi-IDE installations of the same extension version receive distinct deterministic installation IDs and detail references. Canonical ZIPs are written to a temporary file, atomically moved into place, and structurally verified. Existing ZIP exports are copied without recalculating evidence. Shareable output does not include original local installation paths.

## Release acceptance

- Inventories of 0, 1, 20, 100, and 500 installations remain bounded and searchable.
- Output stays within 32, 40, 60, 80, and 120 columns.
- Duplicate cross-IDE installations round-trip through a verified ZIP.
- Missing providers produce explicit INCOMPLETE results when required.
- Expected user errors do not print tracebacks.
- Fresh GitHub installation, wheel build, installed-extension smoke scan, report verification, and Linux/macOS/Windows CI must pass.

## Deferred

Full-screen mouse UI, cloud accounts and sync, scheduled monitoring, automatic uninstall or quarantine, custom policy editing, and generated explanations are outside the first release.
