# Guardrails CLI Architecture

The CLI is a private local-scan presentation client. It discovers installed extensions, creates private snapshots, invokes its bundled scanner runtime, and exports canonical reports without changing scanner policy.

## Boundaries

- `guardrails_cli/scanner_adapter.py` verifies the bundled scanner runtime before importing scanner modules, then exposes narrow scan and report-adaptation calls.
- `snapshot.py` owns temporary private scan copies and cleanup.
- `scan_service.py` owns user-selected profile semantics.
- `presentation.py`, `tui.py`, and `exporters/` own display and export only.

## Engine integrity

`engine_source.json` records the canonical scanner revision and a SHA-256 hash for every bundled runtime file. The adapter checks those hashes before scanner code loads. CI synchronizes the bundled runtime from `ide-scanner` and rejects any unrecorded drift. Users install one `guardlens` wheel with no scanner runtime dependency.

## Contract

CLI reports preserve the engine decision, analysis status, scores, ruleset/policy versions, intelligence snapshot, and scanner build identity. The CLI may add local installation identity and presentation metadata, but cannot convert an incomplete scan into an approval.
