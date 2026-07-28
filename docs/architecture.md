# Guardrails CLI Architecture

The CLI is a private local-scan presentation client. It discovers installed extensions, creates private snapshots, invokes `guardlens-core`, and exports canonical reports without changing scanner policy.

## Boundaries

- `guardrails_cli/scanner_adapter.py` verifies the installed `guardlens-core` wheel before importing scanner modules, then exposes narrow scan and report-adaptation calls.
- `snapshot.py` owns temporary private scan copies and cleanup.
- `scan_service.py` owns user-selected profile semantics.
- `presentation.py`, `tui.py`, and `exporters/` own display and export only.

## Engine integrity

`engine_distribution.json` pins the required core version. The adapter checks every installed scanner file against the package `RECORD` hash before scanner code loads. The release verifier rejects a CLI wheel containing `ide_scanner` files; the engine is never copied into this repository.

## Contract

CLI reports preserve the engine decision, analysis status, scores, ruleset/policy versions, intelligence snapshot, and scanner build identity. The CLI may add local installation identity and presentation metadata, but cannot convert an incomplete scan into an approval.
