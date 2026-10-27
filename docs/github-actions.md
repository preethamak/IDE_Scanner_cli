# GuardRails GitHub Actions integration

The GuardRails composite action scans an extension artifact before it is
published, attached to a release, or installed in a test environment. It runs
the same CLI scanner and writes the canonical JSON report; the action does not
upload source code to Abscissa.

## Use the action

```yaml
name: GuardRails extension review

on:
  pull_request:
  release:
    types: [published]

permissions:
  contents: read

jobs:
  scan-extension:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: preethamak/IDE_Scanner_cli@main
        id: guardrails
        with:
          artifact: dist/example.vsix
          profile: standard
          fail-on: review
          upload-report: "true"
          upload-sbom: "true"
      - run: echo "decision=${{ steps.guardrails.outputs.decision }}"
```

For production, replace `@main` with a release tag or full commit SHA and
verify the action revision through your organization’s normal action-pinning
policy.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `artifact` | required | VSIX, ZIP, or unpacked extension path to scan. |
| `profile` | `standard` | `standard` static analysis, `offline` local-only, or `deep` when its providers are available. |
| `fail-on` | `block` | Fails the job at `block`, `review`, or never. |
| `online` | `false` | Enables online dependency and registry intelligence for a local artifact. |
| `extension-advisories` | empty | Pinned advisory snapshot for reproducible CI. |
| `registry-snapshot` | empty | Pinned registry intelligence snapshot for reproducible CI. |
| `report-path` | `guardrails-report.json` | Canonical JSON evidence report path. |
| `upload-report` | `true` | Upload the report for 30 days, including failed policy checks. |
| `sbom-path` | `guardrails-sbom.cdx.json` | Destination for the CycloneDX 1.5 SBOM generated from a completed report. |
| `upload-sbom` | `true` | Generate and retain the SBOM artifact when a canonical report is available. |

## Outputs and failure behavior

`decision`, `extension-count`, `coverage-percent`, `complete`, and
`report-valid`, and `sbom-valid` are action outputs. The summary uses the worst result across all
reported extensions and the lowest coverage percentage. Missing or unreadable
reports become `incomplete`; the action never converts missing analysis into an
allow result.

The scan step is allowed to finish long enough to publish its summary and
evidence artifact. The action then returns a failing status when the configured
`fail-on` threshold was met, preserving normal GitHub branch protection.

## Reproducible CI

Pass `extension-advisories` and `registry-snapshot` created and reviewed by
your team when you need a deterministic evidence boundary. Without them, an
online scan may incorporate current dependency and registry intelligence. The
report records its analysis coverage and artifact identity; use the JSON
artifact as the review record rather than treating a job checkmark as evidence.

The SBOM is a second artifact, not a replacement for the report. It preserves
an observed artifact hash where present and does not invent a hash or resolved
dependency version where the report contains only a version specification.
