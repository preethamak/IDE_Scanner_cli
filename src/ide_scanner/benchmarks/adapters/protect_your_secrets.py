from __future__ import annotations

import csv
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

DATASET_ID = "vscode-credential-exposure-2024"
SOURCE_NAME = "Protect Your Secrets replication package"
SOURCE_URL = "https://github.com/yueyueL/VSCode-Extensions-Security-Analysis/"

TYPE_TO_RULE = {
    "RequestedConfiguration": "credential-config-key",
    "WorkspaceConfiguration": "credential-config-key",
    "GlobalState": "credential-global-state-key",
    "InputBox": "credential-inputbox-prompt",
    "RequestedCommands": "credential-command-registration",
    "Commands": "credential-command-execution",
}

TYPE_TO_EXPOSURE = {
    "RequestedConfiguration": "configuration",
    "WorkspaceConfiguration": "configuration",
    "GlobalState": "globalState",
    "InputBox": "inputBox",
    "RequestedCommands": "command",
    "Commands": "command",
}


def normalize_ground_truth_csv(input_path: Path | str, *, source_ref: str = SOURCE_URL) -> dict[str, Any]:
    """Normalize the paper's labeled CSV into IDE Scanner benchmark JSON.

    The public CSV labels individual data points as Credential, PII, or Other.
    Only Credential rows are converted into expected credential-exposure findings;
    PII and Other rows are preserved as non-credential labels for future benchmark
    extensions without treating them as vulnerabilities.
    """
    rows = _read_rows(Path(input_path))
    by_extension: dict[str, list[dict[str, str]]] = defaultdict(list)
    label_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    for row in rows:
        extension_id = row.get("extensionID", "").strip()
        if not extension_id:
            continue
        label = row.get("is_vulnerable", "").strip() or "Other"
        item_type = row.get("type", "").strip()
        label_counts[label] += 1
        type_counts[item_type] += 1
        by_extension[extension_id].append(row)

    extensions: list[dict[str, Any]] = []
    for extension_id, items in sorted(by_extension.items()):
        credential_items = [item for item in items if item.get("is_vulnerable") == "Credential"]
        pii_items = [item for item in items if item.get("is_vulnerable") == "PII"]
        expected_findings = sorted({
            TYPE_TO_RULE[item["type"]]
            for item in credential_items
            if item.get("type") in TYPE_TO_RULE
        })
        exposure_types = sorted({
            TYPE_TO_EXPOSURE[item["type"]]
            for item in credential_items
            if item.get("type") in TYPE_TO_EXPOSURE
        })
        label = "credential_exposure" if credential_items else "non_credential"
        if pii_items and not credential_items:
            label = "pii_exposure"
        extensions.append({
            "extension_id": extension_id,
            "version": "unknown",
            "label": label,
            "exposure_types": exposure_types,
            "expected_findings": expected_findings,
            "credential_data_points": [_benchmark_data_point(item) for item in credential_items[:25]],
            "pii_data_points": [_benchmark_data_point(item) for item in pii_items[:25]],
            "install_count": _first_install_count(items),
            "reference": source_ref,
        })

    return {
        "schema_version": "1.0",
        "dataset_id": DATASET_ID,
        "source": SOURCE_NAME,
        "source_url": SOURCE_URL,
        "label_granularity": "data-point",
        "total_data_points": sum(label_counts.values()),
        "credential_data_points": label_counts.get("Credential", 0),
        "pii_data_points": label_counts.get("PII", 0),
        "other_data_points": label_counts.get("Other", 0),
        "extension_count": len(extensions),
        "credential_extension_count": sum(1 for item in extensions if item["label"] == "credential_exposure"),
        "type_counts": dict(sorted(type_counts.items())),
        "label_counts": dict(sorted(label_counts.items())),
        "extensions": extensions,
    }


def write_normalized_dataset(input_path: Path | str, output_path: Path | str, *, source_ref: str = SOURCE_URL) -> dict[str, Any]:
    dataset = normalize_ground_truth_csv(input_path, source_ref=source_ref)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dataset, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dataset


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        return [
            {str(key).lstrip("\ufeff"): str(value or "") for key, value in row.items()}
            for row in reader
        ]


def _benchmark_data_point(item: dict[str, str]) -> dict[str, str]:
    item_type = item.get("type", "")
    return {
        "type": item_type,
        "exposure_type": TYPE_TO_EXPOSURE.get(item_type, "unknown"),
        "expected_finding": TYPE_TO_RULE.get(item_type, ""),
        "data": item.get("data", "")[:500],
    }


def _first_install_count(items: list[dict[str, str]]) -> int:
    for item in items:
        try:
            return int(item.get("install") or 0)
        except ValueError:
            continue
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize the Protect Your Secrets ground-truth CSV.")
    parser.add_argument("input", help="Path to data/Ground_Truth_datasets.csv")
    parser.add_argument("output", help="Path to write normalized benchmark JSON")
    parser.add_argument("--source-ref", default=SOURCE_URL, help="Reference URL or local commit for this dataset copy.")
    args = parser.parse_args(argv)
    dataset = write_normalized_dataset(args.input, args.output, source_ref=args.source_ref)
    print(json.dumps({
        "output": args.output,
        "dataset_id": dataset["dataset_id"],
        "extension_count": dataset["extension_count"],
        "credential_extension_count": dataset["credential_extension_count"],
        "credential_data_points": dataset["credential_data_points"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
