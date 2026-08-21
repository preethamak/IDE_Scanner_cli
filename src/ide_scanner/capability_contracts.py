from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any


@lru_cache(maxsize=1)
def load_contracts() -> dict[str, Any]:
    payload = json.loads(files("ide_scanner").joinpath("contracts/capability-v1.json").read_text(encoding="utf-8"))
    if payload.get("schema_version") != "1" or not isinstance(payload.get("classes"), dict):
        raise ValueError("Invalid capability contract policy")
    return payload


def classify_extension(extension: Any) -> dict[str, Any]:
    """Infer functional class as context; classification never grants trust."""
    payload = load_contracts()
    text = " ".join((str(extension.name), str(extension.description))).lower()
    capabilities = {
        str(item.get("id")) for item in extension.capabilities
        if isinstance(item, dict) and item.get("id")
    }
    ranked: list[tuple[int, str, list[str]]] = []
    for class_id, contract in payload["classes"].items():
        signals: list[str] = []
        for keyword in contract.get("keywords", []):
            if str(keyword).lower() in text:
                signals.append(f"text:{keyword}")
        for capability in contract.get("signals", []):
            if capability in capabilities:
                signals.append(f"capability:{capability}")
        ranked.append((len(signals), str(class_id), signals))
    score, class_id, signals = max(ranked, default=(0, "unknown", []))
    if score == 0:
        class_id, signals = "unknown", []
    return {
        "primary": class_id,
        "confidence": round(min(0.95, 0.35 + score * 0.15), 2) if score else 0.0,
        "signals": signals,
        "contract_version": str(payload["policy_version"]),
    }


def extension_profile(extension_id: str) -> dict[str, Any] | None:
    profile = load_contracts().get("extension_profiles", {}).get(extension_id.lower())
    return dict(profile) if isinstance(profile, dict) else None


def class_contract(class_id: str) -> dict[str, Any]:
    contract = load_contracts()["classes"].get(class_id, {})
    return dict(contract) if isinstance(contract, dict) else {}


def expected_capabilities(profile: dict[str, Any] | None, class_id: str) -> set[str]:
    if profile and isinstance(profile.get("capabilities"), list):
        return {str(item) for item in profile["capabilities"]}
    return {str(item) for item in class_contract(class_id).get("expected", [])}
