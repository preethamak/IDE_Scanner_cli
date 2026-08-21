from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any


CALIBRATION_RESOURCE = "calibration/scoring-v1.json"
_REQUIRED_COMPONENTS = {
    "confirmed_intelligence",
    "observed_behavior",
    "proven_observed_behavior",
    "correlated_behavior",
    "sensitive_capability",
    "dependency",
    "posture",
    "cross_extension_exposure",
    "reputation",
}


@lru_cache(maxsize=1)
def scoring_calibration() -> dict[str, Any]:
    resource = files("ide_scanner").joinpath(CALIBRATION_RESOURCE)
    data = json.loads(resource.read_text(encoding="utf-8"))
    _validate_calibration(data)
    return data


def policy_version() -> str:
    return str(scoring_calibration()["policy_version"])


def calibrated_score(component: str, rule_id: str, default: int = 0) -> int:
    components = scoring_calibration()["components"]
    scores = components.get(component, {})
    return int(scores.get(rule_id, default))


def max_calibrated_score(component: str, rule_ids: set[str]) -> int:
    return max((calibrated_score(component, rule_id) for rule_id in rule_ids), default=0)


def _validate_calibration(data: Any) -> None:
    if not isinstance(data, dict):
        raise ValueError("Scoring calibration must be a JSON object")
    if data.get("schema_version") != "1":
        raise ValueError("Unsupported scoring calibration schema_version")
    policy = data.get("policy_version")
    if not isinstance(policy, str) or not policy.strip():
        raise ValueError("Scoring calibration requires a policy_version")
    components = data.get("components")
    if not isinstance(components, dict):
        raise ValueError("Scoring calibration requires a components object")
    missing = sorted(_REQUIRED_COMPONENTS - set(components))
    if missing:
        raise ValueError(f"Scoring calibration is missing components: {', '.join(missing)}")
    for component, rules in components.items():
        if not isinstance(rules, dict):
            raise ValueError(f"Calibration component {component!r} must be an object")
        for rule_id, score in rules.items():
            if not isinstance(rule_id, str) or not rule_id:
                raise ValueError(f"Calibration component {component!r} contains an invalid rule id")
            if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
                raise ValueError(f"Calibration score {component}.{rule_id} must be an integer from 0 to 100")
