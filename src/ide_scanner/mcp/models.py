from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


VETO_ORDER = {None: 0, "warning": 1, "failure": 2}


@dataclass(frozen=True)
class MetricSpec:
    name: str
    title: str
    weight: float
    runner: str | None = None
    children: tuple["MetricSpec", ...] = ()

    @property
    def is_module(self) -> bool:
        return bool(self.children)


@dataclass
class MetricRunOutput:
    score: float | None
    status: str = "success"
    veto: str | None = None
    veto_message: str | None = None
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    # The reference metric engine calls this field ``artifacts``.  Keep both
    # spellings while the public report contract remains ``details``.
    artifacts: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.artifacts is not None:
            self.details = self.artifacts
        else:
            self.artifacts = self.details

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "status": self.status,
            "veto": self.veto,
            "veto_message": self.veto_message,
            "message": self.message,
            "details": self.details,
            "artifacts": self.details,
        }


@dataclass
class MetricResult:
    name: str
    title: str
    weight: float
    score: float | None
    status: str
    message: str
    veto: str | None = None
    veto_message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    children: list["MetricResult"] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["children"] = [child.as_dict() for child in self.children]
        return value


def higher_veto(*values: str | None) -> str | None:
    return max(values, key=lambda value: VETO_ORDER.get(value, 0))
