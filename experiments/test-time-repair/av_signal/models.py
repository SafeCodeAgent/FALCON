from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class Target:
    path: str
    symbol: str
    language: str
    source: str = ""

    @property
    def key(self) -> str:
        return f"{self.path}::{self.symbol}"


@dataclass(frozen=True)
class Probe:
    id: str
    target: str
    cwe: str
    rationale: str
    script: str
    language: str = "python"


@dataclass(frozen=True)
class Event:
    kind: str
    value: Any = None
    detail: dict[str, Any] = field(default_factory=dict)
    frames: tuple[str, ...] = ()
    phase: str = "target"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        return cls(str(data.get("kind", "")), data.get("value"),
                   dict(data.get("detail") or {}), tuple(data.get("frames") or ()),
                   str(data.get("phase", "target")))


@dataclass
class Trace:
    probe_id: str
    target: str
    language: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    timed_out: bool = False
    oom: bool = False
    observations: list[dict[str, Any]] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    target_frames: list[str] = field(default_factory=list)
    harness_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Trace:
        values = dict(data)
        values["events"] = [Event.from_dict(e) for e in data.get("events", [])]
        return cls(**{k: v for k, v in values.items() if k in cls.__dataclass_fields__})


@dataclass(frozen=True)
class Verdict:
    status: Literal["secure", "insecure", "uncertain"]
    stage: str
    reason: str
    evidence: str = ""
    detector: str = ""


@dataclass
class SignalResult:
    status: Literal["secure", "insecure", "no-evidence"]
    admitted: int
    counterexamples: list[dict[str, Any]] = field(default_factory=list)
    probes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def rl_security_reward(self) -> float:
        return 0.0 if self.status == "insecure" else 1.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"rl_security_reward": self.rl_security_reward}
