from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Target:
    path: str
    qualname: str
    kind: str
    start: int
    end: int
    source: str
    imports: str = ""

    @property
    def canonical(self) -> str:
        return f"{self.path}::{self.qualname}"


@dataclass(frozen=True)
class Probe:
    id: str
    target: str
    cwe: str
    rationale: str
    script: str


@dataclass
class Trace:
    probe_id: str
    target: str
    returncode: int | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    observations: list[dict[str, Any]] = field(default_factory=list)
    frames: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    exception: dict[str, Any] | None = None
    target_return: Any = None
    harness_error: str = ""
    duration_s: float = 0.0

    def for_judge(self) -> dict[str, Any]:
        value = asdict(self)
        # stdout/stderr are free-form text printed by the attacker script. The
        # measured return, exception, frames and attributed events are separate.
        value.pop("stdout", None)
        value.pop("stderr", None)
        return value


@dataclass(frozen=True)
class Decision:
    verdict: str
    stage: int | None
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    detector: str = ""


@dataclass
class ProbeRecord:
    probe: Probe
    static_reasons: list[str] = field(default_factory=list)
    runtime_reasons: list[str] = field(default_factory=list)
    trace: Trace | None = None
    decision: Decision | None = None

    @property
    def admitted(self) -> bool:
        return not self.static_reasons and not self.runtime_reasons and self.trace is not None


@dataclass
class CheckReport:
    verdict: str
    records: list[ProbeRecord]
    errors: list[str] = field(default_factory=list)

    @property
    def counterexamples(self) -> list[ProbeRecord]:
        return [r for r in self.records if r.admitted and r.decision and r.decision.verdict == "insecure"]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["faithfulness"] = {
            "generated": len(self.records),
            "f_stat_rejected": sum(bool(r.static_reasons) for r in self.records),
            "f_att_rejected": sum(bool(r.runtime_reasons) for r in self.records if not r.static_reasons),
            "admitted": sum(r.admitted for r in self.records),
            "execution_errors": sum(not r.static_reasons and r.trace is None for r in self.records),
        }
        return value
