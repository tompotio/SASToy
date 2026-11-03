"""Typed result contracts shared by analysis strategies and aggregation."""

from dataclasses import dataclass, field
from typing import Literal, TypeAlias


StrategyStatus: TypeAlias = Literal[
    "completed",
    "partial",
    "failed",
    "unavailable",
]
AggregateStatus: TypeAlias = Literal["completed", "partial", "failed"]
Severity: TypeAlias = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unknown",
]
FindingKind: TypeAlias = Literal[
    "signal",
    "secret",
    "taint_flow",
    "policy_violation",
    "symbolic_path",
]
SymbolicFeasibility: TypeAlias = Literal["feasible", "infeasible", "unknown"]


@dataclass(slots=True)
class Location:
    """Source location associated with a finding or evidence point."""

    file: str
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None


@dataclass(slots=True)
class FindingOrigin:
    """Strategy that produced a finding."""

    strategy: str


@dataclass(slots=True)
class PatternEvidence:
    """Evidence for a syntax-level security signal."""

    description: str
    cwe_id: str | None = None
    cwe_name: str | None = None


@dataclass(slots=True)
class SecretEvidence:
    """Non-sensitive metadata about a detected secret."""

    detector: str
    verified: bool


@dataclass(slots=True)
class AnalysisPoint:
    """A named point in a source-level analysis."""

    location: Location
    label: str | None = None


@dataclass(slots=True)
class DataFlowEvidence:
    """Source-to-sink path information for a data-flow finding."""

    source: AnalysisPoint
    sink: AnalysisPoint
    sanitizers: list[AnalysisPoint] = field(default_factory=list)


@dataclass(slots=True)
class CFIPolicyEvidence:
    """Observed control-flow transfer and the policy used to assess it."""

    transfer: AnalysisPoint
    observed_target: str
    allowed_targets: list[str]
    policy: str


@dataclass(slots=True)
class SymbolicPathEvidence:
    """Path and constraints supporting a symbolic-execution finding."""

    entry_point: AnalysisPoint
    path: list[AnalysisPoint]
    sink: AnalysisPoint
    constraints: list[str]
    feasibility: SymbolicFeasibility


FindingEvidence: TypeAlias = (
    PatternEvidence
    | SecretEvidence
    | DataFlowEvidence
    | CFIPolicyEvidence
    | SymbolicPathEvidence
)


@dataclass(slots=True)
class Finding:
    """Normalized security signal or finding from one strategy."""

    rule_id: str
    kind: FindingKind
    category: str
    severity: Severity
    confidence: float | None
    message: str
    location: Location | None
    evidence: FindingEvidence
    origin: FindingOrigin


@dataclass(slots=True)
class AnalysisDiagnostic:
    """Problem or limitation encountered while running a strategy."""

    code: str
    message: str
    file: str | None = None
    line: int | None = None


@dataclass(slots=True)
class StrategyResult:
    """All findings and diagnostics produced by one strategy run."""

    strategy: str
    status: StrategyStatus
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[AnalysisDiagnostic] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisAggregate:
    """Ordered, non-deduplicated collection of strategy results."""

    status: AggregateStatus
    results: list[StrategyResult]
    findings: list[Finding]
