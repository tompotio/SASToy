"""Aggregation of normalized results from independent analysis strategies."""

from collections.abc import Sequence

from src.results import AnalysisAggregate, StrategyResult


def aggregate_results(results: Sequence[StrategyResult]) -> AnalysisAggregate:
    """Combine results without scoring or deduplicating their findings."""
    ordered_results = list(results)
    findings = [
        finding
        for result in ordered_results
        for finding in result.findings
    ]

    statuses = {result.status for result in ordered_results}
    if statuses == {"failed"}:
        status = "failed"
    elif statuses & {"partial", "failed", "unavailable"}:
        status = "partial"
    else:
        status = "completed"

    return AnalysisAggregate(
        status=status,
        results=ordered_results,
        findings=findings,
    )
