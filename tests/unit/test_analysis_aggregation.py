from src.aggregation import aggregate_results
from src.results import (
    Finding,
    FindingOrigin,
    Location,
    PatternEvidence,
    StrategyResult,
)


def _finding(strategy):
    return Finding(
        rule_id="EXAMPLE",
        kind="signal",
        category="security_signal",
        severity="medium",
        confidence=None,
        message="Example signal.",
        location=Location(file="sample.py", start_line=3, end_line=3),
        evidence=PatternEvidence(description="Syntax-level pattern."),
        origin=FindingOrigin(strategy=strategy),
    )


def test_aggregate_preserves_strategy_and_finding_order_without_deduplication():
    first = StrategyResult(
        strategy="ast_pattern_scan",
        status="completed",
        findings=[_finding("ast_pattern_scan")],
    )
    second = StrategyResult(
        strategy="cfg_analysis",
        status="unavailable",
        findings=[_finding("cfg_analysis")],
    )

    aggregate = aggregate_results([first, second])

    assert aggregate.status == "partial"
    assert aggregate.results == [first, second]
    assert aggregate.findings == [first.findings[0], second.findings[0]]
    assert [finding.origin.strategy for finding in aggregate.findings] == [
        "ast_pattern_scan",
        "cfg_analysis",
    ]


def test_aggregate_distinguishes_all_failed_from_partial_runs():
    failed = StrategyResult(strategy="ast_pattern_scan", status="failed")

    assert aggregate_results([failed]).status == "failed"
    assert aggregate_results(
        [failed, StrategyResult(strategy="secret_scan", status="completed")]
    ).status == "partial"
    assert aggregate_results([]).status == "completed"
