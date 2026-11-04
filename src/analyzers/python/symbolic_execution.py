"""Symbolic execution strategy entry point."""

from src.results import AnalysisDiagnostic, StrategyResult


def analyze(files: list[str]) -> StrategyResult:
    """Return the defined unavailable result until symbolic execution is implemented."""
    del files
    return StrategyResult(
        strategy="symbolic_execution",
        status="unavailable",
        diagnostics=[
            AnalysisDiagnostic(
                code="strategy_not_implemented",
                message=(
                    "La stratégie symbolic_execution est définie mais son "
                    "analyse n'est pas encore implémentée."
                ),
            )
        ],
    )
