"""Prototype data and orchestration for exhaustive-mode demonstration reports."""

from dataclasses import dataclass
from typing import Callable, Sequence


@dataclass
class StrategyResult:
    """One strategy's demonstration output or execution error."""

    strategy: str
    status: str
    output: object = None
    error: str | None = None


STRATEGY_LABELS = {
    "security_signals": "Signaux de sécurité",
    "hcs": "Secrets codés en dur (HCS)",
}

UNAVAILABLE_STRATEGIES = {
    "cfi": "CFI (Control Flow Integrity)",
    "sqli": "SQLi (injection SQL)",
}


def demo_security_signals(_files: Sequence[str]) -> list[dict[str, object]]:
    """Return illustrative signals; this is not a scan of the target files."""
    return [
        {
            "file": "exemple_app.py",
            "rule": "EXEMPLE_EVAL",
            "line": 18,
            "description": "Un appel à eval() pourrait exécuter une entrée non fiable.",
            "evidence": "Extrait fictif masqué pour la démonstration.",
        },
        {
            "file": "exemple_routes.py",
            "rule": "EXEMPLE_SUBPROCESS",
            "line": 42,
            "description": "Une commande système mérite une revue de ses arguments.",
            "evidence": "Extrait fictif masqué pour la démonstration.",
        },
    ]


def demo_hardcoded_secrets(_files: Sequence[str]) -> list[dict[str, object]]:
    """Return illustrative secret-detection output without any secret value."""
    return [
        {
            "file": "exemple_config.py",
            "rule": "EXEMPLE_SECRET",
            "line": 12,
            "description": "Valeur ressemblant à un secret détectée (exemple fictif).",
            "evidence": "Valeur masquée ; donnée fictive.",
        }
    ]


DEMO_RUNNERS: dict[str, Callable[[Sequence[str]], object]] = {
    "security_signals": demo_security_signals,
    "hcs": demo_hardcoded_secrets,
}


def run_strategies(
    strategies: Sequence[str],
    files: Sequence[str],
    runners: dict[str, Callable[[Sequence[str]], object]] = DEMO_RUNNERS,
) -> list[StrategyResult]:
    """Run selected strategies sequentially and retain errors without aborting."""
    results = []
    for strategy in strategies:
        try:
            results.append(
                StrategyResult(
                    strategy=strategy,
                    status="demo",
                    output=runners[strategy](files),
                )
            )
        except Exception as exc:
            results.append(
                StrategyResult(
                    strategy=strategy,
                    status="error",
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
    return results
