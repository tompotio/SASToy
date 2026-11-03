import subprocess
import sys
from pathlib import Path

import pytest

from src.aggregation import aggregate_results
from src.report import generate_report
from src.results import StrategyResult


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_FILE = (
    PROJECT_ROOT
    / "tests"
    / "vulnerabilities"
    / "unsafe_eval"
    / "python"
    / "sample.py"
)


def test_generated_report_displays_aggregated_strategy_results(tmp_path):
    results = [
        StrategyResult(
            strategy="ast_pattern_scan",
            status="completed",
        ),
        StrategyResult(
            strategy="cfg_analysis",
            status="unavailable",
        ),
    ]
    report_path = generate_report(
        target="<cible>",
        files=["/tmp/target.py"],
        aggregate=aggregate_results(results),
        reports_dir=tmp_path / "reports",
    )

    report = report_path.read_text(encoding="utf-8")
    assert report_path.parent == (tmp_path / "reports").resolve()
    assert "AGRÉGAT BRUT · SANS SYNTHÈSE NI SCORING" in report
    assert "completed" in report
    assert "unavailable" in report
    assert "Analyse CFG (CFI, flot/taint et SQLi)" in report
    assert "Exécution symbolique" not in report
    assert "&lt;cible&gt;" in report
    assert "https://" not in report
    assert "<link " not in report


def test_exhaustive_cli_runs_strategies_aggregates_and_creates_report(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "src" / "main.py"),
            "py",
            str(SAMPLE_FILE),
            "--mode",
            "exhaustif",
            "--strategies",
            "ast_pattern_scan",
            "cfg_analysis",
            "secret_scan",
            "symbolic_execution",
        ],
        capture_output=True,
        cwd=tmp_path,
        text=True,
        check=False,
        timeout=30,
    )

    reports = list((tmp_path / "reports").glob("*.html"))
    assert result.returncode == 0, result.stderr
    assert len(reports) == 1
    assert "Rapport exhaustif généré" in result.stdout
    assert "4 stratégie(s), 1 constat(s), statut partial" in result.stdout
    report = reports[0].read_text(encoding="utf-8")
    assert "Résultats des stratégies" in report
    assert "AGRÉGAT BRUT · SANS SYNTHÈSE NI SCORING" in report
    assert "Repérage de motifs syntaxiques" in report
    assert "UNSAFE_EVAL" in report
    assert "completed" in report
    assert "unavailable" in report
    assert "Exécution symbolique" in report


def test_report_rejects_unknown_strategies(tmp_path):
    with pytest.raises(ValueError, match="inconnue"):
        generate_report(
            target="project",
            files=[],
            aggregate=aggregate_results(
                [StrategyResult(strategy="unknown", status="completed")]
            ),
            reports_dir=tmp_path,
        )
