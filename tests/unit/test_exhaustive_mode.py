import subprocess
import sys
from pathlib import Path

from src.exhaustive import StrategyResult, run_strategies
from src.report import anonymized_ai_summary, generate_report


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_FILE = (
    PROJECT_ROOT
    / "tests"
    / "vulnerabilities"
    / "unsafe_eval"
    / "python"
    / "sample.py"
)


def test_run_strategies_retains_failure_and_continues():
    executed = []

    def fail(_files):
        executed.append("first")
        raise ValueError("erreur de démonstration")

    def succeed(_files):
        executed.append("second")
        return [{"rule": "EXEMPLE"}]

    results = run_strategies(
        ["first", "second"],
        ["target.py"],
        runners={"first": fail, "second": succeed},
    )

    assert executed == ["first", "second"]
    assert results[0].status == "error"
    assert results[0].error == "ValueError: erreur de démonstration"
    assert results[1].status == "demo"
    assert results[1].output == [{"rule": "EXEMPLE"}]


def test_anonymized_ai_summary_contains_only_strategy_provenance_and_counts():
    results = [
        StrategyResult(
            strategy="hcs",
            status="demo",
            output=[
                {
                    "file": "private_source.py",
                    "secret": "must-not-be-sent",
                    "line": 5,
                }
            ],
        )
    ]

    summary = anonymized_ai_summary(results)

    assert "hcs" in summary
    assert "example_count" in summary
    assert "private_source.py" not in summary
    assert "must-not-be-sent" not in summary
    assert '"line"' not in summary


def test_generated_report_is_standalone_and_labels_demo_data(tmp_path):
    results = [
        StrategyResult(
            strategy="security_signals",
            status="demo",
            output=[
                {
                    "file": "<example>.py",
                    "rule": "EXAMPLE_RULE",
                    "line": 9,
                    "description": "Description <fictive>",
                    "evidence": "Aucun code réel",
                }
            ],
        )
    ]
    report_path = generate_report(
        target="<cible>",
        files=["/tmp/target.py"],
        results=results,
        duration_seconds=1.25,
        ai_status="Non réalisée : token absent.",
        reports_dir=tmp_path / "reports",
    )

    report = report_path.read_text(encoding="utf-8")
    assert report_path.parent == (tmp_path / "reports").resolve()
    assert "DONNÉES FICTIVES" in report
    assert "aucune analyse réelle exécutée" in report
    assert "non implémentée, non exécutée" in report
    assert "Analyse IA — section distincte" in report
    assert "&lt;example&gt;.py" in report
    assert "&lt;cible&gt;" in report
    assert "https://" not in report
    assert "<link " not in report


def test_exhaustive_cli_creates_report_without_running_real_analyzers(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "src" / "main.py"),
            "py",
            str(SAMPLE_FILE),
            "--mode",
            "exhaustif",
            "--strategies",
            "security_signals",
            "hcs",
        ],
        input="n\n",
        capture_output=True,
        cwd=tmp_path,
        text=True,
        check=False,
        timeout=30,
    )

    reports = list((tmp_path / "reports").glob("*.html"))
    assert result.returncode == 0, result.stderr
    assert len(reports) == 1
    assert "Rapport de démonstration généré" in result.stdout
    assert "aucune stratégie n'a analysé la cible" in result.stdout
    assert "DONNÉES FICTIVES" in reports[0].read_text(encoding="utf-8")
