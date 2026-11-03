import subprocess
import sys
from io import StringIO
from pathlib import Path

from rich.console import Console

from src.analyzers.python import PythonAnalyzer


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_FILE = (
    PROJECT_ROOT
    / "tests"
    / "vulnerabilities"
    / "unsafe_eval"
    / "python"
    / "sample.py"
)


def test_implemented_and_unimplemented_strategies_return_contracts():
    analyzer = PythonAnalyzer()
    files = [str(SAMPLE_FILE)]

    ast_result = analyzer.analyze_strategy("ast_pattern_scan", files)
    secret_result = analyzer.analyze_strategy("secret_scan", files)
    cfg_result = analyzer.analyze_strategy("cfg_analysis", files)
    symbolic_result = analyzer.analyze_strategy("symbolic_execution", files)

    assert ast_result.status == "completed"
    assert any(finding.rule_id == "UNSAFE_EVAL" for finding in ast_result.findings)
    assert secret_result.status == "completed"
    assert cfg_result.status == "unavailable"
    assert symbolic_result.status == "unavailable"
    assert cfg_result.diagnostics[0].code == "strategy_not_implemented"
    assert symbolic_result.diagnostics[0].code == "strategy_not_implemented"


def test_manual_cli_displays_selected_strategy_results_without_aggregation(
    tmp_path,
):
    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "src" / "main.py"),
            "py",
            str(SAMPLE_FILE),
            "--mode",
            "manuel",
        ],
        input="ast_pattern_scan,cfg_analysis\n",
        capture_output=True,
        cwd=tmp_path,
        text=True,
        check=False,
        timeout=30,
    )

    output = " ".join(result.stdout.split())
    assert result.returncode == 0, result.stderr
    assert "UNSAFE_EVAL" in output
    assert "Repérage de motifs syntaxiques — completed" in output
    assert "Analyse CFG (CFI, flot/taint et SQLi) — unavailable" in output
    assert "Agrégation" not in output
    assert not list(tmp_path.glob("reports/*.html"))


def test_unknown_strategy_is_reported():
    output = StringIO()

    PythonAnalyzer().analyze_operation("unknown", [], Console(file=output))

    assert "Opération inconnue : unknown" in output.getvalue()
