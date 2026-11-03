from pathlib import Path

from rich.console import Console

from src.analyzers.python import PythonAnalyzer


def test_ast_strategy_converts_rule_catalog_match_to_normalized_signal(
    tmp_path,
):
    source = tmp_path / "unsafe.py"
    source.write_text("result = eval(value)\n", encoding="utf-8")

    result = PythonAnalyzer().analyze_strategy(
        "ast_pattern_scan",
        [str(source)],
    )

    assert result.status == "completed"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "UNSAFE_EVAL"
    assert finding.kind == "signal"
    assert finding.severity == "high"
    assert finding.location.file == str(source)
    assert finding.location.start_line == 1
    assert finding.origin.strategy == "ast_pattern_scan"
    assert finding.evidence.cwe_id == "CWE-94"


def test_secret_strategy_reports_location_without_secret_value(tmp_path):
    secret_value = "example-test-password-not-real"
    source = tmp_path / "config.py"
    source.write_text(f'PASSWORD = "{secret_value}"\n', encoding="utf-8")

    result = PythonAnalyzer().analyze_strategy("secret_scan", [str(source)])

    assert result.status == "completed"
    assert result.findings
    assert all(finding.kind == "secret" for finding in result.findings)
    assert all(secret_value not in finding.message for finding in result.findings)
    assert all(finding.location.start_line == 1 for finding in result.findings)
    assert all(finding.origin.strategy == "secret_scan" for finding in result.findings)

    output = Console(record=True)
    PythonAnalyzer.display_strategy_result(result, output)
    assert secret_value not in output.export_text()


def test_ast_parse_failure_is_reported_instead_of_silently_discarded(tmp_path):
    source = tmp_path / "broken.py"
    source.write_text("def unfinished(:\n", encoding="utf-8")

    result = PythonAnalyzer().analyze_strategy(
        "ast_pattern_scan",
        [str(source)],
    )

    assert result.status == "failed"
    assert result.findings == []
    assert result.diagnostics[0].code == "python_parse_error"
    assert result.diagnostics[0].file == str(source)


def test_strategy_contract_types_are_available_for_future_implementations():
    result = PythonAnalyzer().analyze_strategy("cfg_analysis", [])

    assert result.strategy == "cfg_analysis"
    assert result.status == "unavailable"
    assert result.findings == []
    assert result.diagnostics


def test_location_contract_supports_optional_evidence_points():
    from src.results import AnalysisPoint, Location

    point = AnalysisPoint(
        location=Location(file=Path("module.py").as_posix(), start_line=4),
        label="SQL execute",
    )

    assert point.location.start_line == 4
    assert point.label == "SQL execute"
