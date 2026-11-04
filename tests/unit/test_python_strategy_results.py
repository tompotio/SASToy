from pathlib import Path

from rich.console import Console

from src.analyzers.python import PythonAnalyzer
from src.results import DataFlowEvidence


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


def test_taint_strategy_returns_normalized_taint_flow_finding(tmp_path):
    source = tmp_path / "tainted.py"
    source.write_text(
        "import os\n"
        "command = input()\n"
        "os.system(command)\n",
        encoding="utf-8",
    )

    result = PythonAnalyzer().analyze_strategy("taint_analysis", [])

    assert result.strategy == "taint_analysis"
    assert result.status == "completed"
    assert result.findings == []

    result = PythonAnalyzer().analyze_strategy(
        "taint_analysis",
        [str(source)],
    )
    assert result.status == "completed"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "TAINT_COMMAND_INJECTION_OS"
    assert finding.kind == "taint_flow"
    assert finding.location.file == str(source)
    assert finding.location.start_line == 3
    assert finding.origin.strategy == "taint_analysis"
    assert isinstance(finding.evidence, DataFlowEvidence)
    assert finding.evidence.source.location.file == str(source)
    assert finding.evidence.source.location.start_line == 2
    assert finding.evidence.sink.location.start_line == 3


def test_taint_strategy_reports_parse_errors(tmp_path):
    source = tmp_path / "broken.py"
    source.write_text("def unfinished(:\n", encoding="utf-8")

    result = PythonAnalyzer().analyze_strategy("taint_analysis", [str(source)])

    assert result.status == "failed"
    assert result.findings == []
    assert result.diagnostics[0].code == "python_parse_error"


def test_taint_strategy_follows_input_through_local_function_and_import_alias(
    tmp_path,
):
    source = tmp_path / "tainted_function.py"
    source.write_text(
        "import os as operating_system\n"
        "def run(command):\n"
        "    operating_system.system(command)\n"
        "run(input())\n",
        encoding="utf-8",
    )

    result = PythonAnalyzer().analyze_strategy("taint_analysis", [str(source)])

    assert result.status == "completed"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "TAINT_COMMAND_INJECTION_OS"
    assert finding.location.start_line == 3
    assert finding.evidence.source.location.start_line == 4


def test_taint_strategy_recognizes_request_get_as_a_source(tmp_path):
    source = tmp_path / "request_source.py"
    source.write_text(
        "import os\n"
        "command = request.args.get('command')\n"
        "os.system(command)\n",
        encoding="utf-8",
    )

    result = PythonAnalyzer().analyze_strategy("taint_analysis", [str(source)])

    assert result.status == "completed"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "TAINT_COMMAND_INJECTION_OS"
    assert finding.evidence.source.location.start_line == 2


def test_taint_strategy_applies_sanitizers_and_reports_static_sink_rules(
    tmp_path,
):
    source = tmp_path / "sanitized.py"
    source.write_text(
        "import hashlib\n"
        "import os\n"
        "command = escape(input())\n"
        "os.system(command)\n"
        "hashlib.md5(b'data')\n",
        encoding="utf-8",
    )

    result = PythonAnalyzer().analyze_strategy("taint_analysis", [str(source)])

    assert result.status == "completed"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "TAINT_WEAK_CRYPTOGRAPHY"
    assert finding.kind == "signal"
    assert finding.location.start_line == 5


def test_taint_strategy_only_reports_subprocess_injection_when_shell_is_true(
    tmp_path,
):
    source = tmp_path / "subprocess_calls.py"
    source.write_text(
        "import subprocess\n"
        "command = input()\n"
        "subprocess.run(command)\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    result = PythonAnalyzer().analyze_strategy("taint_analysis", [str(source)])

    assert result.status == "completed"
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "TAINT_COMMAND_INJECTION_SUBPROCESS"
    assert result.findings[0].location.start_line == 4


def test_location_contract_supports_optional_evidence_points():
    from src.results import AnalysisPoint, Location

    point = AnalysisPoint(
        location=Location(file=Path("module.py").as_posix(), start_line=4),
        label="SQL execute",
    )

    assert point.location.start_line == 4
    assert point.label == "SQL execute"
