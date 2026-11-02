import ast
import json
from pathlib import Path

from src.analyzers.python import FunctionCallVisitor, PYTHON_SECURITY_RULES


PROJECT_ROOT = Path(__file__).resolve().parents[4]
SAMPLE_FILE = Path(__file__).resolve().parent / "sample.py"


def test_detected_security_rules_exist_in_catalog():
    source = SAMPLE_FILE.read_text(encoding="utf-8")
    visitor = FunctionCallVisitor(str(SAMPLE_FILE))
    visitor.visit(ast.parse(source))

    with (PROJECT_ROOT / "src" / "rules" / "python_security.json").open(
        encoding="utf-8"
    ) as rules_file:
        rules = json.load(rules_file)

    assert visitor.findings
    assert all(finding["rule_key"] in rules for finding in visitor.findings)
    assert set(PYTHON_SECURITY_RULES) == set(rules)


def test_exec_call_uses_catalogued_rule():
    visitor = FunctionCallVisitor("sample.py")
    visitor.visit(ast.parse("exec('pass')"))

    assert visitor.findings == [
        {"file": "sample.py", "line": 1, "rule_key": "UNSAFE_EXEC"}
    ]
