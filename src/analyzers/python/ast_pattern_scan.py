"""Syntax-pattern security strategy for Python source."""

import ast
import json
from pathlib import Path
from typing import Any, Callable

from src.results import (
    AnalysisDiagnostic,
    Finding,
    FindingOrigin,
    Location,
    PatternEvidence,
    StrategyResult,
)


_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "rules" / "python_security.json"
)
with _RULES_PATH.open(encoding="utf-8") as _rules_file:
    PYTHON_SECURITY_RULES: dict[str, Any] = json.load(_rules_file)

Parser = Callable[
    [str],
    tuple[ast.Module | None, AnalysisDiagnostic | None],
]
StatusResolver = Callable[
    [list[str], int, list[AnalysisDiagnostic]],
    str,
]


class FunctionCallVisitor(ast.NodeVisitor):
    """Find syntax-level calls that warrant a closer security review."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.findings: list[dict[str, Any]] = []
        self.module_aliases: dict[str, str] = {}
        self.imported_names: dict[str, str] = {}

    def visit_Module(self, node: ast.Module) -> None:
        """Resolve straightforward import aliases before inspecting calls."""
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    local_name = alias.asname or alias.name.split(".")[0]
                    self.module_aliases[local_name] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(child, ast.ImportFrom) and child.module:
                for alias in child.names:
                    local_name = alias.asname or alias.name
                    self.imported_names[local_name] = (
                        f"{child.module}.{alias.name}"
                    )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Collect calls matching the syntax described by the rule catalog."""
        call_name = self._resolve_name(node.func)
        for rule_key, rule in PYTHON_SECURITY_RULES.items():
            match = rule.get("match")
            if match and self._matches_rule(node, call_name, match):
                self.findings.append(
                    {
                        "file": self.filepath,
                        "line": node.lineno,
                        "rule_key": rule_key,
                    }
                )

        self.generic_visit(node)

    def _resolve_name(self, node: ast.expr) -> str:
        """Return a dotted name, applying aliases from straightforward imports."""
        if isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Attribute):
            parent_name = self._resolve_name(node.value)
            return f"{parent_name}.{node.attr}" if parent_name else node.attr
        else:
            return ""

        if name in self.imported_names:
            return self.imported_names[name]
        if name in self.module_aliases:
            return self.module_aliases[name]
        return name

    def _matches_rule(
        self,
        node: ast.Call,
        call_name: str,
        match: dict[str, Any],
    ) -> bool:
        calls = match.get("calls", [])
        suffixes = match.get("attribute_suffixes", [])
        matches_name = call_name in calls or (
            isinstance(node.func, ast.Attribute) and node.func.attr in suffixes
        )
        if not matches_name:
            return False

        for keyword_name, expected_value in match.get(
            "keyword_equals", {}
        ).items():
            keyword = next(
                (arg for arg in node.keywords if arg.arg == keyword_name),
                None,
            )
            if (
                keyword is None
                or not isinstance(keyword.value, ast.Constant)
                or keyword.value.value != expected_value
            ):
                return False

        for keyword_name, safe_names in match.get(
            "skip_if_keyword_names", {}
        ).items():
            keyword = next(
                (arg for arg in node.keywords if arg.arg == keyword_name),
                None,
            )
            if keyword and self._resolve_name(keyword.value) in safe_names:
                return False

        return True


def analyze(
    files: list[str],
    parse_python_file: Parser,
    result_status: StatusResolver,
) -> StrategyResult:
    """Run the syntax-pattern strategy and normalize its findings."""
    findings = []
    diagnostics = []
    successful_files = 0

    for file in files:
        tree, diagnostic = parse_python_file(file)
        if diagnostic:
            diagnostics.append(diagnostic)
            continue

        successful_files += 1
        visitor = FunctionCallVisitor(file)
        visitor.visit(tree)

        for match in visitor.findings:
            rule_id = match["rule_key"]
            rule = PYTHON_SECURITY_RULES[rule_id]
            findings.append(
                Finding(
                    rule_id=rule_id,
                    kind="signal",
                    category="security_signal",
                    severity=rule.get("severity", "unknown").lower(),
                    confidence=None,
                    message=rule.get("title", rule_id),
                    location=Location(
                        file=file,
                        start_line=match["line"],
                        end_line=match["line"],
                    ),
                    evidence=PatternEvidence(
                        description=rule["description"],
                        cwe_id=rule.get("cwe_id"),
                        cwe_name=rule.get("cwe_name"),
                    ),
                    origin=FindingOrigin(strategy="ast_pattern_scan"),
                )
            )

    return StrategyResult(
        strategy="ast_pattern_scan",
        status=result_status(files, successful_files, diagnostics),
        findings=findings,
        diagnostics=diagnostics,
    )
