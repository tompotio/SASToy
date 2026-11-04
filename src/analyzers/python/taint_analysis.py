"""AST-based taint analysis strategy."""

import ast
import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from src.results import (
    AnalysisDiagnostic,
    AnalysisPoint,
    DataFlowEvidence,
    Finding,
    FindingOrigin,
    Location,
    PatternEvidence,
    StrategyResult,
)

_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "python_taint.json"
with _RULES_PATH.open(encoding="utf-8") as _rules_file:
    _RULES: dict[str, Any] = json.load(_rules_file)


@dataclass(frozen=True, slots=True)
class TaintFinding:
    """Unnormalized alert emitted by the AST visitor."""

    file: str
    line: int
    rule_key: str
    message: str
    source_line: int | None = None


class PathSensitiveTaintVisitor(ast.NodeVisitor):
    """Track tainted values and report configured sensitive calls."""

    _SOURCE_ONLY_SINKS = {
        "Weak Cryptography",
        "WEAK_SSL_CONTEXT",
        "Race Condition",
        "WEAK_PRNG",
        "INSECURE_TRANSPORT",
    }

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.findings: set[TaintFinding] = set()
        self.import_map: dict[str, str] = {}
        self.tainted_variables: set[str] = set()
        self.taint_source_lines: dict[str, int | None] = {}
        self.tainted_arguments_by_func: dict[str, dict[int, int | None]] = {}
        self.function_params_map: dict[str, list[str]] = {}
        self.sources: set[str] = set(_RULES["sources"])
        self.sanitizers: set[str] = set(_RULES["sanitizers"])
        self.sinks: dict[str, str] = _RULES["sinks"]

    def prepare(self, tree: ast.Module) -> None:
        """Resolve imports and local function signatures before visiting calls."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.import_map[alias.asname or alias.name.split(".")[0]] = (
                        alias.name
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.import_map[alias.asname or alias.name] = (
                        f"{node.module}.{alias.name}"
                    )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.function_params_map[node.name] = [
                    arg.arg for arg in node.args.args
                ]

    @staticmethod
    def _resolve_attribute_chain(node: ast.AST) -> str | None:
        """Return the dotted name represented by a name or attribute expression."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = PathSensitiveTaintVisitor._resolve_attribute_chain(node.value)
            if base:
                return f"{base}.{node.attr}"
        if isinstance(node, ast.Subscript):
            return PathSensitiveTaintVisitor._resolve_attribute_chain(node.value)
        return None

    def _resolve_full_name(self, node: ast.AST) -> str | None:
        """Resolve an imported alias to its fully-qualified name."""
        name = self._resolve_attribute_chain(node)
        if not name:
            return None
        head, separator, tail = name.partition(".")
        resolved_head = self.import_map.get(head, head)
        return f"{resolved_head}.{tail}" if separator else resolved_head

    def _is_source_expression(self, node: ast.AST) -> bool:
        name = self._resolve_full_name(node.func if isinstance(node, ast.Call) else node)
        if not name:
            return False
        if isinstance(node, ast.Call):
            parts = name.split(".")
            return any(
                source in name if "." in source else source in parts
                for source in self.sources
            )
        return (
            any(source in name for source in self.sources)
            or "sys.argv" in name
        )

    def _source_line(self, node: ast.AST | None) -> int | None:
        if node is None:
            return None
        if self._is_source_expression(node):
            return getattr(node, "lineno", None)
        if isinstance(node, ast.Name):
            return self.taint_source_lines.get(node.id)
        for child in ast.iter_child_nodes(node):
            line = self._source_line(child)
            if line is not None:
                return line
        return None

    def _check_expression_taint(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if self._is_source_expression(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.tainted_variables
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and self._check_expression_taint(
                node.func.value
            ):
                return True
            return any(self._check_expression_taint(arg) for arg in node.args) or any(
                self._check_expression_taint(keyword.value)
                for keyword in node.keywords
            )
        return any(
            self._check_expression_taint(child)
            for child in ast.iter_child_nodes(node)
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_body(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_body(node)

    def _visit_function_body(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        previous_tainted = copy.deepcopy(self.tainted_variables)
        previous_sources = copy.deepcopy(self.taint_source_lines)
        for index, parameter in enumerate(self.function_params_map[node.name]):
            source_line = self.tainted_arguments_by_func.get(node.name, {}).get(
                index
            )
            if index in self.tainted_arguments_by_func.get(node.name, {}):
                self.tainted_variables.add(parameter)
                self.taint_source_lines[parameter] = source_line
        for statement in node.body:
            self.visit(statement)
        self.tainted_variables = previous_tainted
        self.taint_source_lines = previous_sources

    def visit_If(self, node: ast.If) -> None:
        condition = ast.unparse(node.test)
        if "hostname" in condition or "domain" in condition:
            for variable in tuple(self.tainted_variables):
                if any(
                    keyword in variable
                    for keyword in ("url", "input", "data", "path")
                ):
                    self.tainted_variables.remove(variable)
                    self.taint_source_lines.pop(variable, None)

        initial_tainted = copy.deepcopy(self.tainted_variables)
        initial_sources = copy.deepcopy(self.taint_source_lines)

        self.tainted_variables = copy.deepcopy(initial_tainted)
        self.taint_source_lines = copy.deepcopy(initial_sources)
        for statement in node.body:
            self.visit(statement)
        if_tainted = copy.deepcopy(self.tainted_variables)
        if_sources = copy.deepcopy(self.taint_source_lines)

        self.tainted_variables = copy.deepcopy(initial_tainted)
        self.taint_source_lines = copy.deepcopy(initial_sources)
        for statement in node.orelse:
            self.visit(statement)
        else_tainted = copy.deepcopy(self.tainted_variables)
        else_sources = copy.deepcopy(self.taint_source_lines)

        self.tainted_variables = initial_tainted | if_tainted | else_tainted
        self.taint_source_lines = initial_sources | if_sources | else_sources

    def visit_Assign(self, node: ast.Assign) -> None:
        is_tainted = self._check_expression_taint(node.value)
        source_line = self._source_line(node.value)
        if isinstance(node.value, ast.Call):
            function_name = self._resolve_full_name(node.value.func) or ""
            if function_name.rsplit(".", 1)[-1] in self.sanitizers:
                is_tainted = False
                source_line = None

        for target in node.targets:
            if isinstance(target, ast.Name):
                if is_tainted:
                    self.tainted_variables.add(target.id)
                    self.taint_source_lines[target.id] = source_line
                else:
                    self.tainted_variables.discard(target.id)
                    self.taint_source_lines.pop(target.id, None)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name) and self._check_expression_taint(
                item.context_expr
            ):
                variable = item.optional_vars.id
                self.tainted_variables.add(variable)
                self.taint_source_lines[variable] = self._source_line(
                    item.context_expr
                )
        self.generic_visit(node)

    def _resolve_sink(self, name: str) -> str | None:
        if name in self.sinks:
            return self.sinks[name]
        for sink_name, category in self.sinks.items():
            if name.endswith(sink_name) or sink_name.endswith(name):
                if "urlparse" in name:
                    continue
                if name.endswith(".get") and "requests" not in name:
                    continue
                if name in {"new", "text", "open", "bytes"} and name != sink_name:
                    continue
                return category
        return None

    def visit_Call(self, node: ast.Call) -> None:
        function_name = (
            node.func.attr
            if isinstance(node.func, ast.Attribute)
            else node.func.id
            if isinstance(node.func, ast.Name)
            else None
        )
        if function_name in self.function_params_map:
            for index, argument in enumerate(node.args):
                if self._check_expression_taint(argument):
                    source_line = self._source_line(argument)
                    self.tainted_arguments_by_func.setdefault(
                        function_name, {}
                    ).setdefault(index, source_line)

        resolved_name = self._resolve_full_name(node.func) or function_name or ""
        rule_key = (
            None
            if function_name in self.function_params_map
            else self._resolve_sink(resolved_name)
        )
        if rule_key == "COMMAND_INJECTION_SUBPROCESS":
            shell_enabled = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if not shell_enabled:
                rule_key = None

        if rule_key == "Weak Cryptography" and resolved_name == "hmac.new":
            uses_sha256 = any(
                "sha256" in (self._resolve_full_name(argument) or "").lower()
                for argument in node.args
            ) or any(
                keyword.arg == "digestmod"
                and "sha256"
                in (self._resolve_full_name(keyword.value) or "").lower()
                for keyword in node.keywords
            )
            if uses_sha256:
                rule_key = None

        if rule_key:
            tainted_argument = next(
                (
                    argument
                    for argument in [*node.args, *(kw.value for kw in node.keywords)]
                    if self._check_expression_taint(argument)
                ),
                None,
            )
            if rule_key in self._SOURCE_ONLY_SINKS:
                message = f"Utilisation dangereuse de '{resolved_name}'"
                source_line = None
            elif tainted_argument is not None or (
                isinstance(node.func, ast.Attribute)
                and self._check_expression_taint(node.func.value)
            ):
                message = (
                    f"Faille détectée via '{resolved_name}'. "
                    "L'argument dépend d'une entrée utilisateur non nettoyée."
                )
                source_line = self._source_line(tainted_argument)
                if source_line is None and isinstance(node.func, ast.Attribute):
                    source_line = self._source_line(node.func.value)
            else:
                message = ""
                source_line = None

            if message:
                self.findings.add(
                    TaintFinding(
                        file=self.filepath,
                        line=node.lineno,
                        rule_key=rule_key,
                        message=message,
                        source_line=source_line,
                    )
                )

        self.generic_visit(node)


Parser = Callable[
    [str],
    tuple[ast.Module | None, AnalysisDiagnostic | None],
]
StatusResolver = Callable[
    [list[str], int, list[AnalysisDiagnostic]],
    str,
]


def analyze(
    files: list[str],
    parse_python_file: Parser,
    result_status: StatusResolver,
) -> StrategyResult:
    """Run taint analysis and normalize its findings."""
    findings = []
    diagnostics = []
    successful_files = 0

    for file in files:
        tree, diagnostic = parse_python_file(file)
        if diagnostic:
            diagnostics.append(diagnostic)
            continue

        successful_files += 1
        visitor = PathSensitiveTaintVisitor(file)
        visitor.prepare(tree)
        visitor.visit(tree)
        visitor.visit(tree)

        for match in sorted(visitor.findings, key=lambda finding: finding.line):
            is_taint_flow = match.message.startswith("Faille détectée via")
            location = Location(
                file=match.file,
                start_line=match.line,
                end_line=match.line,
            )
            if is_taint_flow:
                evidence = DataFlowEvidence(
                    source=AnalysisPoint(
                        location=Location(
                            file=match.file,
                            start_line=match.source_line,
                            end_line=match.source_line,
                        ),
                        label="Source d'entrée non fiable",
                    ),
                    sink=AnalysisPoint(
                        location=location,
                        label=match.rule_key,
                    ),
                )
                kind = "taint_flow"
                category = "taint_flow"
            else:
                evidence = PatternEvidence(description=match.message)
                kind = "signal"
                category = "security_signal"

            severity = (
                "medium"
                if match.rule_key
                in {"WEAK_PRNG", "Weak Cryptography", "WEAK_SSL_CONTEXT"}
                else "high"
            )
            rule_id = "TAINT_" + re.sub(
                r"[^A-Za-z0-9]+",
                "_",
                match.rule_key,
            ).strip("_").upper()
            findings.append(
                Finding(
                    rule_id=rule_id,
                    kind=kind,
                    category=category,
                    severity=severity,
                    confidence=None,
                    message=match.message,
                    location=location,
                    evidence=evidence,
                    origin=FindingOrigin(strategy="taint_analysis"),
                )
            )

    return StrategyResult(
        strategy="taint_analysis",
        status=result_status(files, successful_files, diagnostics),
        findings=findings,
        diagnostics=diagnostics,
    )
