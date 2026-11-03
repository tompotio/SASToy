"""Python source discovery and security-analysis strategies."""

import ast
import json
from pathlib import Path
from typing import Any

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings
from rich.console import Console

from src.analyzers.base import VulnerabilityAnalyzer
from src.results import (
    AnalysisDiagnostic,
    Finding,
    FindingOrigin,
    Location,
    PatternEvidence,
    SecretEvidence,
    StrategyResult,
)
from src.strategies import STRATEGIES
from src.utils import get_files_by_extension


_RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "python_security.json"
with _RULES_PATH.open(encoding="utf-8") as _rules_file:
    PYTHON_SECURITY_RULES = json.load(_rules_file)


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


class PythonAnalyzer(VulnerabilityAnalyzer):
    """Python source discovery and strategy entry points."""

    @staticmethod
    def get_files(target_path, recursive=False):
        """Return Python source files from a path."""
        return get_files_by_extension(target_path, ".py", recursive)

    @staticmethod
    def _parse_python_file(
        file: str,
    ) -> tuple[ast.Module | None, AnalysisDiagnostic | None]:
        try:
            with open(file, "r", encoding="utf-8") as source_file:
                return ast.parse(source_file.read()), None
        except (OSError, UnicodeError, SyntaxError) as exc:
            return None, AnalysisDiagnostic(
                code="python_parse_error",
                message=f"{type(exc).__name__}: {exc}",
                file=file,
                line=getattr(exc, "lineno", None),
            )

    @staticmethod
    def parse_python_file(file):
        """Parse a Python file and return its AST, or None on parse failure."""
        tree, diagnostic = PythonAnalyzer._parse_python_file(file)
        if diagnostic:
            print(
                f"[!] Erreur lors de l'analyse du fichier {file}: "
                f"{diagnostic.message}"
            )
        return tree

    @staticmethod
    def detect_hardcoded_secrets(file_to_scan):
        """Return secret detector metadata without exposing secret values."""
        path = Path(file_to_scan)
        if not path.is_file() or path.suffix != ".py":
            raise ValueError(
                f"Le fichier spécifié n'est pas un fichier Python valide : "
                f"{file_to_scan}"
            )

        collection = SecretsCollection()
        with default_settings():
            collection.scan_file(str(path))

        findings = []
        for filename, detections in collection.json().items():
            for detection in detections:
                findings.append(
                    {
                        "file": filename,
                        "line": detection.get("line_number"),
                        "detector": detection.get("type", "unknown"),
                        "verified": bool(detection.get("is_verified", False)),
                    }
                )

        return findings

    def analyze_strategy(self, strategy: str, files: list[str]) -> StrategyResult:
        """Run one strategy and return its normalized result contract."""
        if strategy == "ast_pattern_scan":
            return self._analyze_ast_patterns(files)
        if strategy == "secret_scan":
            return self._analyze_secrets(files)
        if strategy in {"cfg_analysis", "symbolic_execution"}:
            return StrategyResult(
                strategy=strategy,
                status="unavailable",
                diagnostics=[
                    AnalysisDiagnostic(
                        code="strategy_not_implemented",
                        message=(
                            f"La stratégie {strategy} est définie mais son "
                            "analyse n'est pas encore implémentée."
                        ),
                    )
                ],
            )
        raise ValueError(f"Stratégie inconnue : {strategy}")

    @staticmethod
    def _analyze_ast_patterns(files: list[str]) -> StrategyResult:
        findings = []
        diagnostics = []
        successful_files = 0

        for file in files:
            tree, diagnostic = PythonAnalyzer._parse_python_file(file)
            if diagnostic:
                diagnostics.append(diagnostic)
                continue

            successful_files += 1
            visitor = FunctionCallVisitor(file)
            visitor.visit(tree)

            for match in visitor.findings:
                rule_id = match["rule_key"]
                rule = PYTHON_SECURITY_RULES[rule_id]
                finding = Finding(
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
                findings.append(finding)

        return StrategyResult(
            strategy="ast_pattern_scan",
            status=PythonAnalyzer._result_status(
                files, successful_files, diagnostics
            ),
            findings=findings,
            diagnostics=diagnostics,
        )

    @staticmethod
    def _analyze_secrets(files: list[str]) -> StrategyResult:
        findings = []
        diagnostics = []
        successful_files = 0

        for file in files:
            try:
                detected = PythonAnalyzer.detect_hardcoded_secrets(file)
            except (OSError, UnicodeError, ValueError) as exc:
                diagnostics.append(
                    AnalysisDiagnostic(
                        code="secret_scan_error",
                        message=f"{type(exc).__name__}: {exc}",
                        file=file,
                    )
                )
                continue

            successful_files += 1
            for detection in detected:
                line = detection["line"]
                findings.append(
                    Finding(
                        rule_id="HARDCODED_SECRET",
                        kind="secret",
                        category="hardcoded_secret",
                        severity="unknown",
                        confidence=None,
                        message="Valeur ressemblant à un secret détectée.",
                        location=Location(
                            file=detection["file"],
                            start_line=line,
                            end_line=line,
                        ),
                        evidence=SecretEvidence(
                            detector=detection["detector"],
                            verified=detection["verified"],
                        ),
                        origin=FindingOrigin(strategy="secret_scan"),
                    )
                )

        return StrategyResult(
            strategy="secret_scan",
            status=PythonAnalyzer._result_status(
                files, successful_files, diagnostics
            ),
            findings=findings,
            diagnostics=diagnostics,
        )

    @staticmethod
    def _result_status(files, successful_files, diagnostics):
        if not diagnostics:
            return "completed"
        if successful_files == 0 and files:
            return "failed"
        return "partial"

    @staticmethod
    def display_strategy_result(result: StrategyResult, console: Console) -> None:
        """Display findings and diagnostics without exposing secret contents."""
        label = STRATEGIES[result.strategy]
        console.print(f"[bold cyan]{label} — {result.status}[/]")
        for finding in result.findings:
            location = finding.location
            where = (
                f"{location.file}:{location.start_line}"
                if location and location.start_line is not None
                else (location.file if location else "emplacement inconnu")
            )
            console.print(
                f"  - {where}: {finding.message} [{finding.rule_id}]"
            )
        for diagnostic in result.diagnostics:
            where = f"{diagnostic.file}: " if diagnostic.file else ""
            console.print(f"  [yellow]Avertissement : {where}{diagnostic.message}[/]")

    def analyze_operation(self, operation, files, console):
        """Run a strategy and display its normalized result."""
        if operation not in STRATEGIES:
            console.print(f"[bold red]Opération inconnue : {operation}[/]")
            return None

        result = self.analyze_strategy(operation, files)
        self.display_strategy_result(result, console)
        return result
