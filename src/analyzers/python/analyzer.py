"""Python source discovery and security-analysis strategies."""

import ast

from rich.console import Console

from src.analyzers.python import ast_pattern_scan, secret_scan, symbolic_execution
from src.analyzers.base import VulnerabilityAnalyzer
from src.analyzers.python.taint_analysis import analyze as analyze_taint
from src.results import (
    AnalysisDiagnostic,
    StrategyResult,
)
from src.strategies import STRATEGIES
from src.utils import get_files_by_extension


class PythonAnalyzer(VulnerabilityAnalyzer):
    """Python source discovery and strategy entry points."""

    @staticmethod
    def get_files(target_path: str, recursive: bool = False) -> list[str]:
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
    def detect_hardcoded_secrets(file_to_scan: str) -> list[dict[str, object]]:
        """Return secret detector metadata without exposing secret values."""
        return secret_scan.detect_hardcoded_secrets(file_to_scan)

    def analyze_strategy(self, strategy: str, files: list[str]) -> StrategyResult:
        """Run one strategy and return its normalized result contract."""
        if strategy == "ast_pattern_scan":
            return ast_pattern_scan.analyze(
                files,
                self._parse_python_file,
                self._result_status,
            )
        if strategy == "secret_scan":
            return secret_scan.analyze(files, self._result_status)
        if strategy == "taint_analysis":
            return analyze_taint(
                files,
                self._parse_python_file,
                self._result_status,
            )
        if strategy == "symbolic_execution":
            return symbolic_execution.analyze(files)
        raise ValueError(f"Stratégie inconnue : {strategy}")

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

    def analyze_operation(
        self,
        operation: str,
        files: list[str],
        console: Console,
    ) -> StrategyResult | None:
        """Run a strategy and display its normalized result."""
        if operation not in STRATEGIES:
            console.print(f"[bold red]Opération inconnue : {operation}[/]")
            return None

        result = self.analyze_strategy(operation, files)
        self.display_strategy_result(result, console)
        return result
