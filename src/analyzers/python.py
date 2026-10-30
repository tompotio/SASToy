import ast
import json
from pathlib import Path

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings
from rich.console import Console

from src.analyzers.base import VulnerabilityAnalyzer
from src.utils import get_files_by_extension


rules_path = Path(__file__).resolve().parents[1] / "rules_function_calls.json"
with open(rules_path, "r", encoding="utf-8") as rules_file:
    SECURITY_FUNCTION_CALLS_RULES = json.load(rules_file)


class FunctionCallVisitor(ast.NodeVisitor):
    """Find potentially dangerous function calls in Python source."""

    def __init__(self, filepath):
        """Initialize the visitor for a source file."""
        self.filepath = filepath
        self.findings = []
        self.dangerous_functions = {
            "eval": "UNSAFE_EVAL",
            "exec": "UNSAFE_EXEC",
        }

    def visit_Call(self, node):
        """Collect calls to functions known to be unsafe."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.dangerous_functions:
                self.findings.append(
                    {
                        "file": self.filepath,
                        "line": node.lineno,
                        "rule_key": self.dangerous_functions[func_name],
                    }
                )

        self.generic_visit(node)


class PythonAnalyzer(VulnerabilityAnalyzer):
    """Vulnerability analyses implemented for Python source files."""

    @staticmethod
    def get_files(target_path, recursive=False):
        """Return Python source files from a path."""
        return get_files_by_extension(target_path, ".py", recursive)

    @staticmethod
    def parse_python_file(file):
        """Parse a Python file and return its AST."""
        try:
            with open(file, "r", encoding="utf-8") as source_file:
                return ast.parse(source_file.read())
        except Exception as exc:
            print(f"[!] Erreur lors de l'analyse du fichier {file}: {exc}")
            return None

    @staticmethod
    def is_python_check(target_path, recursive=False):
        """Return whether a path contains Python source files."""
        return bool(PythonAnalyzer.get_files(target_path, recursive))

    @staticmethod
    def analyse_fonctions_vul(files_to_scan):
        """Display potentially dangerous function calls in Python files."""
        for file in files_to_scan:
            tree = PythonAnalyzer.parse_python_file(file)
            if tree is None:
                continue

            visitor = FunctionCallVisitor(file)
            visitor.visit(tree)

            if visitor.findings:
                print(f"[!] Vulnérabilités détectées dans le fichier : {file}")
                for finding in visitor.findings:
                    print(
                        f"  - Ligne {finding['line']}: {finding['rule_key']} "
                        "(Appel de fonction potentiellement dangereux)"
                    )

    @staticmethod
    def detect_hardcoded_secrets(file_to_scan):
        """Detect hardcoded secrets in a Python source file."""
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
                    }
                )

        return findings

    def analyze_operation(self, operation, files, console):
        """Run the selected supported operation on Python source files."""
        match operation:
            case "function_calls":
                with console.status(
                    "[bold cyan]Analyse des appels de fonctions...[/]",
                    spinner="dots",
                ):
                    self.analyse_fonctions_vul(files)

            case "cfi":
                console.print(
                    "[yellow]Analyse CFI (Control Flow Integrity) non implémentée.[/]"
                )

            case "hcs":
                console.print(
                    "[yellow]Analyse HCS (Hardcoded Secrets) en cours...[/]"
                )
                for file in files:
                    secrets = self.detect_hardcoded_secrets(file)
                    if secrets:
                        console.print(
                            f"[bold red]Secrets codés en dur détectés dans "
                            f"{file} :[/]"
                        )
                        for secret in secrets:
                            console.print(f"  - Ligne {secret['line']}")
                    else:
                        console.print(
                            f"[green]Aucun secret codé en dur détecté dans "
                            f"{file}.[/]"
                        )

            case "sqli":
                console.print(
                    "[yellow]Analyse SQLi (SQL Injection) non implémentée.[/]"
                )

            case _:
                console.print(f"[bold red]Opération inconnue : {operation}[/]")
