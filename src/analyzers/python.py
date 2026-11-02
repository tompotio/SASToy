import ast
import json
from pathlib import Path

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings
from rich.console import Console

from src.analyzers.base import VulnerabilityAnalyzer
from src.utils import get_files_by_extension


rules_path = Path(__file__).resolve().parents[1] / "rules" / "python_security.json"
with open(rules_path, "r", encoding="utf-8") as rules_file:
    PYTHON_SECURITY_RULES = json.load(rules_file)


class FunctionCallVisitor(ast.NodeVisitor):
    """Find syntax-level calls that warrant a closer security review."""

    def __init__(self, filepath):
        """Initialize the visitor for a source file."""
        self.filepath = filepath
        self.findings = []
        self.module_aliases = {}
        self.imported_names = {}

    def visit_Module(self, node):
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

    def visit_Call(self, node):
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

    def _resolve_name(self, node):
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

    def _matches_rule(self, node, call_name, match):
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
    def analyse_signaux_securite(files_to_scan):
        """Display syntax-level security signals in Python files."""
        for file in files_to_scan:
            tree = PythonAnalyzer.parse_python_file(file)
            if tree is None:
                continue

            visitor = FunctionCallVisitor(file)
            visitor.visit(tree)

            if visitor.findings:
                print(f"[!] Signaux indicatifs détectés dans le fichier : {file}")
                for finding in visitor.findings:
                    rule = PYTHON_SECURITY_RULES[finding["rule_key"]]
                    print(
                        f"  - Ligne {finding['line']}: "
                        f"{rule.get('title', finding['rule_key'])} "
                        f"({finding['rule_key']})"
                    )
                    print(f"    {rule['description']}")
                print(
                    "    Ces signaux syntaxiques ne constituent pas une preuve "
                    "de vulnérabilité."
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
            case "security_signals":
                with console.status(
                    "[bold cyan]Analyse des signaux de sécurité...[/]",
                    spinner="dots",
                ):
                    self.analyse_signaux_securite(files)

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
