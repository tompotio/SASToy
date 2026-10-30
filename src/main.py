import os
import sys
from pathlib import Path

from rich.console import Console

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analyzers.python import PythonAnalyzer
from src.integrity import run_hash_verification
from src.interface import ask_for_operations, build_parser, show_python_files


def main(argv=None):
    """Run the selected SASToy command and return its process exit code."""
    console = Console()
    args = build_parser().parse_args(argv)

    if args.type in {"hash", "exe"}:
        if not os.path.isfile(args.target):
            console.print(f"[bold red]Fichier introuvable : {args.target}[/]")
            return 1

        try:
            is_valid = run_hash_verification(args, console)
        except (OSError, RuntimeError, ValueError) as exc:
            console.print(f"[bold red]Échec de la vérification : {exc}[/]")
            return 1

        return 0 if is_valid else 1

    analyzer = PythonAnalyzer()
    files_to_scan = analyzer.get_files(args.target, recursive=args.recursive)
    if not analyzer.is_python_check(args.target, recursive=args.recursive):
        print("[!] Le fichier ou le dossier spécifié ne contient pas de fichiers Python.")
        return 1

    show_python_files(console, files_to_scan)
    for operation in ask_for_operations():
        analyzer.analyze_operation(
            operation.strip().lower(),
            files_to_scan,
            console,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
