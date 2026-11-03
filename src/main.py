import os
import sys
from pathlib import Path

from rich.console import Console

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.aggregation import aggregate_results
from src.analyzers.python import PythonAnalyzer
from src.integrity import run_hash_verification
from src.interface import (
    ask_for_mode,
    ask_for_exhaustive_strategies,
    ask_for_manual_strategies,
    build_parser,
    show_python_files,
)
from src.report import generate_report
from src.results import AnalysisDiagnostic, StrategyResult


def main(argv=None):
    """Run the selected SASToy command and return its process exit code."""
    console = Console()
    args = build_parser().parse_args(argv)

    if args.type == "file":
        if not os.path.isfile(args.target):
            console.print(f"[bold red]Fichier introuvable : {args.target}[/]")
            return 1

        try:
            is_valid = run_hash_verification(args, console)
        except (OSError, RuntimeError, ValueError) as exc:
            console.print(f"[bold red]Échec de la vérification : {exc}[/]")
            return 1

        return 0 if is_valid else 1

    mode = args.mode or ask_for_mode()
    if mode == "manuel" and args.strategies is not None:
        console.print(
            "[bold red]L'option --strategies est réservée au mode exhaustif.[/]"
        )
        return 2

    analyzer = PythonAnalyzer()
    files_to_scan = analyzer.get_files(args.target, recursive=args.recursive)
    if not files_to_scan:
        print("[!] Le fichier ou le dossier spécifié ne contient pas de fichiers Python.")
        return 1

    show_python_files(console, files_to_scan)
    if mode == "exhaustif":
        try:
            selected_strategies = (
                args.strategies
                if args.strategies is not None
                else ask_for_exhaustive_strategies()
            )
        except ValueError as exc:
            console.print(f"[bold red]{exc}[/]")
            return 2

        strategy_results = []
        for strategy in selected_strategies:
            try:
                strategy_result = analyzer.analyze_strategy(
                    strategy,
                    files_to_scan,
                )
            except Exception as exc:
                strategy_result = StrategyResult(
                    strategy=strategy,
                    status="failed",
                    diagnostics=[
                        AnalysisDiagnostic(
                            code="strategy_execution_error",
                            message=f"{type(exc).__name__}: {exc}",
                        )
                    ],
                )
            strategy_results.append(strategy_result)

        aggregate = aggregate_results(strategy_results)
        try:
            report_path = generate_report(
                target=args.target,
                files=files_to_scan,
                aggregate=aggregate,
            )
        except OSError as exc:
            console.print(
                f"[bold red]Impossible d'écrire le rapport HTML : {exc}[/]"
            )
            return 1

        console.print(
            "[bold green]Rapport exhaustif généré :[/] "
            f"{report_path}"
        )
        console.print(
            "[cyan]Analyse exhaustive :[/] "
            f"{len(aggregate.results)} stratégie(s), "
            f"{len(aggregate.findings)} constat(s), statut {aggregate.status}."
        )
        return 0

    selected_strategies = dict.fromkeys(
        strategy.strip().lower()
        for strategy in ask_for_manual_strategies()
        if strategy.strip()
    )
    for strategy in selected_strategies:
        analyzer.analyze_operation(
            strategy,
            files_to_scan,
            console,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
