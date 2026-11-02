import os
import sys
import time
from pathlib import Path

from google import genai
from rich.console import Console

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analyzers.python import PythonAnalyzer
from src.exhaustive import run_strategies
from src.integrity import run_hash_verification
from src.interface import (
    ask_for_ai_consent,
    ask_for_mode,
    ask_for_operations,
    ask_for_strategies,
    build_parser,
    show_python_files,
)
from src.report import anonymized_ai_summary, generate_report


def _request_ai_recommendations(results):
    """Request contextual guidance using only anonymized, fictitious counts."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None, "Non réalisée : GEMINI_API_KEY est absente."

    try:
        client = genai.Client(api_key=api_key)
        response = client.interactions.create(
            model="gemini-3.8-flash",
            input=(
                "Tu aides à contextualiser un prototype pédagogique de SAST. "
                "Les données ci-dessous sont fictives et ne décrivent aucune "
                "cible réelle. Propose des recommandations générales, sans "
                "inventer de constats. Ne demande et n'infère aucun code source, "
                "chemin, secret, emplacement ou détail individuel. "
                "Conserve leur provenance par stratégie.\n"
                f"Résumé anonymisé : {anonymized_ai_summary(results)}"
            ),
        )
        recommendations = response.output_text.strip()
        if not recommendations:
            return None, "Non réalisée : la réponse IA était vide."
        return recommendations, "Réalisée sur un résumé anonymisé."
    except Exception as exc:
        return None, (
            "Non réalisée : échec du service IA "
            f"({type(exc).__name__}) ; les résultats locaux sont conservés."
        )


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
    if not analyzer.is_python_check(args.target, recursive=args.recursive):
        print("[!] Le fichier ou le dossier spécifié ne contient pas de fichiers Python.")
        return 1

    show_python_files(console, files_to_scan)
    if mode == "exhaustif":
        started_at = time.perf_counter()
        use_ai = ask_for_ai_consent()
        try:
            selected_strategies = (
                args.strategies
                if args.strategies is not None
                else ask_for_strategies()
            )
        except ValueError as exc:
            console.print(f"[bold red]{exc}[/]")
            return 2
        results = run_strategies(selected_strategies, files_to_scan)
        ai_recommendations = None
        if use_ai:
            ai_recommendations, ai_status = _request_ai_recommendations(results)
            if ai_recommendations is None:
                console.print(f"[yellow]Analyse IA : {ai_status}[/]")
        else:
            ai_status = "Non réalisée : utilisation non autorisée ou token absent."

        duration_seconds = time.perf_counter() - started_at
        try:
            report_path = generate_report(
                target=args.target,
                files=files_to_scan,
                results=results,
                duration_seconds=duration_seconds,
                ai_status=ai_status,
                ai_recommendations=ai_recommendations,
            )
        except OSError as exc:
            console.print(
                f"[bold red]Impossible d'écrire le rapport HTML : {exc}[/]"
            )
            return 1

        console.print(
            "[bold green]Rapport de démonstration généré :[/] "
            f"{report_path}"
        )
        console.print(
            "[yellow]Les sorties sont fictives ; aucune stratégie n'a analysé "
            "la cible.[/]"
        )
        return 0

    for operation in ask_for_operations():
        analyzer.analyze_operation(
            operation.strip().lower(),
            files_to_scan,
            console,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
