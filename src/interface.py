import argparse

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from src.strategies import STRATEGIES

STRATEGY_IDS = tuple(STRATEGIES)


def build_parser():
    """Build the command-line parser and its supported options."""
    parser = argparse.ArgumentParser(
        description=(
            "SASToy - stratégies d'analyse Python et outil de vérification "
            "d'intégrité."
        ),
        epilog=(
            "Exemples :\n"
            "  python src/main.py py fichier.py\n"
            "  python src/main.py file chemin\\vers\\fichier --algorithm md5 "
            "--official-hash <haché>\n"
            "  python src/main.py file chemin\\vers\\fichier --algorithm sha1 "
            "--web-search"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "type",
        choices=["py", "file"],
        help=(
            "py (stratégies d'analyse Python), "
            "file (vérification d'intégrité d'un fichier)"
        ),
    )
    parser.add_argument(
        "target",
        type=str,
        help="Chemin du fichier ou du dossier à analyser",
    )
    parser.add_argument(
        "--mode",
        choices=["manuel", "exhaustif"],
        help="Mode d'analyse (par défaut : choix interactif)",
    )
    parser.add_argument(
        "--strategies",
        nargs="+",
        choices=STRATEGY_IDS,
        help=(
            "Stratégies à inclure dans le rapport exhaustif "
            "(par défaut : les quatre stratégies)"
        ),
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Analyser les sous-dossiers de manière récursive",
    )
    parser.add_argument(
        "--algorithm",
        choices=["md5", "sha1", "sha256"],
        default="sha256",
        help="Algorithme de hachage à utiliser (défaut : sha256)",
    )

    hash_source = parser.add_mutually_exclusive_group()
    hash_source.add_argument(
        "--official-hash",
        help="Haché de référence fourni par l'utilisateur",
    )
    hash_source.add_argument(
        "--web-search",
        action="store_true",
        help="Rechercher le haché officiel sur le web (nécessite GEMINI_API_KEY)",
    )

    return parser


def show_python_files(console, files):
    """Display the Python files selected for analysis."""
    console.print(
        Panel(
            f"[bold cyan]{len(files)} fichier(s) Python identifié(s)[/]\n"
            + "\n".join(files),
            title="SASToy",
            border_style="cyan",
        )
    )


def ask_for_manual_strategies():
    """Prompt for strategy identifiers in manual mode."""
    return Prompt.ask(
        "[bold cyan]Stratégies à sélectionner[/] "
        f"({', '.join(STRATEGY_IDS)} ; séparées par des virgules)"
    ).split(",")


def ask_for_mode():
    """Prompt for the analysis mode."""
    return Prompt.ask(
        "[bold cyan]Mode d'analyse[/]",
        choices=["manuel", "exhaustif"],
        default="manuel",
    )


def ask_for_exhaustive_strategies():
    """Prompt for strategies to list in the exhaustive-mode report."""
    default = ",".join(STRATEGY_IDS)
    selected = Prompt.ask(
        "[bold cyan]Stratégies (séparées par des virgules)[/]",
        default=default,
    )
    strategies = [
        strategy.strip()
        for strategy in selected.split(",")
        if strategy.strip()
    ]
    invalid = sorted(set(strategies) - set(STRATEGY_IDS))
    if invalid:
        raise ValueError(
            "Stratégie(s) inconnue(s) : "
            + ", ".join(invalid)
        )
    return list(dict.fromkeys(strategies))
