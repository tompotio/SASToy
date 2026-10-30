import argparse

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt


def build_parser():
    """Build the command-line parser and its supported options."""
    parser = argparse.ArgumentParser(
        description=(
            "SASToy - analyseur statique Python et outil de vérification "
            "d'intégrité par haché."
        ),
        epilog=(
            "Exemples :\n"
            "  python src/scanner.py py fichier.py\n"
            "  python src/scanner.py hash fichier.exe --algorithm md5 "
            "--official-hash <haché>\n"
            "  python src/scanner.py exe fichier.exe --algorithm sha1 --web-search"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "type",
        type=str,
        choices=["py", "exe", "hash"],
        help=(
            "py (analyse AST), exe (haché d'un exécutable), "
            "hash (haché d'un fichier)"
        ),
    )
    parser.add_argument(
        "target",
        type=str,
        help="Chemin du fichier ou du dossier à analyser",
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


def ask_for_operations():
    """Prompt for and return the analysis operations selected by the user."""
    return Prompt.ask(
        "[bold cyan]Opérations à effectuer[/] "
        "(function_calls, cfi, hcs, sqli ; séparées par des virgules)"
    ).split(",")
