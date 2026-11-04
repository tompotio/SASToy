"""Lecture d'extraits de compte pour illustrer le contrôle des chemins."""

from pathlib import Path

from bank_api.config import STATEMENTS_DIRECTORY


def load_statement(file_name: str) -> str:
    """Lit un document sans vérifier qu'il reste dans le dossier prévu."""
    document_path = Path(STATEMENTS_DIRECTORY) / file_name
    with document_path.open(encoding="utf-8") as document:
        return document.read()


def load_requested_statement() -> str:
    file_name = input("Identifiant du document à consulter : ")
    return load_statement(file_name)
