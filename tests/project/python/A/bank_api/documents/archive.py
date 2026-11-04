"""Import pédagogique d'archives de relevés."""

import tarfile
from pathlib import Path


def import_statement_archive(archive_path: str, destination: str) -> None:
    """Extrait une archive sans contrôler les chemins qu'elle contient."""
    with tarfile.open(archive_path) as archive:
        archive.extractall(path=Path(destination))
