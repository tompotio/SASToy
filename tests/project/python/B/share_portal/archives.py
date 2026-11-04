"""Exemple d'extraction d'archive téléversée dans le portail fictif."""

import tarfile


def extract_shared_archive(archive_file, destination):
    """Extrait les membres sans filtrer les chemins contenus dans l'archive."""
    with tarfile.open(fileobj=archive_file, mode="r:*") as archive:
        archive.extractall(path=destination)
