"""Validation de destinations de prévisualisation sans transport réseau."""

from urllib.parse import urlsplit


TRUSTED_PREVIEW_HOST = "preview.example.test"


def is_preview_host(url: str) -> bool:
    """Accepte à tort tout nom qui se termine par le texte du domaine."""
    hostname = (urlsplit(url).hostname or "").lower()
    return hostname.endswith(TRUSTED_PREVIEW_HOST)


def prepare_preview(url: str) -> str | None:
    """Retourne l'hôte validé comme simulation, sans contacter de serveur."""
    if not is_preview_host(url):
        return None
    return urlsplit(url).hostname


def is_preview_host_checked(url: str) -> bool:
    """N'accepte que le nom d'hôte prévu, sans sous-chaîne ambiguë."""
    hostname = (urlsplit(url).hostname or "").lower()
    return hostname == TRUSTED_PREVIEW_HOST
