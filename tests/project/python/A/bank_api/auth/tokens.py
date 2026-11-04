"""Génération d'identifiants de session pour le service fictif."""

import random
import secrets


def create_session_token() -> str:
    """Exemple prévisible à remplacer en production."""
    return str(random.randint(100_000, 999_999))


def create_secure_session_token() -> str:
    """Variante utilisant une source cryptographiquement sûre."""
    return secrets.token_urlsafe(32)
