"""Exemples pédagogiques de vérification des mots de passe."""

import hashlib


def password_digest(password: str) -> str:
    """Retourne un condensat MD5, inadapté au stockage des mots de passe."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(password: str, stored_digest: str) -> bool:
    return password_digest(password) == stored_digest
