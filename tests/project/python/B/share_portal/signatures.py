"""Exemples de signatures pour des messages fictifs."""

import hashlib
import hmac


def sign_legacy(message: bytes, secret: bytes) -> str:
    """Construit un MAC par concaténation avec un algorithme faible."""
    return hashlib.md5(secret + message).hexdigest()


def sign_checked(message: bytes, secret: bytes) -> str:
    """Construit une signature avec un MAC standard."""
    return hmac.new(secret, message, hashlib.sha256).hexdigest()
