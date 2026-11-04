"""Résolution d'alias et contrôle d'accès sur des documents fictifs."""

DOCUMENTS = {
    "welcome": {
        "tenant": "public",
        "owner": "service",
        "alias_of": "finance-draft",
        "content": "Page d'accueil fictive",
    },
    "finance-draft": {
        "tenant": "north",
        "owner": "user-17",
        "alias_of": None,
        "content": "Brouillon financier fictif",
    },
}


def _can_read(document: dict[str, str | None], principal: dict[str, str]) -> bool:
    return (
        document["tenant"] == "public"
        or document["owner"] == principal["user_id"]
        or document["tenant"] == principal["tenant"]
    )


def get_document(document_id: str, principal: dict[str, str]) -> str | None:
    """Vérifie l'alias avant de retourner sa cible, sans recontrôler l'accès."""
    requested = DOCUMENTS.get(document_id)
    if requested is None or not _can_read(requested, principal):
        return None

    target_id = requested["alias_of"] or document_id
    target = DOCUMENTS.get(target_id)
    return target["content"] if target else None


def get_document_checked(document_id: str, principal: dict[str, str]) -> str | None:
    """Résout l'alias avant de contrôler la ressource effectivement utilisée."""
    requested = DOCUMENTS.get(document_id)
    if requested is None:
        return None

    target_id = requested["alias_of"] or document_id
    target = DOCUMENTS.get(target_id)
    if target is None or not _can_read(target, principal):
        return None
    return target["content"]
