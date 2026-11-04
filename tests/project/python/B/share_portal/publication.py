"""Publication fictive en mémoire avec une autorisation à deux étapes."""

DOCUMENTS = {
    "release-note": {
        "owner": "editor-4",
        "revision": 3,
        "published": False,
    }
}


def authorize_publication(document_id: str, user_id: str) -> str | None:
    """Retourne un identifiant si son propriétaire est autorisé à publier."""
    document = DOCUMENTS.get(document_id)
    if document is None or document["owner"] != user_id:
        return None
    return document_id


def publish(authorization: str) -> bool:
    """Utilise une autorisation ancienne sans revalider l'état courant."""
    document = DOCUMENTS.get(authorization)
    if document is None:
        return False
    document["published"] = True
    return True


def publish_checked(
    authorization: str,
    user_id: str,
    authorized_revision: int,
) -> bool:
    """Revérifie le propriétaire et la version lors de l'opération effective."""
    document = DOCUMENTS.get(authorization)
    if (
        document is None
        or document["owner"] != user_id
        or document["revision"] != authorized_revision
    ):
        return False
    document["published"] = True
    return True
