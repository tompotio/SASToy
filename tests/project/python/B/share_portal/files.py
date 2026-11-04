"""Accès aux documents partagés à partir d'un nom fourni par le client."""


def read_shared_document(request, storage_root):
    """Lit un document sans confiner le chemin fourni par le client."""
    document_name = request.args.get("name", "welcome.txt")
    return open(storage_root / document_name, encoding="utf-8").read()
