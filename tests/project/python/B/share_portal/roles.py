"""Gestion de rôles sur un jeu de comptes fictifs en mémoire."""


def change_role(
    actor: dict[str, str],
    target: dict[str, str],
    new_role: str,
) -> bool:
    """Permet à un administrateur d'agir sans vérifier son organisation."""
    if actor["role"] != "admin":
        return False
    target["role"] = new_role
    return True


def change_role_checked(
    actor: dict[str, str],
    target: dict[str, str],
    new_role: str,
) -> bool:
    """Vérifie le privilège de l'acteur et sa portée organisationnelle."""
    if actor["role"] != "admin" or actor["organization"] != target["organization"]:
        return False
    target["role"] = new_role
    return True
