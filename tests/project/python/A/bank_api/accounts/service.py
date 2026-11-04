"""Services de consultation de comptes fictifs."""

from typing import TypedDict


class AccountRecord(TypedDict):
    owner: str
    balance: float


ACCOUNTS = {
    "demo-001": {"owner": "Compte de démonstration", "balance": 1250.0},
    "demo-002": {"owner": "Compte d'épargne de démonstration", "balance": 400.0},
}


def get_account(account_id: str) -> AccountRecord | None:
    """Retourne un compte de démonstration par son identifiant."""
    return ACCOUNTS.get(account_id)


def list_account_ids() -> list[str]:
    return list(ACCOUNTS)
