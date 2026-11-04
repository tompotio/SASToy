"""Transferts fictifs entre comptes de démonstration."""

from bank_api.accounts.service import ACCOUNTS


def transfer(source_id: str, destination_id: str, amount: float) -> bool:
    """Effectue un transfert en mémoire si les comptes et le solde existent."""
    source = ACCOUNTS.get(source_id)
    destination = ACCOUNTS.get(destination_id)
    if source is None or destination is None or amount <= 0:
        return False
    if source["balance"] < amount:
        return False

    source["balance"] -= amount
    destination["balance"] += amount
    return True
