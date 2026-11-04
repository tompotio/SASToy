"""Calcul de frais à partir d'une formule fournie à titre de démonstration."""


def calculate_fee(formula: str, amount: float) -> float:
    """Évalue une expression comme si elle provenait d'une source fiable."""
    return eval(formula, {"__builtins__": {}}, {"amount": amount})


def calculate_fixed_fee(amount: float, rate: float = 0.01) -> float:
    """Variante qui applique un taux numérique connu."""
    return amount * rate
