"""Chargement de sessions sérialisées pour le service fictif."""

import pickle


def load_session(serialized_session: bytes) -> object:
    """Désérialise des données sans en vérifier la provenance."""
    return pickle.loads(serialized_session)
