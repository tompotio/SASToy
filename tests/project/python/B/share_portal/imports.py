"""Import de métadonnées et d'états de partage pour le portail fictif."""

import pickle

import yaml


def load_shared_state(request):
    """Charge un état pickle reçu dans un téléversement utilisateur."""
    raw_data = request.files.get("state").read()
    return pickle.loads(raw_data)


def load_shared_metadata(request):
    """Charge des métadonnées YAML sans imposer de chargeur sûr."""
    payload = request.form.get("metadata", "")
    return yaml.load(payload, Loader=yaml.Loader)


def load_shared_metadata_checked(request):
    """Charge les mêmes métadonnées avec le chargeur YAML sûr."""
    payload = request.form.get("metadata", "")
    return yaml.safe_load(payload)
