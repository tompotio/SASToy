# Consignes Copilot — SASToy

## Projet et stack

- Projet pédagogique de SAST en Python ; l'analyse de vulnérabilités est actuellement limitée à Python.
- CLI : `src/main.py`. L'orchestration est dans `src/main.py`, les arguments et prompts dans `src/interface.py`, l'intégrité dans `src/integrity.py`, et les analyseurs dans `src/analyzers/`.
- Dépendances déclarées dans `requirements.txt` : pytest, Rich, Google GenAI, pefile, detect-secrets, Sphinx et Furo.
- Documentation en français, écrite en reStructuredText avec Sphinx, autodoc et le thème Furo (`docs/`).

## Repères utiles

- Installation : `python -m pip install -r requirements.txt`
- Tests : `python -m pytest`
- Documentation HTML : `python -m sphinx -W --keep-going -b html docs docs/_build/html`
- Voir `docs/getting_started.rst` pour l'utilisation et `docs/architecture.rst` pour les responsabilités des modules.

## Consignes de changement

- Respecter l'organisation et le style existants ; privilégier des changements ciblés et réutiliser les fonctions et abstractions en place.
- Pour tout changement fonctionnel, ajouter ou mettre à jour des tests pertinents et lancer au minimum les tests concernés.
- Les fichiers sous `tests/vulnerabilities/` sont des exemples de code vulnérable utilisés comme données de test : ne pas les « corriger » dans le cadre d'un changement sans rapport.
- Ne jamais inscrire de secrets ou de clés API dans le dépôt. La recherche web d'intégrité utilise `GEMINI_API_KEY`.
- Garder la documentation utilisateur en français et à jour avec les changements de comportement ou d'interface.
- Ne pas ajouter de dépendance, de framework ou de configuration d'outillage sans nécessité pour la tâche.
