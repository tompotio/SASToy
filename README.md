# SASToy - Outil SAST jouet

Petit projet de Static Application Security Testing (SAST) conçu pour apprendre les concepts de sécurité logicielle.

---

## Structure du projet

- `src/` : Contient le code source de notre moteur de scan SAST.
- `tests/` : Regroupe les tests unitaires, les échantillons vulnérables par catégorie et langage, et les fixtures.
- `Dockerfile` : Configuration pour exécuter l'outil dans un conteneur Docker indépendant du système d'exploitation.
- `requirements.txt` : Liste des dépendances Python du projet avec leurs versions exactes.

Le code source sépare l'interface en ligne de commande (`src/interface.py`),
l'orchestration (`src/main.py`), les utilitaires (`src/utils.py`) et la
vérification d'intégrité (`src/integrity.py`). Les analyses de vulnérabilités
reposent sur le contrat `VulnerabilityAnalyzer` dans `src/analyzers/base.py`,
implémenté pour Python dans `src/analyzers/python.py`.

---

## Configuration du développement local (avec venv)

Pour coder ou tester le projet directement dans l'IDE :

1. **Créer l'environnement virtuel :**
   ```bash
   python -m venv .venv
   ```

2. **Activer l'environnement :**
   - **macOS / Linux :** 
     ```bash
     source .venv/bin/activate
     ```
   - **Windows (CMD) :** 
     ```cmd
     .venv\Scripts\activate.bat
     ```
   - **Windows (PowerShell) :** 
     ```powershell
     .venv\Scripts\Activate.ps1
     ```

3. **Installer les dépendances :**
   ```bash
   pip install -r requirements.txt
   ```

---

## Utilisation avec Docker

Le Dockerfile utilise l'image `python:3.11-windowsservercore`. Il nécessite
Docker en mode conteneurs Windows ; il n'est pas compatible avec un moteur
Docker configuré pour les conteneurs Linux.

Dans PowerShell, depuis la racine du dépôt :

1. **Construire l'image Docker :**
   ```bash
   docker build -t sastoy .
   ```

2. **Exécuter le scanner :**
   ```bash
   docker run --rm --isolation=process -v "${PWD}:C:\app" sastoy py C:\app\tests\vulnerabilities\unsafe_eval\python\sample.py
   ```

## Organisation des tests

Les tests unitaires sont dans `tests/unit/`. Les tests ciblant une vulnérabilité
et leurs échantillons sont regroupés sous
`tests/vulnerabilities/<categorie>/<langage>/` (par exemple
`tests/vulnerabilities/hardcoded_secrets/python/`). Les données de test
génériques sont stockées dans `tests/fixtures/`.

Lancer tous les tests :

```powershell
python -m pytest
```

## Vérification d'un haché

Le mode `hash` calcule le haché d'un fichier et le compare à une valeur de
référence. Les algorithmes pris en charge sont MD5, SHA-1 et SHA-256. Sans
option de référence, SASToy demande interactivement l'algorithme et la source
du haché.

Comparer avec un haché fourni :

```powershell
python src/main.py hash chemin\vers\fichier.bin --algorithm sha1 --official-hash <haché>
```

Rechercher le haché officiel sur le web (nécessite une clé Gemini dans
`GEMINI_API_KEY`) :

```powershell
python src/main.py binary chemin\vers\fichier.bin --algorithm sha256 --web-search
```

La recherche web demande à Gemini d'identifier une source officielle et
n'accepte un haché que si la réponse fournit explicitement le marqueur
`OFFICIAL_CHECKSUM`. Les comparaisons MD5 et SHA-1 sont disponibles.
Le mode `binary` accepte aussi l'alias `bin`. L'ancien mode `exe` reste accepté
comme alias de compatibilité.

Afficher les commandes et options à tout moment :

```powershell
python src/main.py --help
```

## Documentation

La documentation du projet est rédigée avec Sphinx dans `docs/`. Pour générer
le site HTML localement :

```powershell
python -m sphinx -b html docs docs/_build/html
```

Ouvrez ensuite `docs/_build/html/index.html`. Les fichiers générés dans
`docs/_build/` sont ignorés par Git.