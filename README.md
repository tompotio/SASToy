# SASToy

Petit projet de Static Application Security Testing (SAST) conçu pour apprendre les concepts de sécurité logicielle.

---

## Structure du projet

- `src/` : Contient le code source de l'interface CLI et des outils SASToy.
- `tests/` : Regroupe les tests unitaires, les échantillons vulnérables par catégorie et langage, et les fixtures.
- `Dockerfile` : Configuration pour exécuter l'outil dans un conteneur Docker indépendant du système d'exploitation.
- `requirements.txt` : Liste des dépendances Python du projet.

Le code source sépare l'interface en ligne de commande (`src/interface.py`),
l'orchestration (`src/main.py`), les utilitaires (`src/utils.py`) et la
vérification d'intégrité (`src/integrity.py`). Les quatre stratégies Python
sont définies dans `src/strategies.py`, mais ne sont pas encore implémentées :
les modes manuel et exhaustif ne font actuellement qu'afficher leur statut.
Le mode exhaustif génère un rapport HTML sans résultats de scan.

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

2. **Ouvrir l'interface :**
   ```bash
   docker run --rm --isolation=process -v "${PWD}:C:\app" sastoy py C:\app\tests\vulnerabilities\unsafe_eval\python\sample.py
   ```

## Organisation des tests

Les tests sont dans `tests/unit/`. Les exemples de code vulnérable, conservés
comme données pédagogiques, sont regroupés sous
`tests/vulnerabilities/<categorie>/<langage>/`. Les données de test génériques
sont stockées dans `tests/fixtures/`.

Lancer tous les tests :

```powershell
python -m pytest
```

## Vérification de l'intégrité d'un fichier

Le mode `file` calcule le haché d'un fichier et le compare à une valeur de
référence, sans restriction de type ou d'extension. Les algorithmes pris en
charge sont MD5, SHA-1 et SHA-256. Sans option de référence, SASToy demande
interactivement l'algorithme et la source du haché.

Comparer avec un haché fourni :

```powershell
python src/main.py file chemin\vers\fichier --algorithm sha1 --official-hash <haché>
```

Rechercher le haché officiel sur le web (nécessite une clé Gemini dans
`GEMINI_API_KEY`) :

```powershell
python src/main.py file chemin\vers\fichier --algorithm sha256 --web-search
```

La recherche web demande à Gemini d'identifier une source officielle et
n'accepte un haché que si la réponse fournit explicitement le marqueur
`OFFICIAL_CHECKSUM`. Les comparaisons MD5 et SHA-1 sont disponibles.
Lorsque le fichier est au format Windows PE, SASToy tente d'extraire ses
métadonnées de version pour préciser la recherche. La détection se base sur le
contenu du fichier, pas sur son extension ; aucun format particulier n'est
requis pour calculer et vérifier son haché.

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