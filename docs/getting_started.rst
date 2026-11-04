Guide de démarrage
==================

Installation
------------

Depuis la racine du dépôt, créez un environnement virtuel et installez les
dépendances :

.. code-block:: powershell

   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt

Analyser un fichier Python
--------------------------

Lancez l'interface Python pour choisir les stratégies :

.. code-block:: powershell

   python src/main.py py tests/vulnerabilities/unsafe_eval/python/sample.py

Le mode manuel demande une ou plusieurs stratégies à sélectionner. Elles sont
exécutées séquentiellement et chacune affiche son résultat dans le terminal.
Ce mode s'arrête aux résultats individuels : il ne lance ni agrégation, ni
synthèse, ni génération de rapport HTML. Exemple :

.. code-block:: text

   ast_pattern_scan, taint_analysis, secret_scan, symbolic_execution

Les quatre stratégies proposées sont ``ast_pattern_scan`` (repérage de motifs
syntaxiques), ``taint_analysis`` (suivi AST expérimental de données non fiables
vers des appels sensibles), ``secret_scan`` (HCS) et
``symbolic_execution``. ``ast_pattern_scan``, ``taint_analysis`` et
``secret_scan`` sont implémentées. ``symbolic_execution`` retourne un statut
« indisponible » et un diagnostic. ``taint_analysis`` ne construit pas un
graphe de flot de contrôle ni ne vérifie de politique CFI ; elle constitue un
premier suivi AST de données potentiellement non fiables. Les signaux AST ne
prouvent pas à eux seuls une vulnérabilité, et la détection HCS n'expose pas la
valeur détectée.

Mode exhaustif
--------------

Le mode exhaustif exécute séquentiellement les stratégies sélectionnées,
agrège leurs résultats et génère un rapport HTML de l'agrégat brut. Les
constats restent séparés par stratégie ; aucune déduplication, synthèse ou
scoring n'est effectué pour le moment. Une stratégie indisponible est marquée
comme telle dans le rapport.

Lancez le mode exhaustif et sélectionnez les stratégies dans l'invite :

.. code-block:: powershell

   python src/main.py py chemin\vers\projet --mode exhaustif

Pour sélectionner les stratégies sans invite :

.. code-block:: powershell

   python src/main.py py chemin\vers\projet --mode exhaustif --strategies ast_pattern_scan taint_analysis secret_scan symbolic_execution

Sans ``--mode``, SASToy demande de choisir entre le mode manuel (valeur par
défaut) et le mode exhaustif. En mode exhaustif, un rapport HTML autonome est
créé sous ``reports/`` dans le répertoire courant. Le chemin du rapport est
affiché dans le terminal ; il n'est pas ouvert automatiquement.

Vérifier l'intégrité d'un fichier
---------------------------------

Fournissez un checksum de référence avec l'algorithme voulu :

.. code-block:: powershell

   python src/main.py file chemin\vers\fichier --algorithm sha256 --official-hash <haché>

La recherche automatique d'un checksum officiel nécessite une variable
d'environnement ``GEMINI_API_KEY`` :

.. code-block:: powershell

   python src/main.py file chemin\vers\fichier --algorithm sha256 --web-search

La vérification porte sur les octets du fichier, quel que soit son nom ou son
extension. Lors d'une recherche web, SASToy tente aussi d'extraire des
métadonnées de version si le contenu est un exécutable Windows PE ; cette
extraction dépend du format, pas de l'extension. Les autres fichiers sont
recherchés avec leur nom, sans métadonnées PE.

Générer la documentation
------------------------

Après l'installation des dépendances du projet, générez le site HTML Sphinx
avec :

.. code-block:: powershell

   python -m sphinx -b html docs docs/_build/html

Ouvrez ensuite ``docs/_build/html/index.html`` dans un navigateur. Les fichiers
de sortie sous ``docs/_build/`` sont générés localement et ne sont pas suivis
par Git.
