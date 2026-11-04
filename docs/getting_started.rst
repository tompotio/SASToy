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

Benchmark des mini-projets
--------------------------

Les mini-projets de ``tests/project/python/`` peuvent décrire leurs constats
attendus dans un fichier ``expected.json`` à leur racine. Le script
``benchmark.py`` analyse tous les projets présents et agrège les alertes sans
retenir quelle stratégie les a produites. Le manifeste décrit les scénarios
de vulnérabilité ; chaque entrée de ``vulnerabilities`` possède un identifiant,
un titre, un fichier et les identifiants de règle qui peuvent permettre de
l'associer à une alerte :

.. code-block:: json

   {
     "version": 2,
     "vulnerabilities": [
       {
         "id": "dynamic-evaluation",
         "title": "Évaluation de code non fiable",
         "file": "src/example.py",
         "rule_ids": ["UNSAFE_EVAL"]
       }
     ]
   }

Une liste ``rule_ids`` vide permet de documenter une faille qui n'est pas
encore reconnue par les analyseurs. Une vulnérabilité est considérée repérée
si une alerte de l'un des analyseurs exécutés correspond à l'un de ses
identifiants de règle dans le fichier indiqué. Si plusieurs stratégies
produisent le même signal, il n'est compté qu'une fois.

.. code-block:: powershell

   python benchmark.py

Pour ne lancer que certains projets ou stratégies :

.. code-block:: powershell

   python benchmark.py --projects A B
   python benchmark.py --strategies ast_pattern_scan taint_analysis secret_scan

Le rapport affiche les vulnérabilités repérées et non repérées ainsi que les
signaux qui ne correspondent à aucun scénario déclaré. Les vulnérabilités non
repérées ne font pas échouer le benchmark : il sert à observer la couverture,
pas à imposer une correspondance exacte ni à maximiser un score. Le code de
sortie est non nul en cas d'erreur d'analyse ou de manifeste invalide. Par
défaut, le benchmark sélectionne les trois stratégies implémentées ;
``symbolic_execution`` n'est pas incluse car elle est actuellement
indisponible.

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
