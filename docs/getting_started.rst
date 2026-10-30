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

Lancez l'interface historique, qui reste prise en charge :

.. code-block:: powershell

   python src/scanner.py py tests/vulnerabilities/unsafe_eval/python/sample.py

Le scanner demande les opérations à exécuter. Exemple pour rechercher les
appels dangereux :

.. code-block:: text

   function_calls

Vérifier l'intégrité d'un fichier
---------------------------------

Fournissez un checksum de référence avec l'algorithme voulu :

.. code-block:: powershell

   python src/scanner.py hash chemin\vers\fichier.exe --algorithm sha256 --official-hash <haché>

La recherche automatique d'un checksum officiel nécessite une variable
d'environnement ``GEMINI_API_KEY`` :

.. code-block:: powershell

   python src/scanner.py exe chemin\vers\fichier.exe --algorithm sha256 --web-search

Générer la documentation
------------------------

Après l'installation des dépendances du projet, générez le site HTML Sphinx
avec :

.. code-block:: powershell

   python -m sphinx -b html docs docs/_build/html

Ouvrez ensuite ``docs/_build/html/index.html`` dans un navigateur. Les fichiers
de sortie sous ``docs/_build/`` sont générés localement et ne sont pas suivis
par Git.
