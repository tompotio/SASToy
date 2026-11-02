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

Lancez l'analyseur Python :

.. code-block:: powershell

   python src/main.py py tests/vulnerabilities/unsafe_eval/python/sample.py

Le scanner demande les opérations à exécuter. Exemple pour rechercher les
signaux de sécurité :

.. code-block:: text

   security_signals

Cette analyse repère des constructions syntaxiques à examiner (par exemple
``eval``, ``pickle.loads`` ou une extraction avec ``tarfile.extractall``).
Un signal n'affirme pas qu'une vulnérabilité est présente : l'analyse ne suit
pas les données et ne déduit pas leur provenance. Les alias d'import simples
sont reconnus, mais pas les alias dynamiques ni tous les usages indirects.

Le catalogue contient aussi des avis historiques concernant des dépendances
telles que Requests et urllib3. Ils sont documentaires : cette opération ne
vérifie pas les versions installées ou déclarées. Il faut comparer les
dépendances des fichiers de requirements ou de verrouillage aux avis concernés.

Mode exhaustif (prototype)
--------------------------

Le mode exhaustif est un prototype d'interface et de rapport : ses sorties,
comptages et recommandations sont fictifs et aucune stratégie n'analyse la
cible. Il ne faut pas interpréter ses exemples comme des résultats de scan.
Les stratégies sélectionnées par défaut sont celles actuellement implémentées
(``security_signals`` et ``hcs``) ; CFI et SQLi sont indiquées comme non
implémentées.

Lancez le prototype et sélectionnez les stratégies dans l'invite :

.. code-block:: powershell

   python src/main.py py chemin\vers\projet --mode exhaustif

Pour sélectionner les stratégies sans invite :

.. code-block:: powershell

   python src/main.py py chemin\vers\projet --mode exhaustif --strategies security_signals hcs

Sans ``--mode``, SASToy demande de choisir entre le mode manuel (valeur par
défaut) et le mode exhaustif. Dans le prototype exhaustif, un rapport HTML
autonome est créé sous ``reports/`` dans le répertoire courant. Le chemin du
rapport est affiché dans le terminal ; il n'est pas ouvert automatiquement.

Le CLI demande si un token Gemini est configuré, puis, le cas échéant, un
consentement distinct avant l'envoi d'un résumé anonymisé. Seuls les noms des
stratégies et leurs nombres d'exemples fictifs sont transmis ; ni le code, ni
les chemins de fichiers, ni les valeurs de secrets ne sont envoyés. La partie
IA reste distincte des sorties locales dans le rapport.

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
