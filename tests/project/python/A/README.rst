Projet A — service bancaire fictif
==================================

Ce mini-projet sert de cible d'essai à SASToy. Il représente quelques
composants d'un back-end bancaire sans dépendance externe ni vraie donnée
client. Les fonctions sont des exemples pédagogiques : elles ne constituent
pas une application bancaire et ne doivent pas être déployées.

Vulnérabilités représentées
---------------------------

* **Secret codé en dur** : identifiant de démonstration dans
  ``bank_api/config.py``.
* **Hachage faible** : MD5 employé pour les mots de passe dans
  ``bank_api/auth/passwords.py``.
* **Générateur pseudo-aléatoire prévisible** : ``random`` utilisé pour un
  jeton de session dans ``bank_api/auth/tokens.py``.
* **Évaluation de code non fiable** : ``eval`` dans
  ``bank_api/reports/formula.py``.
* **Injection de commande potentielle** : commande construite avec une valeur
  saisie, puis transmise à ``subprocess`` avec ``shell=True`` dans
  ``bank_api/support/diagnostics.py``.
* **Lecture de fichier hors du répertoire prévu** : nom de fichier utilisé
  sans confinement dans ``bank_api/documents/files.py``.
* **Désérialisation non sûre** : chargement de données par ``pickle`` dans
  ``bank_api/storage/sessions.py``.
* **Extraction d'archive risquée** : extraction ``tar`` sans filtre dans
  ``bank_api/documents/archive.py``.

Le fichier ``bank_api/safe_patterns.py`` présente des variantes plus sûres
pour la génération de jetons, l'appel de commande et la résolution de chemin.
Ces contrastes permettent aussi de vérifier les faux positifs éventuels.

Lancer une analyse depuis la racine du dépôt
--------------------------------------------

.. code-block:: powershell

   python src/main.py py tests/project/python/A --recursive --mode exhaustif --strategies ast_pattern_scan taint_analysis secret_scan symbolic_execution

Les alertes sont des signaux statiques à examiner, pas une preuve d'exploitabilité.
La règle de détection dépend de la stratégie sélectionnée ; certaines
propriétés, comme la faiblesse de MD5, sont détectées par l'analyse de flux.

Benchmark automatisé
--------------------

Le fichier ``expected.json`` décrit les vulnérabilités de ce projet et les
identifiants de règle susceptibles de les signaler, sans associer de stratégie
particulière à une vulnérabilité. Depuis la racine du dépôt, affichez celles
qui sont repérées et celles qui ne le sont pas :

.. code-block:: powershell

   python benchmark.py --projects A

Les vulnérabilités non repérées sont informatives et ne font pas échouer le
benchmark. Une erreur d'analyse ou un manifeste manquant/invalide produit un
code de sortie non nul. Le benchmark utilise par défaut les trois stratégies
implémentées ; ``symbolic_execution`` peut être sélectionnée explicitement.
