SASToy
======

SASToy est un outil pédagogique de **Static Application Security Testing**
(SAST). Il analyse actuellement le code source Python pour repérer certains
motifs dangereux et les secrets codés en dur. Il propose également des outils
de vérification d'intégrité par hachage.

.. note::

   L'analyse des vulnérabilités n'est actuellement implémentée que pour Python.
   L'architecture permet d'ajouter ultérieurement des analyseurs dédiés à
   d'autres langages.

.. toctree::
   :maxdepth: 2
   :caption: Documentation

   getting_started
   architecture
   api

Fonctionnalités actuelles
-------------------------

* Repérage d'appels à ``eval`` et ``exec`` dans du code Python.
* Détection de secrets codés en dur avec ``detect-secrets``.
* Calcul et comparaison de hachages MD5, SHA-1 et SHA-256.
* Recherche facultative d'un checksum officiel avec Gemini et Google Search.

Pour les exemples de commandes, consultez le :doc:`guide de démarrage
<getting_started>`. La documentation de référence des modules se trouve dans
:doc:`api`.
