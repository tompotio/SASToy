Architecture
============

Le code est divisé par responsabilité :

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Module
     - Responsabilité
   * - ``src.main``
     - Orchestration des commandes et code de sortie.
   * - ``src.interface``
     - Configuration de l'argument CLI et affichage/prompt utilisateur.
   * - ``src.analyzers.base``
     - Contrat abstrait commun aux analyseurs de vulnérabilités par langage.
   * - ``src.analyzers.python``
     - Sélection des fichiers Python, analyse des appels dangereux et détection de secrets.
   * - ``src.integrity``
     - Calcul et vérification des hachages, indépendamment des analyseurs de langage.
   * - ``src.utils``
     - Utilitaires de découverte de fichiers.
   * - ``src.scanner``
     - Point d'entrée historique et réexport de compatibilité.

Ajouter un analyseur pour un langage doit consister à implémenter
``VulnerabilityAnalyzer`` avec les opérations prises en charge pour ce langage.
Les fonctions d'intégrité restent en dehors de cette hiérarchie, car elles ne
dépendent pas de la syntaxe ou du langage analysé.
