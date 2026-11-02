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
     - Sélection des fichiers Python, détection de signaux syntaxiques définis dans le catalogue et détection de secrets.
   * - ``src.integrity``
     - Calcul et vérification des hachages, indépendamment des analyseurs de langage.
   * - ``src.utils``
     - Utilitaires de découverte de fichiers.

Ajouter un analyseur pour un langage doit consister à implémenter
``VulnerabilityAnalyzer`` avec les opérations prises en charge pour ce langage.
Les fonctions d'intégrité restent en dehors de cette hiérarchie, car elles ne
dépendent pas de la syntaxe ou du langage analysé.

L'analyse des appels Python est heuristique : elle repère des constructions
syntaxiques indicatives sans démontrer qu'une vulnérabilité est exploitable.
Les avis sur les dépendances présentes dans le catalogue sont documentaires ;
la passe AST ne vérifie pas les versions déclarées ou installées.
