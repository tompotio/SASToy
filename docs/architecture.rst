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
     - Sélection des fichiers Python, exécution des stratégies AST et HCS et définition des sorties indisponibles pour CFG et l'exécution symbolique.
   * - ``src.results`` et ``src.aggregation``
     - Contrats typés des résultats et regroupement ordonné des constats sans scoring ni déduplication.
   * - ``src.report``
     - Présentation HTML des résultats individuels et de l'agrégat brut du mode exhaustif, sans synthèse ni scoring.
   * - ``src.strategies``
     - Identifiants et libellés communs des quatre stratégies proposées.
   * - ``src.integrity``
     - Calcul et vérification des hachages, indépendamment des analyseurs de langage.
   * - ``src.utils``
     - Utilitaires de découverte de fichiers.

Les stratégies ``ast_pattern_scan`` et ``secret_scan`` sont exécutées en mode
manuel et affichent leurs résultats individuels dans le terminal. Les
stratégies ``cfg_analysis`` et ``symbolic_execution`` ont un contrat de
résultat défini, mais restent indisponibles. Le mode manuel ne lance ni
agrégation, ni synthèse, ni rapport HTML. Les fonctions d'intégrité restent en
dehors de cette hiérarchie, car elles ne dépendent pas de la syntaxe ou du
langage analysé.

Le mode manuel et le mode exhaustif exposent les mêmes quatre stratégies :
``ast_pattern_scan``, ``cfg_analysis`` (CFI et analyse de flot/taint et SQLi),
``secret_scan`` (HCS) et ``symbolic_execution``. Le mode exhaustif exécute les
stratégies sélectionnées séquentiellement, agrège leurs résultats sans
déduplication ni scoring, puis les transmet au rapport HTML. La synthèse des
constats reste à implémenter.
