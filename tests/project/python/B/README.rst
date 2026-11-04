Projet B — portail de documents partagés
=========================================

Ce mini-projet est une cible pédagogique pour SASToy. Il met en scène un
portail fictif avec des documents, des rôles et des liens de prévisualisation
entièrement simulés. Les données sont inventées et conservées en mémoire :
aucun accès réseau ou fichier n'est effectué. Ce code n'est pas une
application et ne doit pas être déployé.

Scénarios étudiés
-----------------

* **Autorisation avant résolution d'alias** : ``documents.py`` contrôle un
  document, puis renvoie sa cible sans refaire le contrôle sur la ressource
  effectivement chargée. La variante ``get_document_checked`` résout d'abord
  la cible, puis applique la politique à celle-ci.
* **Validation de destination par suffixe** : ``previews.py`` accepte un hôte
  sur la seule base de son suffixe. Des noms qui se terminent par le domaine
  attendu ne sont pas nécessairement des sous-domaines de confiance.
  ``is_preview_host_checked`` utilise une comparaison exacte. Le module ne
  réalise aucune requête réseau.
* **Rôle privilégié sans portée organisationnelle** : ``roles.py`` accepte
  qu'un administrateur agisse sur un compte d'une autre organisation.
  ``change_role_checked`` vérifie aussi la portée de l'acteur.
* **Autorisation périmée entre deux étapes** : ``publication.py`` conserve un
  identifiant après le contrôle, puis publie l'état courant sans revérifier
  l'autorisation ni la version. ``publish_checked`` effectue ces vérifications
  au moment de la publication.
* **Construction de signature vulnérable à l'extension de longueur** :
  ``signatures.py`` calcule MD5 sur le secret concaténé au message au lieu
  d'utiliser un MAC. La variante ``sign_checked`` emploie HMAC-SHA-256.
* **Désérialisation de données importées** : ``imports.py`` charge des états
  pickle et des métadonnées YAML non fiables. L'exemple YAML avec
  ``yaml.SafeLoader`` montre un chargement sûr.
* **Injection de commandes lors d'une conversion** : ``conversions.py``
  transmet un nom de fichier contrôlé au shell avec ``os.system`` et
  ``subprocess`` avec ``shell=True``. ``convert_video_checked`` passe plutôt
  les arguments séparément.
* **Extraction d'archive sans confinement** : ``archives.py`` extrait une
  archive tar sans filtrer ses membres, ce qui peut permettre une traversée
  de chemin.
* **Lecture de document par chemin non confiné** : ``files.py`` utilise un
  nom de document fourni par le client sans vérifier qu'il reste dans le
  stockage partagé.

Ces scénarios illustrent des familles de vulnérabilités observées dans des
incidents et avis historiques, sans reproduire une CVE ni un exploit précis.
Ils couvrent des défauts de logique, de désérialisation et de flux de données.
Le manifeste ``expected.json`` décrit tous les scénarios avec leurs règles
associées ; le benchmark indique ceux que les stratégies actuelles détectent.

Lancer une analyse depuis la racine du dépôt
--------------------------------------------

.. code-block:: powershell

   python src/main.py py tests/project/python/B --recursive --mode exhaustif --strategies ast_pattern_scan taint_analysis secret_scan

Comparer les résultats attendus aux résultats du scanner :

.. code-block:: powershell

   python benchmark.py --projects B

Les alertes sont des signaux statiques à examiner, pas une preuve
d'exploitabilité. L'analyse lit les sources sans appeler leurs fonctions. Les
fonctions vulnérables qui manipulent des commandes ou des fichiers ne doivent
pas être invoquées sur des données réelles. Les fonctions « checked » sont des
exemples pédagogiques, et non une garantie de sécurité pour un système réel.
