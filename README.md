# SASToy - Outil SAST jouet

Petit projet de Static Application Security Testing (SAST) conçu pour apprendre les concepts de sécurité logicielle. Et l'utilisation d'un Abstract Syntax Trees (AST).

---

## Structure du projet

- `src/` : Contient le code source de notre moteur de scan SAST.
- `tests/` : Héberge les fichiers de test et les échantillons de code intentionnellement vulnérables.
- `Dockerfile` : Configuration pour exécuter l'outil dans un conteneur Docker indépendant du système d'exploitation.
- `requirements.txt` : Liste des dépendances Python du projet avec leurs versions exactes.

---

## Configuration du développement local (avec venv)

Pour coder ou tester le projet directement dans l'IDE :

1. **Créer l'environnement virtuel :**
   ```bash
   python -m venv .venv
   ```

2. **Activer l'environnement :**
   - **macOS / Linux :** 
     ```bash
     source .venv/bin/activate
     ```
   - **Windows (CMD) :** 
     ```cmd
     .venv\Scripts\activate.bat
     ```
   - **Windows (PowerShell) :** 
     ```powershell
     .venv\Scripts\Activate.ps1
     ```

3. **Installer les dépendances :**
   ```bash
   pip install -r requirements.txt
   ```

---

## Utilisation avec Docker

Pour exécuter le scanner de manière identique sur n'importe quelle machine (Mac, Linux, Windows) :

1. **Construire l'image Docker :**
   ```bash
   docker build -t sastoy .
   ```

2. **Exécuter le scanner :**

   2.1 **Version classique**
   ```bash
      docker run --rm -v $(pwd):/app sastoy /app/vulnerability/sample_1.py
   ```

   2.2 **Version alternative (à adapter en fonction de la version windows) :**

   Construction préalable :
   ```bash
      docker build -t sastoy-windows .
   ```

   Lancement du docker :
   ```bash
      docker run --rm --isolation=process -v ${PWD}:C:\app sastoy-windows C:\app\tests\vulnerability\sample_1.py
   ```

*(Note sous Windows PowerShell : si `$(pwd)` génère une erreur, remplacer par `${PWD}`)

## Vérification d'un haché

Le mode `hash` calcule le haché d'un fichier et le compare à une valeur de
référence. Les algorithmes pris en charge sont MD5, SHA-1 et SHA-256. Sans
option de référence, SASToy demande interactivement l'algorithme et la source
du haché.

Comparer avec un haché fourni :

```powershell
python src/scanner.py hash chemin\vers\fichier.exe --algorithm sha1 --official-hash <haché>
```

Rechercher le haché officiel sur le web (nécessite une clé Gemini dans
`GEMINI_API_KEY`) :

```powershell
python src/scanner.py exe chemin\vers\fichier.exe --algorithm sha256 --web-search
```

La recherche web demande à Gemini d'identifier une source officielle et
n'accepte un haché que si la réponse fournit explicitement le marqueur
`OFFICIAL_CHECKSUM`. Vérifiez les sources affichées avant de vous fier au
résultat. Les comparaisons MD5 et SHA-1 sont disponibles pour compatibilité,
mais ces algorithmes ne sont pas recommandés lorsque la résistance aux
collisions est nécessaire.

Afficher les commandes et options à tout moment :

```powershell
python src/scanner.py --help
```