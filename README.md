# SASToy - Outil SAST jouet

Petit projet de Static Application Security Testing (SAST) conçu pour apprendre les concepts de sécurité logicielle, analyser les Abstract Syntax Trees (AST).

---

## Structure du projet

- `src/` : Contient le code source de notre moteur de scan SAST.
- `tests/` : Héberge les fichiers de test et les échantillons de code intentionnellement vulnérables.
- `Dockerfile` : Configuration pour exécuter l'outil dans un conteneur Docker indépendant du système d'exploitation.
- `requirements.txt` : Liste des dépendances Python du projet avec leurs versions exactes.

---

## Configuration du développement local (avec venv)

Si vous souhaitez coder ou tester le projet directement dans votre IDE :

1. **Créer l'environnement virtuel :**
   ```bash
   python -m venv venv
   ```

2. **Activer l'environnement :**
   - **macOS / Linux :** 
     ```bash
     source venv/bin/activate
     ```
   - **Windows (CMD) :** 
     ```cmd
     venv\Scripts\activate.bat
     ```
   - **Windows (PowerShell) :** 
     ```powershell
     venv\Scripts\Activate.ps1
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
      docker run --rm -v $(pwd):/app sastoy /app/tests/votre_fichier.py
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