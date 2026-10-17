#FROM python:3.11-slim
#
#WORKDIR /app
#
#COPY requirements.txt .
#
#RUN pip install --no-cache-dir -r requirements.txt
#
#COPY . .
#
#ENTRYPOINT ["python", "src/scanner.py"]

# Utilisation de l'image Windows officielle de Python
FROM python:3.11-windowsservercore

# Définition du répertoire de travail (chemin Windows)
WORKDIR C:\app

# Copie et installation des dépendances (mises en cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du reste du code source
COPY . .

# Point d'entrée par défaut
ENTRYPOINT ["python", "src/scanner.py"]