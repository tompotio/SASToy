import os
import sys
import subprocess

def lire_document():

    if len(sys.argv) > 1:
        fichier = sys.argv[1]
    else:
        fichier = "sample.py"

    repertoire_courant = os.getcwd()
    fichier_cible = os.path.join(repertoire_courant, fichier)
    print(f"[+] Lecture du fichier : {fichier_cible}")

    with open(fichier_cible, 'r') as f:
        return f.read()

if __name__ == "__main__":
  try:
    document = lire_document()
    print(f"\n{document}")
  except Exception as e:
    print(f"Erreur : {e}")
