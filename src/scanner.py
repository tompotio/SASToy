import argparse
import ast
import sys
import os

from pathlib import Path

def get_python_files(target_path, recursive=False):
  # Case 1: Check if the user provided a single file path
  if os.path.isfile(target_path) and target_path.endswith(".py"):
    return [target_path]

  # Case 2: Check if the user provided a directory path
  if os.path.isdir(target_path):
    python_files = []

    if recursive:
      for root, dirs, files in os.walk(target_path):
        for filename in files:
          if filename.endswith(".py"):
            python_files.append(os.path.join(root, filename))
    else:
      for filename in os.listdir(target_path):
        if filename.endswith(".py"):
          full_path = os.path.join(target_path, filename)
          if os.path.isfile(full_path):
            python_files.append(full_path)

    return python_files

  return []


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description="Mini analyseur statique de code source basé sur l'AST."
  )

  parser.add_argument(
      "target",
      type=str,
      help="Chemin du fichier .py ou du dossier à analyser",
  )

  parser.add_argument(
      "-r",
      "--recursive",
      action="store_true",  # Devient True si l'option est passée dans la commande
      help="Analyser les sous-dossiers de manière récursive",
  )

  args = parser.parse_args()
  files_to_scan = get_python_files(args.target, recursive=args.recursive)

  print(f"[*] Fichiers identifiés pour l'analyse : {files_to_scan}")