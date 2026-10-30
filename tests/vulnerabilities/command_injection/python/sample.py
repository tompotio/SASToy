import os
import sys
import subprocess

def test_ping():
  target = input("Entrez l'IP d'une machine cible : ")
  ping = f"ping -c3 {target}"
  print(f"[+] Exécution de la commande ping : {ping}")
  output = subprocess.check_output(ping,shell=True,text=True)
  return output

if __name__ == "__main__":
  try:
    ping = test_ping()
    print(f"\n{ping}")
  except Exception as e:
    print(f"Erreur : {e}")
