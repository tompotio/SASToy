"""Diagnostic de connectivité destiné à l'équipe de support."""

import subprocess


def check_host_connectivity() -> str:
    host = input("Hôte à diagnostiquer : ")
    command = f"ping {host}"
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout
