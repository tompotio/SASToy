"""Exemples de conversion de fichiers partagés sans exécution à l'import."""

import os
import subprocess


def convert_video(request):
    """Construit une commande shell avec un nom de fichier contrôlé."""
    filename = request.args.get("name", "default.mp4")
    os.system(f"ffmpeg -i {filename} output.avi")


def convert_preview_with_shell(request):
    """Passe une entrée contrôlée au shell via subprocess."""
    filename = request.args.get("name", "preview.mp4")
    subprocess.run(
        f"ffmpeg -i {filename} -f null -",
        shell=True,
        check=True,
    )


def convert_video_checked(request):
    """Transmet le nom comme argument séparé, sans interprétation par le shell."""
    filename = request.args.get("name", "default.mp4")
    subprocess.run(
        ["ffmpeg", "-i", filename, "output.avi"],
        check=True,
    )
