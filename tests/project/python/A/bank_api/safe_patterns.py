"""Contre-exemples de pratiques plus sûres pour les exercices."""

import secrets
import subprocess
from pathlib import Path


def create_token() -> str:
    return secrets.token_urlsafe(32)


def ping_host(host: str) -> str:
    result = subprocess.run(
        ["ping", host],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def statement_path(root: Path, file_name: str) -> Path:
    resolved_root = root.resolve()
    resolved_path = (resolved_root / file_name).resolve()
    resolved_path.relative_to(resolved_root)
    return resolved_path
