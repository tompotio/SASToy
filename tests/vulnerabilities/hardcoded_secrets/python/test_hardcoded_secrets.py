import subprocess
import sys
from pathlib import Path

from src.scanner import detect_hardcoded_secrets


PROJECT_ROOT = Path(__file__).resolve().parents[4]
SAMPLE_FILE = Path(__file__).resolve().parent / "sample.py"


def test_detect_hardcoded_secrets_finds_sample_file():
    findings = detect_hardcoded_secrets(str(SAMPLE_FILE))

    assert {"file": str(SAMPLE_FILE), "line": 1} in findings


def test_hcs_operation_reports_sample_through_cli():
    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "src" / "scanner.py"),
            "py",
            str(SAMPLE_FILE),
        ],
        input="hcs\n",
        capture_output=True,
        cwd=PROJECT_ROOT,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "Analyse HCS (Hardcoded Secrets) en cours" in result.stdout
    assert "Secrets codés en dur détectés" in result.stdout
    assert "Ligne 1" in result.stdout
