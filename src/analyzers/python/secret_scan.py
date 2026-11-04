"""Hardcoded-secret detection strategy for Python source."""

from pathlib import Path
from typing import Callable

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from src.results import (
    AnalysisDiagnostic,
    Finding,
    FindingOrigin,
    Location,
    SecretEvidence,
    StrategyResult,
)


StatusResolver = Callable[
    [list[str], int, list[AnalysisDiagnostic]],
    str,
]


def detect_hardcoded_secrets(file_to_scan: str) -> list[dict[str, object]]:
    """Return secret detector metadata without exposing secret values."""
    path = Path(file_to_scan)
    if not path.is_file() or path.suffix != ".py":
        raise ValueError(
            f"Le fichier spécifié n'est pas un fichier Python valide : "
            f"{file_to_scan}"
        )

    collection = SecretsCollection()
    with default_settings():
        collection.scan_file(str(path))

    findings = []
    for filename, detections in collection.json().items():
        for detection in detections:
            findings.append(
                {
                    "file": filename,
                    "line": detection.get("line_number"),
                    "detector": detection.get("type", "unknown"),
                    "verified": bool(detection.get("is_verified", False)),
                }
            )
    return findings


def analyze(
    files: list[str],
    result_status: StatusResolver,
) -> StrategyResult:
    """Run secret detection and convert metadata into normalized findings."""
    findings = []
    diagnostics = []
    successful_files = 0

    for file in files:
        try:
            detected = detect_hardcoded_secrets(file)
        except (OSError, UnicodeError, ValueError) as exc:
            diagnostics.append(
                AnalysisDiagnostic(
                    code="secret_scan_error",
                    message=f"{type(exc).__name__}: {exc}",
                    file=file,
                )
            )
            continue

        successful_files += 1
        for detection in detected:
            line = detection["line"]
            findings.append(
                Finding(
                    rule_id="HARDCODED_SECRET",
                    kind="secret",
                    category="hardcoded_secret",
                    severity="unknown",
                    confidence=None,
                    message="Valeur ressemblant à un secret détectée.",
                    location=Location(
                        file=str(detection["file"]),
                        start_line=line if isinstance(line, int) else None,
                        end_line=line if isinstance(line, int) else None,
                    ),
                    evidence=SecretEvidence(
                        detector=str(detection["detector"]),
                        verified=bool(detection["verified"]),
                    ),
                    origin=FindingOrigin(strategy="secret_scan"),
                )
            )

    return StrategyResult(
        strategy="secret_scan",
        status=result_status(files, successful_files, diagnostics),
        findings=findings,
        diagnostics=diagnostics,
    )
