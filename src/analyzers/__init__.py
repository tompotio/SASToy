"""Language-specific vulnerability analyzers."""

from src.analyzers.base import VulnerabilityAnalyzer
from src.analyzers.python import PythonAnalyzer

__all__ = ["PythonAnalyzer", "VulnerabilityAnalyzer"]
