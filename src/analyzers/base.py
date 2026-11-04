from abc import ABC, abstractmethod

from rich.console import Console

from src.results import StrategyResult


class VulnerabilityAnalyzer(ABC):
    """Common contract for vulnerability analysis of a source language."""

    @abstractmethod
    def get_files(self, target_path: str, recursive: bool = False) -> list[str]:
        """Return source files supported by this analyzer.

        Args:
            target_path: A source file or directory to inspect.
            recursive: Whether to include files in nested directories.
        """

    @abstractmethod
    def analyze_strategy(self, strategy: str, files: list[str]) -> StrategyResult:
        """Run one supported strategy and return its normalized result."""

    @abstractmethod
    def analyze_operation(
        self,
        operation: str,
        files: list[str],
        console: Console,
    ) -> StrategyResult | None:
        """Run one supported analysis operation on source files.

        Args:
            operation: The operation identifier selected by the user.
            files: Source file paths returned by :meth:`get_files`.
            console: Rich console used to display results.
        """
