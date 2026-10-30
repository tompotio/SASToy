from abc import ABC, abstractmethod


class VulnerabilityAnalyzer(ABC):
    """Common contract for vulnerability analysis of a source language."""

    @abstractmethod
    def get_files(self, target_path, recursive=False):
        """Return source files supported by this analyzer.

        Args:
            target_path: A source file or directory to inspect.
            recursive: Whether to include files in nested directories.
        """

    @abstractmethod
    def analyze_operation(self, operation, files, console):
        """Run one supported analysis operation on source files.

        Args:
            operation: The operation identifier selected by the user.
            files: Source file paths returned by :meth:`get_files`.
            console: Rich console used to display results.
        """
