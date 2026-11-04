"""Report which declared benchmark vulnerabilities SASToy detects."""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from src.analyzers.python import PythonAnalyzer
from src.strategies import STRATEGIES


DEFAULT_PROJECTS_DIR = Path(__file__).parent / "tests" / "project" / "python"
DEFAULT_STRATEGIES = (
    "ast_pattern_scan",
    "taint_analysis",
    "secret_scan",
)
FindingKey = tuple[str, str]


@dataclass(frozen=True)
class Vulnerability:
    """A vulnerability scenario declared by a benchmark project's manifest."""

    id: str
    title: str
    file: str
    rule_ids: tuple[str, ...]


@dataclass
class ProjectResult:
    """Declared vulnerabilities and strategy-independent observed findings."""

    name: str
    vulnerabilities: list[Vulnerability]
    findings: set[FindingKey]
    analysis_errors: list[str]

    @property
    def detected(self) -> list[Vulnerability]:
        return [
            vulnerability
            for vulnerability in self.vulnerabilities
            if any(
                (rule_id, vulnerability.file) in self.findings
                for rule_id in vulnerability.rule_ids
            )
        ]

    @property
    def undetected(self) -> list[Vulnerability]:
        detected_ids = {vulnerability.id for vulnerability in self.detected}
        return [
            vulnerability
            for vulnerability in self.vulnerabilities
            if vulnerability.id not in detected_ids
        ]

    @property
    def unassociated_findings(self) -> set[FindingKey]:
        mapped = {
            (rule_id, vulnerability.file)
            for vulnerability in self.vulnerabilities
            for rule_id in vulnerability.rule_ids
        }
        return self.findings - mapped

    @property
    def passed(self) -> bool:
        """Only analysis failures fail the benchmark; missed cases are informative."""
        return not self.analysis_errors


def _validate_relative_file(file_path: object, prefix: str) -> str:
    if not isinstance(file_path, str) or not file_path:
        raise ValueError(f"{prefix}: 'file' doit être une chaîne non vide.")
    if (
        "\\" in file_path
        or PurePosixPath(file_path).is_absolute()
        or PureWindowsPath(file_path).is_absolute()
        or PureWindowsPath(file_path).drive
        or ".." in PurePosixPath(file_path).parts
    ):
        raise ValueError(f"{prefix}: 'file' doit être un chemin relatif sûr.")
    return PurePosixPath(file_path).as_posix()


def load_vulnerabilities(project_dir: Path) -> list[Vulnerability]:
    """Load and validate a project's vulnerability-oriented expected.json."""
    manifest_path = project_dir / "expected.json"
    try:
        with manifest_path.open(encoding="utf-8") as manifest_file:
            manifest = json.load(manifest_file)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{manifest_path}: JSON invalide : {exc}") from exc

    if (
        not isinstance(manifest, dict)
        or type(manifest.get("version")) is not int
        or manifest["version"] != 2
    ):
        raise ValueError(
            f"{manifest_path}: le champ 'version' doit être égal à 2."
        )
    if set(manifest) != {"version", "vulnerabilities"}:
        raise ValueError(
            f"{manifest_path}: les seuls champs permis sont 'version' et "
            "'vulnerabilities'."
        )
    entries = manifest.get("vulnerabilities")
    if not isinstance(entries, list):
        raise ValueError(
            f"{manifest_path}: le champ 'vulnerabilities' doit être une liste."
        )

    vulnerabilities = []
    seen_ids = set()
    for index, entry in enumerate(entries):
        prefix = f"{manifest_path}: vulnerabilities[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{prefix} doit être un objet.")
        if set(entry) != {"id", "title", "file", "rule_ids"}:
            raise ValueError(
                f"{prefix} doit contenir exactement 'id', 'title', 'file' "
                "et 'rule_ids'."
            )

        vulnerability_id = entry.get("id")
        title = entry.get("title")
        if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
            raise ValueError(f"{prefix}: 'id' doit être une chaîne non vide.")
        if vulnerability_id in seen_ids:
            raise ValueError(f"{prefix}: identifiant dupliqué : {vulnerability_id!r}.")
        seen_ids.add(vulnerability_id)
        if not isinstance(title, str) or not title.strip():
            raise ValueError(f"{prefix}: 'title' doit être une chaîne non vide.")
        file_path = _validate_relative_file(entry.get("file"), prefix)
        rule_ids = entry.get("rule_ids")
        if (
            not isinstance(rule_ids, list)
            or any(not isinstance(rule_id, str) or not rule_id.strip() for rule_id in rule_ids)
            or len(set(rule_ids)) != len(rule_ids)
        ):
            raise ValueError(
                f"{prefix}: 'rule_ids' doit être une liste de chaînes "
                "non vides et sans doublons."
            )
        vulnerabilities.append(
            Vulnerability(
                vulnerability_id,
                title,
                file_path,
                tuple(rule_ids),
            )
        )

    return vulnerabilities


def run_project(
    project_dir: Path,
    strategies: tuple[str, ...],
) -> ProjectResult:
    """Analyze a project and merge alerts without retaining their strategy."""
    vulnerabilities = load_vulnerabilities(project_dir)
    analyzer = PythonAnalyzer()
    files = analyzer.get_files(str(project_dir), recursive=True)
    findings: set[FindingKey] = set()
    analysis_errors = []

    if not files:
        analysis_errors.append("aucun fichier Python à analyser")

    for strategy in strategies:
        result = analyzer.analyze_strategy(strategy, files)
        if result.status != "completed":
            analysis_errors.append(f"{strategy}: statut {result.status}")
        analysis_errors.extend(
            f"{strategy}: {diagnostic.code}: {diagnostic.message}"
            for diagnostic in result.diagnostics
        )
        for finding in result.findings:
            if finding.location is None:
                relative_file = "<unknown>"
            else:
                finding_path = Path(finding.location.file).resolve()
                try:
                    relative_file = finding_path.relative_to(
                        project_dir.resolve()
                    ).as_posix()
                except ValueError:
                    relative_file = "<outside-project>"
            findings.add((finding.rule_id, relative_file))

    return ProjectResult(
        project_dir.name,
        vulnerabilities,
        findings,
        analysis_errors,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Signale les vulnérabilités trouvées dans les projets benchmark."
    )
    parser.add_argument(
        "--projects-dir",
        type=Path,
        default=DEFAULT_PROJECTS_DIR,
        help="Dossier contenant les projets benchmark (défaut : tests/project/python).",
    )
    parser.add_argument(
        "--projects",
        nargs="+",
        help="Noms des projets à analyser (défaut : tous les sous-dossiers).",
    )
    parser.add_argument(
        "--strategies",
        nargs="+",
        choices=tuple(STRATEGIES),
        default=DEFAULT_STRATEGIES,
        help="Stratégies à exécuter (défaut : les trois stratégies implémentées).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    projects_dir = args.projects_dir.resolve()
    if not projects_dir.is_dir():
        print(f"Dossier de projets introuvable : {projects_dir}", file=sys.stderr)
        return 2

    project_dirs = (
        [projects_dir / name for name in args.projects]
        if args.projects
        else sorted(path for path in projects_dir.iterdir() if path.is_dir())
    )
    if not project_dirs:
        print(f"Aucun projet trouvé dans {projects_dir}", file=sys.stderr)
        return 2
    missing = [path.name for path in project_dirs if not path.is_dir()]
    if missing:
        print(
            "Projet(s) introuvable(s) : " + ", ".join(missing),
            file=sys.stderr,
        )
        return 2

    try:
        results = [
            run_project(path, tuple(args.strategies))
            for path in project_dirs
        ]
    except (OSError, ValueError) as exc:
        print(f"Impossible d'exécuter le benchmark : {exc}", file=sys.stderr)
        return 2

    print(f"Benchmark SASToy — {len(results)} projet(s)")
    for result in results:
        status = "OK" if result.passed else "ERREUR"
        print(
            f"{result.name}: {status} | "
            f"{len(result.detected)}/{len(result.vulnerabilities)} "
            "vulnérabilité(s) repérée(s)"
        )
        for vulnerability in result.detected:
            print(f"  TROUVÉE: {vulnerability.id} — {vulnerability.title}")
        for vulnerability in result.undetected:
            print(f"  NON REPÉRÉE: {vulnerability.id} — {vulnerability.title}")
        for rule_id, file_path in sorted(result.unassociated_findings):
            print(f"  SIGNAL NON ASSOCIÉ: {rule_id} / {file_path}")
        for error in result.analysis_errors:
            print(f"  ERREUR: {error}")

    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
