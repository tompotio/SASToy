import json
from pathlib import Path

import pytest

from benchmark import load_vulnerabilities, run_project


PROJECT_ROOT = Path(__file__).resolve().parents[2]
IMPLEMENTED_STRATEGIES = ("ast_pattern_scan", "taint_analysis", "secret_scan")


def test_project_a_vulnerabilities_are_found_without_strategy_labels():
    result = run_project(
        PROJECT_ROOT / "tests" / "project" / "python" / "A",
        IMPLEMENTED_STRATEGIES,
    )

    assert result.passed
    assert len(result.vulnerabilities) == 9
    assert len(result.detected) == 9
    assert not result.undetected
    assert not result.unassociated_findings


def test_project_b_detects_security_rules_and_declares_logic_scenarios():
    result = run_project(
        PROJECT_ROOT / "tests" / "project" / "python" / "B",
        IMPLEMENTED_STRATEGIES,
    )

    assert result.passed
    assert len(result.vulnerabilities) == 9
    assert [vulnerability.id for vulnerability in result.detected] == [
        "weak-message-signature",
        "unsafe-shared-state-deserialization",
        "shared-file-command-injection",
        "unsafe-shared-archive-extraction",
        "shared-document-path-traversal",
    ]
    assert [vulnerability.id for vulnerability in result.undetected] == [
        "alias-authorization-confusion",
        "preview-host-suffix-validation",
        "cross-organization-role-change",
        "stale-publication-authorization",
    ]
    assert not result.unassociated_findings


def test_selected_strategy_reports_subset_without_changing_manifest():
    project_dir = PROJECT_ROOT / "tests" / "project" / "python" / "A"
    ast_only = run_project(project_dir, ("ast_pattern_scan",))
    all_strategies = run_project(project_dir, IMPLEMENTED_STRATEGIES)

    assert ast_only.passed
    assert len(ast_only.vulnerabilities) == 9
    assert len(ast_only.detected) == 4
    assert len(ast_only.undetected) == 5
    assert len(all_strategies.detected) == 9


def test_manifest_rejects_paths_outside_project(tmp_path):
    manifest = {
        "version": 2,
        "vulnerabilities": [
            {
                "id": "unsafe-path",
                "title": "Chemin invalide",
                "file": "../outside.py",
                "rule_ids": [],
            }
        ],
    }
    (tmp_path / "expected.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="chemin relatif sûr"):
        load_vulnerabilities(tmp_path)


def test_manifest_rejects_duplicate_vulnerability_ids(tmp_path):
    vulnerability = {
        "id": "duplicate",
        "title": "Scénario",
        "file": "sample.py",
        "rule_ids": [],
    }
    (tmp_path / "expected.json").write_text(
        json.dumps(
            {
                "version": 2,
                "vulnerabilities": [vulnerability, vulnerability],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="identifiant dupliqué"):
        load_vulnerabilities(tmp_path)


def test_undetected_vulnerability_is_reported_without_failing(tmp_path):
    (tmp_path / "sample.py").write_text(
        "def calculate(value):\n    return eval(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "expected.json").write_text(
        json.dumps(
            {
                "version": 2,
                "vulnerabilities": [
                    {
                        "id": "declared-but-not-detected",
                        "title": "Détection volontairement non correspondante",
                        "file": "sample.py",
                        "rule_ids": ["UNSAFE_EXEC"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_project(tmp_path, ("ast_pattern_scan",))

    assert result.passed
    assert not result.detected
    assert [item.id for item in result.undetected] == [
        "declared-but-not-detected"
    ]
    assert result.unassociated_findings == {("UNSAFE_EVAL", "sample.py")}
