import ast
from io import StringIO

import pytest
from rich.console import Console

from src.analyzers.python import FunctionCallVisitor, PythonAnalyzer


def scan(source):
    visitor = FunctionCallVisitor("sample.py")
    visitor.visit(ast.parse(source))
    return visitor.findings


def test_detects_qualified_calls_and_import_aliases():
    findings = scan(
        "import subprocess as sp\n"
        "from os import system as run_command\n"
        "sp.run('echo ok', shell=True)\n"
        "run_command('echo ok')\n"
    )

    assert [finding["rule_key"] for finding in findings] == [
        "SUBPROCESS_SHELL_TRUE",
        "OS_COMMAND_EXECUTION",
    ]


def test_subprocess_call_without_shell_true_is_not_reported():
    assert scan("import subprocess\nsubprocess.run(['echo', 'ok'])") == []


def test_yaml_safe_loader_is_not_reported_but_unrestricted_load_is():
    findings = scan(
        "import yaml\n"
        "from yaml import SafeLoader\n"
        "yaml.load(document, Loader=yaml.SafeLoader)\n"
        "yaml.load(document, Loader=SafeLoader)\n"
        "yaml.load(document)\n"
    )

    assert [finding["rule_key"] for finding in findings] == [
        "UNSAFE_YAML_LOAD"
    ]
    assert findings[0]["line"] == 5


def test_detects_pickle_and_tar_extraction_signals():
    findings = scan(
        "from pickle import loads as decode\n"
        "archive.extractall(destination)\n"
        "decode(payload)\n"
    )

    assert [finding["rule_key"] for finding in findings] == [
        "TARFILE_EXTRACTALL",
        "PICKLE_UNSAFE_LOAD",
    ]


def test_dependency_advisories_are_not_mistaken_for_ast_call_rules():
    assert scan("import requests\nrequests.get(url)") == []


def test_security_signals_operation_dispatches(monkeypatch):
    analyzed_files = []
    monkeypatch.setattr(
        PythonAnalyzer,
        "analyse_signaux_securite",
        staticmethod(analyzed_files.extend),
    )

    PythonAnalyzer().analyze_operation(
        "security_signals",
        ["sample.py"],
        Console(file=StringIO()),
    )

    assert analyzed_files == ["sample.py"]
