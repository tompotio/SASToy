"""Compatibility entry point for the refactored SASToy modules.

Run this module directly to invoke the command-line interface, or import the
re-exported names to keep using the original scanner API.
"""

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analyzers.python import (  # noqa: E402
    FunctionCallVisitor,
    PythonAnalyzer,
    SECURITY_FUNCTION_CALLS_RULES,
)
from src.integrity import (  # noqa: E402
    calculate_hash,
    calculate_md5,
    calculate_sha1,
    calculate_sha256,
    extract_metadata,
    extract_official_checksum,
    run_hash_verification,
    search_official_checksum,
    validate_hash,
    verify_file_hash,
)
from src.main import main  # noqa: E402

get_python_files = PythonAnalyzer.get_files
parse_python_file = PythonAnalyzer.parse_python_file
is_python_check = PythonAnalyzer.is_python_check
analyse_fonctions_vul = PythonAnalyzer.analyse_fonctions_vul
detect_hardcoded_secrets = PythonAnalyzer.detect_hardcoded_secrets


if __name__ == "__main__":
    sys.exit(main())
