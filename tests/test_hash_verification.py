import io

import pytest
from rich.console import Console

from src.scanner import (
    calculate_md5,
    calculate_sha1,
    calculate_sha256,
    extract_official_checksum,
    validate_hash,
    verify_file_hash,
)


@pytest.mark.parametrize(
    ("calculator", "expected"),
    [
        (calculate_md5, "900150983cd24fb0d6963f7d28e17f72"),
        (calculate_sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            calculate_sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ],
)
def test_hash_calculators(tmp_path, calculator, expected):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    assert calculator(str(sample)) == expected


def test_validate_hash_normalizes_case():
    assert validate_hash("A9993E364706816ABA3E25717850C26C9CD0D89D", "sha1") == (
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    )


def test_validate_hash_rejects_wrong_length():
    with pytest.raises(ValueError, match="exactement 32"):
        validate_hash("abcd", "md5")


def test_extract_official_checksum_requires_explicit_checksum():
    checksum = "a9993e364706816aba3e25717850c26c9cd0d89d"

    assert extract_official_checksum(
        f"Source: https://publisher.example\nOFFICIAL_CHECKSUM: {checksum}",
        "sha1",
    ) == checksum

    with pytest.raises(ValueError, match="Un seul haché officiel"):
        extract_official_checksum("OFFICIAL_CHECKSUM: NONE", "sha1")

    with pytest.raises(ValueError, match="Un seul haché officiel"):
        extract_official_checksum(
            f"OFFICIAL_CHECKSUM: {checksum}\nOFFICIAL_CHECKSUM: {checksum}",
            "sha1",
        )


def test_verify_file_hash_reports_match_and_mismatch(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    console_output = io.StringIO()
    console = Console(file=console_output, force_terminal=False)

    assert verify_file_hash(
        str(sample),
        "md5",
        "900150983cd24fb0d6963f7d28e17f72",
        console,
    )
    assert not verify_file_hash(str(sample), "md5", "0" * 32, console)
    assert "CONFORME" in console_output.getvalue()
    assert "NON CONFORME" in console_output.getvalue()
