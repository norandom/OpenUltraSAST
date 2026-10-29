"""Task 11.3: extraction of existing target knowledge into candidate records (Req 2.9).

Extraction reads the legacy recognition strategies and the promoted fact rows and
returns deterministic candidate records carrying source, version and region
evidence. It never modifies promoted outputs.
"""

import hashlib
import re
from pathlib import Path

import pytest

from openultrasast.tools.fact_init import (
    CandidateRecord,
    extract_all,
    extract_fact_rows,
    extract_legacy_strategies,
)

REPO_ROOT = Path(__file__).parents[1]
RULESET_DIR = REPO_ROOT / "src" / "openultrasast" / "ruleset" / "obligations"
MAPPING_FILE = REPO_ROOT / "src" / "openultrasast" / "mapping" / "legacy.py"

_VERSION_PATTERN = re.compile(r"^[0-9a-f]{12}$")


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def _digest_dir(directory: Path) -> dict[str, str]:
    return {path.name: _file_digest(path) for path in sorted(directory.glob("*.toml"))}


def test_fact_rows_extraction_yields_operation_and_discharger_records() -> None:
    records = extract_fact_rows(RULESET_DIR)
    kinds = {record.kind for record in records}
    assert "operation" in kinds
    assert "discharger" in kinds
    assert records


def test_extraction_includes_java_operation_rows() -> None:
    records = extract_fact_rows(RULESET_DIR)
    java_operations = [record for record in records if record.kind == "operation" and record.source.endswith("java.toml")]
    assert java_operations


def test_legacy_strategy_extraction_names_recognisers() -> None:
    records = extract_legacy_strategies(MAPPING_FILE)
    names = {record.name for record in records}
    assert "_stapler_entries" in names
    assert "_jetty_entries" in names
    assert "_python_registered_routes" in names
    for record in records:
        assert record.region.startswith("legacy.py:")


def test_every_candidate_carries_source_version_and_region() -> None:
    records = extract_all(REPO_ROOT)
    assert records
    for record in records:
        assert record.source
        assert _VERSION_PATTERN.match(record.version)
        assert ":" in record.region


def test_version_digest_is_file_derived_and_stable() -> None:
    first = extract_fact_rows(RULESET_DIR)
    second = extract_fact_rows(RULESET_DIR)
    java_rows = [record for record in first if record.source.endswith("java.toml")]
    assert java_rows
    expected = _file_digest(RULESET_DIR / "java.toml")
    assert all(record.version == expected for record in java_rows)
    assert first == second


def test_extraction_is_deterministic_and_sorted() -> None:
    first = extract_all(REPO_ROOT)
    second = extract_all(REPO_ROOT)
    assert first == second
    keys = [(record.kind, record.name, record.region) for record in first]
    assert keys == sorted(keys)


def test_extraction_changes_no_promoted_outputs() -> None:
    from openultrasast.mapping import registry

    tomls_before = _digest_dir(RULESET_DIR)
    mapping_before = _file_digest(MAPPING_FILE)
    strategies_before = len(registry._STRATEGIES)

    extract_all(REPO_ROOT)

    assert _digest_dir(RULESET_DIR) == tomls_before
    assert _file_digest(MAPPING_FILE) == mapping_before
    assert len(registry._STRATEGIES) == strategies_before


def test_operation_payload_carries_row_fields() -> None:
    records = extract_fact_rows(RULESET_DIR)
    java_operations = [record for record in records if record.kind == "operation" and record.source.endswith("java.toml")]
    fields = {name for name, _ in java_operations[0].payload}
    assert "calls" in fields
    assert "kind" in fields


def test_candidate_record_is_frozen() -> None:
    record = CandidateRecord(
        kind="operation",
        name="example",
        source="java.toml",
        version="0" * 12,
        region="java.toml:operations:example",
        payload=(("language", "java"),),
    )
    with pytest.raises(Exception):  # noqa: B017
        record.name = "other"  # type: ignore[misc]
