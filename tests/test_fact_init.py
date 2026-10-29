"""Tasks 11.3 + 11.4: extraction and verified promotion of target knowledge (Reqs 2.9, 2.10).

Extraction reads the legacy recognition strategies and the promoted fact rows and
returns deterministic candidate records carrying source, version and region
evidence. It never modifies promoted outputs. Verification and promotion accept
only evidence-complete, non-contradicting proposals; rejected proposals leave the
promoted corpus unchanged.
"""

import hashlib
import re
from pathlib import Path

import pytest

from openultrasast.tools.fact_init import (
    AcquisitionRecord,
    AdmissionLabelsExposed,
    CandidateRecord,
    PromotionResult,
    acquire,
    extract_all,
    extract_fact_rows,
    extract_legacy_strategies,
    population_is_spent,
    promote_proposals,
    verify_candidate,
)

REPO_ROOT = Path(__file__).parents[1]
RULESET_DIR = REPO_ROOT / "src" / "openultrasast" / "ruleset" / "obligations"
MAPPING_FILE = REPO_ROOT / "src" / "openultrasast" / "mapping" / "legacy.py"

_VERSION_PATTERN = re.compile(r"^[0-9a-f]{12}$")


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def _digest_dir(directory: Path) -> dict[str, str]:
    return {path.name: _file_digest(path) for path in sorted(directory.glob("*.toml"))}


def _proposal(
    name: str = "proposed-read", payload: tuple[tuple[str, str], ...] = (("calls", "read"), ("kind", "protected_read"))
) -> CandidateRecord:
    return CandidateRecord(
        kind="operation",
        name=name,
        source="docs/target.md",
        version="a1b2c3d4e5f6",
        region="docs/target.md:proposed-read",
        payload=payload,
    )


def _promoted_corpus() -> tuple[CandidateRecord, ...]:
    return (
        CandidateRecord(
            kind="operation",
            name="promoted-read",
            source="src/openultrasast/ruleset/obligations/java.toml",
            version="0123456789ab",
            region="java.toml:operation:promoted-read",
            payload=(("calls", "read"), ("kind", "protected_read")),
        ),
    )


def test_verified_novel_proposal_is_accepted_and_promoted() -> None:
    promoted = _promoted_corpus()
    is_valid, reason = verify_candidate(_proposal(), promoted)
    assert is_valid is True
    assert reason is None
    result = promote_proposals((_proposal(),), promoted)
    assert result.accepted == (_proposal(),)
    assert result.rejected == ()
    assert _proposal() in result.promoted_after
    assert promoted[0] in result.promoted_after


def test_contradicted_proposal_is_rejected_and_promoted_knowledge_unchanged() -> None:
    promoted = _promoted_corpus()
    contradicted = CandidateRecord(
        kind="operation",
        name="promoted-read",
        source="docs/target.md",
        version="a1b2c3d4e5f6",
        region="docs/target.md:promoted-read",
        payload=(("calls", "write"),),
    )
    is_valid, reason = verify_candidate(contradicted, promoted)
    assert is_valid is False
    assert reason is not None and reason.startswith("contradicts-promoted")
    result = promote_proposals((contradicted,), promoted)
    assert result.rejected[0][0] == contradicted
    assert result.promoted_after == promoted


def test_evidence_free_proposal_is_rejected() -> None:
    promoted = _promoted_corpus()
    for broken in (
        _proposal().__class__(**{**_proposal().__dict__, "source": ""}),
        CandidateRecord(kind="operation", name="x", source="s", version="short", region="r"),
        CandidateRecord(kind="operation", name="y", source="s", version="a1b2c3d4e5f6", region=""),
    ):
        is_valid, reason = verify_candidate(broken, promoted)
        assert is_valid is False
        assert reason is not None and reason.startswith("missing-evidence")
    result = promote_proposals(
        (CandidateRecord(kind="operation", name="z", source="", version="a1b2c3d4e5f6", region="r"),),
        promoted,
    )
    assert result.promoted_after == promoted


def test_exact_match_proposal_is_accepted_without_duplicate() -> None:
    promoted = _promoted_corpus()
    twin = CandidateRecord(
        kind="operation",
        name="promoted-read",
        source="docs/target.md",
        version="a1b2c3d4e5f6",
        region="docs/target.md:promoted-read",
        payload=promoted[0].payload,
    )
    result = promote_proposals((twin,), promoted)
    assert result.accepted == (twin,)
    assert result.rejected == ()
    same_knowledge = [record for record in result.promoted_after if record.kind == twin.kind and record.name == twin.name]
    assert len(same_knowledge) == 1
    assert len(result.promoted_after) == len(promoted)


def test_rejected_proposals_never_modify_promoted_corpus() -> None:
    promoted = _promoted_corpus()
    contradicted = CandidateRecord(
        kind="operation",
        name="promoted-read",
        source="docs/target.md",
        version="a1b2c3d4e5f6",
        region="docs/target.md:promoted-read",
        payload=(("calls", "purge"),),
    )
    result = promote_proposals((_proposal(), contradicted), promoted)
    assert result.accepted == (_proposal(),)
    assert len(result.rejected) == 1
    assert contradicted not in result.promoted_after
    assert promoted[0] in result.promoted_after


def test_promotion_is_deterministic() -> None:
    promoted = _promoted_corpus()
    first = promote_proposals((_proposal(),), promoted)
    second = promote_proposals((_proposal(),), promoted)
    assert first == second
    assert isinstance(first, PromotionResult)


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


def test_label_blind_acquire_records_provenance() -> None:
    record = acquire((_proposal(), _contradicted_proposal()), _promoted_corpus())
    assert isinstance(record, AcquisitionRecord)
    assert _VERSION_PATTERN.fullmatch(record.input_revision)
    assert _VERSION_PATTERN.fullmatch(record.evidence_digest)
    assert _VERSION_PATTERN.fullmatch(record.output_digest)
    assert record.accepted_names == ("proposed-read",)
    assert record.rejected_names == ("promoted-read",)


def test_admission_labels_are_rejected_before_promotion() -> None:
    promoted = _promoted_corpus()
    with pytest.raises(AdmissionLabelsExposed):
        acquire((_proposal(),), promoted, input_labels=("vulnerability-fix-label",))
    assert promoted == _promoted_corpus()


def test_every_forbidden_marker_raises() -> None:
    for label in ("fix-location:Handler.java:4", "ordinary-change:repo-a", "vulnerability:case-9"):
        with pytest.raises(AdmissionLabelsExposed):
            acquire((_proposal(),), _promoted_corpus(), input_labels=(label,))


def test_acquire_is_deterministic() -> None:
    first = acquire((_proposal(),), _promoted_corpus())
    second = acquire((_proposal(),), _promoted_corpus())
    assert first == second


def test_population_is_spent_detects_output_change() -> None:
    blind = acquire((_proposal(),), _promoted_corpus())
    assert population_is_spent(blind, blind.output_digest) is False
    assert population_is_spent(blind, "0" * 12) is True


def test_acquisition_record_is_frozen() -> None:
    record = acquire((_proposal(),), _promoted_corpus())
    with pytest.raises(Exception):  # noqa: B017
        record.output_digest = "0" * 12  # type: ignore[misc]


def _contradicted_proposal() -> CandidateRecord:
    return CandidateRecord(
        kind="operation",
        name="promoted-read",
        source="proposals.toml",
        version="a" * 12,
        region="proposals.toml:operation:promoted-read",
        payload=(("calls", "write"), ("kind", "protected_read")),
    )
