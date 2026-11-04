"""Two unlike families traverse the complete synthetic readiness path."""

from __future__ import annotations

import os
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from detection_core_end_to_end import ReferencePathResult, run_reference_family_path

from benchmarks.valid import readiness_contract
from openultrasast.core import canonical
from openultrasast.core.admission_report import AdmissionDecision
from openultrasast.core.custody import PopulationStatus
from openultrasast.core.evidence import NeutralOutcome
from openultrasast.core.readiness import ReadinessEvidenceUse, ReadinessStage, StageResult

FIXTURES = Path(__file__).parent / "fixtures" / "detection_core"


def _copied_obligation_fixture(tmp_path: Path) -> Path:
    fixture_root = tmp_path / "detection-core"
    shutil.copytree(FIXTURES, fixture_root)
    return fixture_root


def _run_obligation(fixture_root: Path, scratch: Path) -> ReferencePathResult:
    return run_reference_family_path(
        fixture_root=fixture_root,
        family_file="obligation_family.json",
        cases_file="obligation_cases.json",
        repository="obligation_repository",
        scratch=scratch,
    )


def _assert_obligation_refused(fixture_root: Path, scratch: Path) -> None:
    with pytest.raises(ValueError, match="source authority"):
        _run_obligation(fixture_root, scratch)
    assert not tuple(scratch.glob("*-labels.json"))


@pytest.mark.parametrize(
    ("family_file", "cases_file", "repository", "family_id", "ecosystem", "silence_reason"),
    (
        (
            "obligation_family.json",
            "obligation_cases.json",
            "obligation_repository",
            "operation-constraint",
            "reference-obligation",
            "missing_constraint_relation",
        ),
        (
            "taint_family.json",
            "taint_cases.json",
            "taint_repository",
            "ordered-taint-flow",
            "reference-flow",
            "missing_flow_segment",
        ),
    ),
)
def test_reference_family_completes_synthetic_readiness_path(
    tmp_path: Path,
    family_file: str,
    cases_file: str,
    repository: str,
    family_id: str,
    ecosystem: str,
    silence_reason: str,
) -> None:
    result = run_reference_family_path(
        fixture_root=FIXTURES,
        family_file=family_file,
        cases_file=cases_file,
        repository=repository,
        scratch=tmp_path,
    )

    _assert_instrument_and_readiness(result, family_id, ecosystem)
    _assert_bounded_outputs(result, silence_reason)
    _assert_reviewed_guarded_admission(result)


def test_replaced_authored_source_is_refused_before_admission(tmp_path: Path) -> None:
    fixture_root = _copied_obligation_fixture(tmp_path)
    source = fixture_root / "obligation_repository/reference/obligation_positive.py"
    source.write_text("def unrelated() -> int:\n    return 7\n")

    _assert_obligation_refused(fixture_root, tmp_path)


def test_swapped_authored_sources_are_refused_before_admission(tmp_path: Path) -> None:
    fixture_root = _copied_obligation_fixture(tmp_path)
    positive = fixture_root / "obligation_repository/reference/obligation_positive.py"
    negative = fixture_root / "obligation_repository/reference/obligation_negative.py"
    positive_bytes, negative_bytes = positive.read_bytes(), negative.read_bytes()
    positive.write_bytes(negative_bytes)
    negative.write_bytes(positive_bytes)

    _assert_obligation_refused(fixture_root, tmp_path)


def test_nested_authority_named_file_is_refused_before_admission(tmp_path: Path) -> None:
    fixture_root = _copied_obligation_fixture(tmp_path)
    nested = fixture_root / "obligation_repository/reference/source_authority.json"
    nested.write_bytes(b"")

    _assert_obligation_refused(fixture_root, tmp_path)


def test_outside_root_authority_symlink_is_refused_without_descriptor_leak(tmp_path: Path) -> None:
    fixture_root = _copied_obligation_fixture(tmp_path)
    manifest = fixture_root / "obligation_repository/source_authority.json"
    outside = tmp_path / "outside-authority.json"
    manifest.rename(outside)
    manifest.symlink_to(outside)
    descriptor_root = Path("/proc/self/fd")
    before = len(tuple(descriptor_root.iterdir()))

    for _attempt in range(5):
        _assert_obligation_refused(fixture_root, tmp_path)

    assert len(tuple(descriptor_root.iterdir())) == before


def test_inside_root_source_symlink_is_refused_before_admission(tmp_path: Path) -> None:
    fixture_root = _copied_obligation_fixture(tmp_path)
    repository = fixture_root / "obligation_repository"
    source = repository / "reference/obligation_positive.py"
    hidden = repository / "reference/source_authority.json"
    source.rename(hidden)
    source.symlink_to(hidden.name)

    _assert_obligation_refused(fixture_root, tmp_path)


def test_outside_root_source_symlink_is_refused_before_admission(tmp_path: Path) -> None:
    fixture_root = _copied_obligation_fixture(tmp_path)
    source = fixture_root / "obligation_repository/reference/obligation_positive.py"
    outside = tmp_path / "outside-source.py"
    source.rename(outside)
    source.symlink_to(outside)

    _assert_obligation_refused(fixture_root, tmp_path)


def test_additional_fifo_is_refused_without_opening_it(tmp_path: Path) -> None:
    fixture_root = _copied_obligation_fixture(tmp_path)
    fifo = fixture_root / "obligation_repository/reference/untracked.pipe"
    os.mkfifo(fifo)

    _assert_obligation_refused(fixture_root, tmp_path)


def test_declared_fifo_is_refused_without_opening_it(tmp_path: Path) -> None:
    fixture_root = _copied_obligation_fixture(tmp_path)
    source = fixture_root / "obligation_repository/reference/obligation_positive.py"
    source.unlink()
    os.mkfifo(source)

    _assert_obligation_refused(fixture_root, tmp_path)


def _assert_instrument_and_readiness(
    result: ReferencePathResult,
    family_id: str,
    ecosystem: str,
) -> None:
    assert result.family_id == family_id
    assert result.ecosystem == ecosystem
    assert result.repository_bytes > 0
    assert result.opened_input_count == 3
    identity = result.readiness[0].identity
    assert identity.acquisition_record_digest == result.source_authority_digest
    assert {item.record.packet.provenance.acquisition_record_digest for item in result.inputs} == {result.source_authority_digest}
    assert tuple(item.record.packet.provenance.change_input_digest for item in result.inputs) == result.source_content_digests
    assert tuple(item.stage for item in result.readiness) == tuple(ReadinessStage)
    assert tuple(item.result for item in result.readiness) == (StageResult.PASSED,) * len(ReadinessStage)
    assert tuple(item.evidence_use for item in result.readiness) == (
        ReadinessEvidenceUse.REGRESSION_FIXTURE,
        ReadinessEvidenceUse.REGRESSION_FIXTURE,
        ReadinessEvidenceUse.REGRESSION_FIXTURE,
        ReadinessEvidenceUse.REGRESSION_FIXTURE,
        ReadinessEvidenceUse.REGRESSION_FIXTURE,
        ReadinessEvidenceUse.DEVELOPMENT_POPULATION,
        ReadinessEvidenceUse.FRESH_ADMISSION,
        ReadinessEvidenceUse.CONSUMER_INTEGRATION,
    )
    for index, item in enumerate(result.readiness):
        assert item.predecessor_digests == tuple(prior.result_digest for prior in result.readiness[:index])
        assert item.identity == result.readiness[0].identity
    changed_identity = replace(identity, acquisition_record_digest=canonical.content_digest("different-source-authority"))
    with pytest.raises(readiness_contract.ReadinessBlocked, match="readiness is stale"):
        readiness_contract.require_stage_authorized(ReadinessStage.ADMISSION, result.readiness[:6], changed_identity)


def _assert_bounded_outputs(result: ReferencePathResult, silence_reason: str) -> None:
    assert tuple(item.record.decision.outcome for item in result.inputs) == (
        NeutralOutcome.VIOLATION,
        NeutralOutcome.SATISFIED,
        NeutralOutcome.INDETERMINATE,
    )
    assert tuple((len(item.defects), len(item.satisfactions), len(item.silence)) for item in result.verdicts) == (
        (1, 0, 0),
        (0, 1, 0),
        (0, 0, 1),
    )
    assert result.verdicts[2].silence[0].reasons == (silence_reason,)
    assert all(item.total_reply_ms > 0 for item in result.verdicts)


def _assert_reviewed_guarded_admission(result: ReferencePathResult) -> None:
    replay = result.admission
    assert replay.manifest.label_isolated is True
    assert replay.manifest.labels_opened is False
    assert replay.manifest.review.producer_identity != replay.manifest.review.reviewer_identity
    assert replay.label_release_receipt.status is PopulationStatus.SPENT
    assert replay.report.decision is AdmissionDecision.GO
    assert result.population_status_at_label_read is PopulationStatus.SPENT
    assert result.label_read_count == 1
    assert replay.readiness == result.readiness[:6]
    references = tuple(
        (reference.stage, reference.result, reference.result_digest) for reference in replay.report.measurement.prerequisite_readiness
    )
    expected = tuple((item.stage, item.result, item.result_digest) for item in replay.readiness)
    assert references == expected
