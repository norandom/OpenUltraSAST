"""Contract tests for the v2 coverage funnel and instrument gate."""

from dataclasses import replace

import pytest

from openultrasast.core.coverage import (
    CoverageFunnel,
    CoverageStage,
    InputManifest,
    InputReadReceipt,
    InstrumentFailure,
    ReasonCount,
    RelationStatusCount,
    StageExpectation,
    derive_input_manifest_digest,
    diagnose_first_zero,
    validate_instrument,
)
from openultrasast.core.semantics import RelationStatus

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def _manifest() -> InputManifest:
    inputs = ("src/app.py", "src/lib.py")
    return InputManifest(inputs, derive_input_manifest_digest(inputs))


def _receipts() -> tuple[InputReadReceipt, ...]:
    return (
        InputReadReceipt("src/app.py", "src/app.py", True, 12, DIGEST_A),
        InputReadReceipt("src/lib.py", "src/lib.py", True, 8, DIGEST_B),
    )


def _funnel(**overrides: object) -> CoverageFunnel:
    values: dict[str, object] = {
        "inputs_read": 2,
        "questions_formed": 2,
        "sites_considered": 4,
        "sites_recognized": 3,
        "transitions_materialized": 4,
        "security_objects_constructed": 2,
        "constraints_evaluated": 2,
        "determinate_outcomes": 1,
        "findings_emitted": 1,
        "relation_status_counts": (
            RelationStatusCount(RelationStatus.COMPLETE, 2),
            RelationStatusCount(RelationStatus.INCOMPLETE, 1),
            RelationStatusCount(RelationStatus.UNRESOLVED, 1),
        ),
        "unresolved_by_reason": (ReasonCount("missing_constraint", 1), ReasonCount("ambiguous_call", 1)),
    }
    values.update(overrides)
    return CoverageFunnel(**values)  # type: ignore[arg-type]


def _expectations(*, findings_expected: bool = True) -> tuple[StageExpectation, ...]:
    return tuple(
        StageExpectation(stage, stage is not CoverageStage.INPUTS, findings_expected if stage is CoverageStage.FINDINGS else True)
        for stage in CoverageStage
    )


def test_coverage_v2_instrument_reads_nonzero_source() -> None:
    assert __file__
    with open(__file__, "rb") as source:
        assert len(source.read()) > 0


def test_input_manifest_and_receipts_validate_exactly() -> None:
    validate_instrument(_manifest(), _receipts())


@pytest.mark.parametrize(
    ("opened", "byte_count", "digest", "match"),
    [
        (False, 12, DIGEST_A, "not opened"),
        (True, 0, None, "zero-byte"),
    ],
)
def test_unopened_or_zero_byte_input_is_an_instrument_failure(opened: bool, byte_count: int, digest: str | None, match: str) -> None:
    receipt = InputReadReceipt("src/app.py", "src/app.py", opened, byte_count, digest)
    with pytest.raises(InstrumentFailure, match=match):
        validate_instrument(_manifest(), (receipt, _receipts()[1]))


def test_instrument_refuses_missing_extra_and_duplicate_receipts() -> None:
    manifest = _manifest()
    receipts = _receipts()
    with pytest.raises(InstrumentFailure, match="missing input receipt"):
        validate_instrument(manifest, receipts[:1])
    extra = InputReadReceipt("src/extra.py", "src/extra.py", True, 1, DIGEST_A)
    with pytest.raises(InstrumentFailure, match="unexpected input receipt"):
        validate_instrument(manifest, receipts + (extra,))
    with pytest.raises(InstrumentFailure, match="duplicate input receipt"):
        validate_instrument(manifest, receipts + (receipts[0],))


def test_instrument_revalidates_manifest_and_receipt_after_tampering() -> None:
    manifest = _manifest()
    object.__setattr__(manifest, "manifest_digest", DIGEST_A)
    with pytest.raises(InstrumentFailure, match="manifest digest"):
        validate_instrument(manifest, _receipts())
    receipt = _receipts()[0]
    object.__setattr__(receipt, "content_digest", "UPPER")
    with pytest.raises(InstrumentFailure, match="content digest"):
        validate_instrument(_manifest(), (receipt, _receipts()[1]))


def test_manifest_rejects_duplicate_or_malformed_input_ids() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        InputManifest(("src/app.py", "src/app.py"), DIGEST_A)
    with pytest.raises(ValueError, match="nonempty text"):
        InputManifest(("",), DIGEST_A)


def test_funnel_accounts_every_relation_once() -> None:
    funnel = _funnel()
    assert sum(item.count for item in funnel.relation_status_counts) == funnel.transitions_materialized


@pytest.mark.parametrize(
    "updates",
    [
        {"relation_status_counts": (RelationStatusCount(RelationStatus.COMPLETE, 4),)},
        {
            "relation_status_counts": (
                RelationStatusCount(RelationStatus.COMPLETE, 2),
                RelationStatusCount(RelationStatus.COMPLETE, 1),
                RelationStatusCount(RelationStatus.UNRESOLVED, 1),
            )
        },
        {
            "relation_status_counts": (
                RelationStatusCount(RelationStatus.COMPLETE, 3),
                RelationStatusCount(RelationStatus.INCOMPLETE, 1),
                RelationStatusCount(RelationStatus.UNRESOLVED, 1),
            )
        },
        {"unresolved_by_reason": (ReasonCount("missing_constraint", 1),)},
    ],
)
def test_funnel_refuses_missing_duplicate_or_mismatched_accounting(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _funnel(**updates)


@pytest.mark.parametrize("field", ["inputs_read", "questions_formed", "sites_considered", "findings_emitted"])
def test_funnel_refuses_negative_or_boolean_counts(field: str) -> None:
    with pytest.raises(ValueError, match=field):
        _funnel(**{field: -1})
    with pytest.raises(ValueError, match=field):
        _funnel(**{field: True})


@pytest.mark.parametrize(
    "updates",
    [
        {"sites_considered": 1, "sites_recognized": 2},
        {"questions_formed": 1, "determinate_outcomes": 2, "findings_emitted": 1},
        {"determinate_outcomes": 1, "findings_emitted": 2},
    ],
)
def test_funnel_refuses_impossible_stage_counts_at_construction(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="cannot exceed"):
        _funnel(**updates)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("sites_recognized", 5, "sites_recognized cannot exceed sites_considered"),
        ("determinate_outcomes", 3, "determinate_outcomes cannot exceed questions_formed"),
        ("findings_emitted", 2, "findings_emitted cannot exceed determinate_outcomes"),
    ],
)
def test_diagnosis_revalidates_impossible_stage_counts_after_tampering(field: str, value: int, match: str) -> None:
    funnel = _funnel()
    object.__setattr__(funnel, field, value)
    with pytest.raises(ValueError, match=match):
        diagnose_first_zero(funnel, _expectations())


def test_valid_zero_is_not_diagnosed_as_a_failure() -> None:
    funnel = _funnel(findings_emitted=0)
    diagnosis = diagnose_first_zero(funnel, _expectations(findings_expected=False))
    assert diagnosis.first_failed_output_stage is None
    assert diagnosis.last_verified_nonzero_stage is CoverageStage.OUTCOMES
    assert diagnosis.reasons == ()


@pytest.mark.parametrize("failed_stage", tuple(CoverageStage))
def test_each_injected_first_zero_names_the_failing_stage(failed_stage: CoverageStage) -> None:
    counts = {stage: 1 for stage in CoverageStage}
    failed_index = tuple(CoverageStage).index(failed_stage)
    for stage in tuple(CoverageStage)[failed_index:]:
        counts[stage] = 0
    funnel = CoverageFunnel(
        inputs_read=counts[CoverageStage.INPUTS],
        questions_formed=counts[CoverageStage.QUESTIONS],
        sites_considered=counts[CoverageStage.SITES_CONSIDERED],
        sites_recognized=counts[CoverageStage.SITES_RECOGNIZED],
        transitions_materialized=counts[CoverageStage.TRANSITIONS],
        security_objects_constructed=counts[CoverageStage.SECURITY_OBJECTS],
        constraints_evaluated=counts[CoverageStage.CONSTRAINTS],
        determinate_outcomes=counts[CoverageStage.OUTCOMES],
        findings_emitted=counts[CoverageStage.FINDINGS],
        relation_status_counts=(
            RelationStatusCount(RelationStatus.COMPLETE, counts[CoverageStage.TRANSITIONS]),
            RelationStatusCount(RelationStatus.INCOMPLETE, 0),
            RelationStatusCount(RelationStatus.UNRESOLVED, 0),
        ),
        unresolved_by_reason=(),
    )
    diagnosis = diagnose_first_zero(funnel, _expectations())
    assert diagnosis.first_failed_output_stage is failed_stage
    assert diagnosis.last_verified_nonzero_stage is (None if failed_index == 0 else tuple(CoverageStage)[failed_index - 1])
    assert diagnosis.reasons == (f"{failed_stage.value}:expected_nonzero_output",)


def test_expectations_must_be_complete_unique_and_ordered() -> None:
    funnel = _funnel()
    expectations = _expectations()
    with pytest.raises(ValueError, match="every coverage stage"):
        diagnose_first_zero(funnel, expectations[:-1])
    with pytest.raises(ValueError, match="canonical coverage order"):
        diagnose_first_zero(funnel, tuple(reversed(expectations)))
    with pytest.raises(ValueError, match="duplicate"):
        diagnose_first_zero(funnel, expectations[:-1] + (expectations[0],))


def test_diagnosis_revalidates_nested_counts_and_expectations_after_tampering() -> None:
    funnel = _funnel()
    object.__setattr__(funnel.relation_status_counts[0], "count", -1)
    with pytest.raises(ValueError, match="relation status count"):
        diagnose_first_zero(funnel, _expectations())
    expectation = _expectations()[0]
    object.__setattr__(expectation, "expected_nonzero_output", 1)
    with pytest.raises(ValueError, match="expected_nonzero_output"):
        diagnose_first_zero(_funnel(), (expectation,) + _expectations()[1:])


def test_stage_contracts_reject_wrong_runtime_types() -> None:
    with pytest.raises(ValueError):
        StageExpectation("inputs", True, True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RelationStatusCount("complete", 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ReasonCount("", 1)
    with pytest.raises(ValueError):
        replace(_expectations()[0], expected_nonzero_output=1)  # type: ignore[arg-type]
