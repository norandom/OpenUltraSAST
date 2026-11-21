"""Task 8.6 post-spend recovery of the same immutable sealed run."""

from __future__ import annotations

from dataclasses import dataclass

from benchmarks.valid.arm_contract import RegisteredEvaluationPlanV1
from benchmarks.valid.artifact_repository import S3ArtifactRepository
from benchmarks.valid.durable_custody_store import S3DurableCustodyStore
from benchmarks.valid.isolated_execution_bundle import LabelBlindExecutionBundleV1
from benchmarks.valid.observation_checkpoint import CheckpointSelectorV1
from benchmarks.valid.sealed_retry import (
    AutomaticRetryAuthorityReason,
    AutomaticRetryError,
    _actual_retry_identity,
    _digest,
    build_automatic_retry_identity,
    resolve_head_selected_retry_authority,
    retry_identity_matches_authority,
)
from benchmarks.valid.workflow_journal import S3WorkflowJournal
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue
from openultrasast.core.custody import PopulationStatus

SPENT_RUN_RESUME_SCHEMA = "openultrasast.valid-detection-benchmark.spent-run-resume.v1"


@dataclass(frozen=True)
class SpentRunResumeV1:
    """Post-spend resume product: the committed run stays spent and immutable."""

    authority_digest: str
    retry_digest: str
    population_digest: str
    freeze_digest: str
    labels_spent: bool
    custody_receipt_digest: str | None
    resume_digest: str

    def __post_init__(self) -> None:
        if type(self) is not SpentRunResumeV1 or self.labels_spent is not True:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
        for value in (self.authority_digest, self.retry_digest, self.population_digest, self.freeze_digest):
            _digest(value)
        if self.custody_receipt_digest is not None:
            _digest(self.custody_receipt_digest)
        expected = canonical.content_digest(_resume_value(self, include_digest=False))
        if not self.resume_digest:
            object.__setattr__(self, "resume_digest", expected)
        elif _digest(self.resume_digest) != expected:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)


def _resume_value(value: SpentRunResumeV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": SPENT_RUN_RESUME_SCHEMA,
        "authority_digest": value.authority_digest,
        "retry_digest": value.retry_digest,
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "labels_spent": value.labels_spent,
        "custody_receipt_digest": value.custody_receipt_digest,
    }
    if include_digest:
        result["resume_digest"] = value.resume_digest
    return result


def spent_run_resume_bytes(value: SpentRunResumeV1) -> bytes:
    value.__post_init__()
    return canonical.canonical_bytes(_resume_value(value, include_digest=True))


def resume_spent_sealed_run(
    *,
    admission_identity_digest: str,
    bundles: tuple[LabelBlindExecutionBundleV1, ...],
    checkpoint_selectors: tuple[CheckpointSelectorV1, ...],
    plan: RegisteredEvaluationPlanV1,
    journal: S3WorkflowJournal,
    workflow_digest: str,
    repository: S3ArtifactRepository,
    access_policy_digest: str,
    custody: S3DurableCustodyStore,
) -> SpentRunResumeV1:
    """Resume the same immutable run from durable artifacts without restoring untouched status."""
    _digest(admission_identity_digest)
    if type(bundles) is not tuple or not bundles:
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    authority = resolve_head_selected_retry_authority(journal, repository, access_policy_digest, workflow_digest)
    candidate = build_automatic_retry_identity(
        bundles[0].population_digest,
        bundles[0].freeze_digest,
        admission_identity_digest,
        bundles,
        checkpoint_selectors,
    )
    actual = _actual_retry_identity(candidate, bundles, checkpoint_selectors, plan)
    if actual.retry_digest != candidate.retry_digest or not retry_identity_matches_authority(
        candidate, bundles, plan, authority
    ):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.MISMATCH_AUTHORITY_REQUIRED)
    log = custody.current_log(authority.population_digest)
    if log.status is not PopulationStatus.SPENT or log.receipt_count < 1:
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.CUSTODY_NOT_SPENT)
    return SpentRunResumeV1(
        authority.authority_digest,
        candidate.retry_digest,
        authority.population_digest,
        authority.freeze_digest,
        True,
        log.head_receipt_digest,
        "",
    )


__all__ = [
    "SPENT_RUN_RESUME_SCHEMA",
    "SpentRunResumeV1",
    "resume_spent_sealed_run",
    "spent_run_resume_bytes",
]
