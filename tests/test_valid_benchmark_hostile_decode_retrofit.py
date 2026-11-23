"""Task 11.3 fold-in: hostile-decode discipline on every operator-read decoder.

The four pre-existing decoders behind the operator read path must reject
deeply nested, constant-laden, and numeric-overflow JSON with their closed
typed reasons instead of escaping a raw RecursionError or accepting a
non-finite value. RED against the pre-retrofit state.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_orchestrator import _Client, _settings  # noqa: E402

from benchmarks.valid.artifact_repository import (  # noqa: E402
    ArtifactActorRole,
    ArtifactRepositoryError,
    ArtifactRepositoryReason,
    S3ArtifactRepository,
    artifact_object_location,
    artifact_read_authority,
)
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    accept_artifact,
)
from benchmarks.valid.store_configuration import StorePurpose  # noqa: E402
from benchmarks.valid.workflow_journal import WorkflowJournalError, decode_workflow_head  # noqa: E402
from benchmarks.valid.workflow_outcome import WorkflowOutcomeError, decode_workflow_outcome  # noqa: E402
from openultrasast.core.canonical import bytes_digest  # noqa: E402

DEPTH = 20000


def _deep_bytes() -> bytes:
    return b"[" * DEPTH + b"]" * DEPTH


def _reference(content: bytes) -> ArtifactReference:
    return ArtifactReference(ArtifactKind.POPULATION, bytes_digest(content), len(content), "0" * 64, ArtifactAccessClass.PUBLIC)


def _authority() -> object:
    return artifact_read_authority(
        ArtifactActorRole.OPERATOR,
        (),
        "0" * 64,
        expected_access_policy_digest="0" * 64,
    )


def test_artifact_contract_rejects_deep_nesting_with_a_closed_reason() -> None:
    with pytest.raises(Exception) as raised:
        accept_artifact(_deep_bytes(), reference=_reference(_deep_bytes()))
    assert type(raised.value).__name__ == "ArtifactContractError"


def test_artifact_contract_rejects_nonfinite_and_constant_literals() -> None:
    overflow = b'{"schema_version": "x", "value": 1e999}'
    with pytest.raises(Exception) as raised:
        accept_artifact(overflow, reference=_reference(overflow))
    assert type(raised.value).__name__ == "ArtifactContractError"
    constant = b'{"schema_version": NaN}'
    with pytest.raises(Exception) as raised:
        accept_artifact(constant, reference=_reference(constant))
    assert type(raised.value).__name__ == "ArtifactContractError"


def test_repository_maps_deep_object_to_typed_invalid_object() -> None:
    client = _Client()
    repository = S3ArtifactRepository(_settings(StorePurpose.DURABLE), client)
    content = _deep_bytes()
    reference = _reference(content)
    location = artifact_object_location(_settings(StorePurpose.DURABLE), reference)
    client.put_object(Bucket=location.bucket, Key=location.key, Body=content)
    with pytest.raises(ArtifactRepositoryError) as raised:
        repository.get(
            reference,
            expected_kind=ArtifactKind.POPULATION,
            authority=_authority(),  # type: ignore[arg-type]
            expected_access_policy_digest="0" * 64,
        )
    assert raised.value.reason is ArtifactRepositoryReason.INVALID_OBJECT


def test_workflow_outcome_rejects_deep_nesting_with_a_closed_reason() -> None:
    with pytest.raises(WorkflowOutcomeError):
        decode_workflow_outcome(_deep_bytes())


def test_workflow_outcome_rejects_nonfinite_and_constant_literals() -> None:
    with pytest.raises(WorkflowOutcomeError):
        decode_workflow_outcome(b'{"schema_version": "x", "value": 1e999}')
    with pytest.raises(WorkflowOutcomeError):
        decode_workflow_outcome(b'{"schema_version": NaN}')


def test_workflow_journal_rejects_deep_nesting_with_a_closed_reason() -> None:
    with pytest.raises(WorkflowJournalError):
        decode_workflow_head(_deep_bytes())


def test_workflow_journal_rejects_nonfinite_and_constant_literals() -> None:
    with pytest.raises(WorkflowJournalError):
        decode_workflow_head(b'{"schema_version": "x", "value": 1e999}')
    with pytest.raises(WorkflowJournalError):
        decode_workflow_head(b'{"schema_version": NaN}')
