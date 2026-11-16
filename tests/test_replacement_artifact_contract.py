"""Canonical identity boundary for replacement benchmark artifacts."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import artifact_contract as legacy  # noqa: E402
from benchmarks.valid import replacement_artifact_contract as contract  # noqa: E402
from openultrasast.core.canonical import bytes_digest, content_digest  # noqa: E402

PROVENANCE = content_digest({"review": "independent", "source": "fixture"})


@pytest.mark.parametrize("kind", tuple(contract.ArtifactKind))
def test_all_closed_artifact_kinds_have_deterministic_canonical_identity(
    kind: contract.ArtifactKind,
) -> None:
    first = contract.canonical_artifact_bytes(
        kind,
        {"z": ("two", "one"), "a": {"value": 1}},
        access_class=contract.ArtifactAccessClass.PRIVATE,
        provenance_digest=PROVENANCE,
    )
    second = contract.canonical_artifact_bytes(
        kind,
        {"a": {"value": 1}, "z": ("two", "one")},
        access_class=contract.ArtifactAccessClass.PRIVATE,
        provenance_digest=PROVENANCE,
    )

    assert first == second
    reference = contract.artifact_reference(first)
    assert reference.artifact_kind is kind
    assert reference.content_digest == bytes_digest(first)
    assert reference.byte_length == len(first) > 0
    assert reference.provenance_digest == PROVENANCE
    assert contract.validate_artifact(first, reference=reference).payload["z"] == (
        "two",
        "one",
    )


def test_sequence_order_is_identity_bearing() -> None:
    first = _ordered_artifact(("one", "two"))
    reversed_order = _ordered_artifact(("two", "one"))

    assert first != reversed_order
    assert contract.artifact_reference(first) != contract.artifact_reference(reversed_order)


def test_reference_round_trip_is_canonical_and_strict() -> None:
    content = _artifact()
    reference = contract.artifact_reference(content)
    encoded = contract.canonical_reference_bytes(reference)

    assert contract.decode_reference(encoded) == reference
    assert contract.canonical_reference_bytes(contract.decode_reference(encoded)) == encoded

    noncanonical = json.dumps(json.loads(encoded), indent=2).encode()
    with pytest.raises(contract.ArtifactContractError, match="canonical"):
        contract.decode_reference(noncanonical)


@pytest.mark.parametrize(
    "field,value,message",
    (
        ("schema_version", "unknown", "schema"),
        ("artifact_kind", "unsupported", "kind"),
        ("access_class", "world_readable", "access"),
        ("provenance_digest", "short", "provenance"),
        ("payload_digest", "0" * 64, "payload digest"),
    ),
)
def test_malformed_envelope_is_refused_before_payload_acceptance(field: str, value: object, message: str) -> None:
    envelope = json.loads(_artifact())
    envelope[field] = value
    content = contract.canonical_json_bytes(envelope)

    with pytest.raises(contract.ArtifactContractError, match=message):
        contract.validate_artifact(content)


def test_empty_noncanonical_duplicate_and_unsupported_inputs_are_refused() -> None:
    with pytest.raises(contract.ArtifactContractError, match="nonempty"):
        contract.canonical_artifact_bytes(
            contract.ArtifactKind.REVIEW,
            {},
            access_class=contract.ArtifactAccessClass.PRIVATE,
            provenance_digest=PROVENANCE,
        )
    with pytest.raises(contract.ArtifactContractError, match="nonempty"):
        contract.validate_artifact(b"")
    with pytest.raises(contract.ArtifactContractError, match="canonical"):
        contract.validate_artifact(b'{"schema_version": "not-canonical"}')
    duplicate = b'{"schema_version":"x","schema_version":"x"}'
    with pytest.raises(contract.ArtifactContractError, match="duplicate"):
        contract.validate_artifact(duplicate)
    with pytest.raises(contract.ArtifactContractError, match="unsupported"):
        contract.canonical_artifact_bytes(
            "reservation",
            {"value": object()},
            access_class=contract.ArtifactAccessClass.PRIVATE,
            provenance_digest=PROVENANCE,
        )


@pytest.mark.parametrize(
    "mutation,message",
    (
        ("digest", "content digest"),
        ("length", "byte length"),
        ("kind", "kind"),
        ("access", "access"),
        ("provenance", "provenance"),
    ),
)
def test_reference_mismatch_is_refused(mutation: str, message: str) -> None:
    content = _artifact()
    reference = contract.artifact_reference(content)
    replacements: dict[str, dict[str, object]] = {
        "digest": {"content_digest": "0" * 64},
        "length": {"byte_length": len(content) + 1},
        "kind": {"artifact_kind": contract.ArtifactKind.REPORT},
        "access": {"access_class": contract.ArtifactAccessClass.PUBLIC},
        "provenance": {"provenance_digest": "1" * 64},
    }

    with pytest.raises(contract.ArtifactContractError, match=message):
        contract.validate_artifact(content, reference=replace(reference, **replacements[mutation]))


def test_acceptance_is_idempotent_and_refuses_same_identity_different_bytes() -> None:
    content = _artifact()
    reference = contract.artifact_reference(content)

    assert contract.accept_artifact(content, reference=reference).reference == reference
    assert contract.accept_artifact(content, reference=reference, existing=bytes(content)).reference == reference
    conflicting = content + b"\n"
    with pytest.raises(contract.ArtifactIdentityConflict, match="different bytes"):
        contract.accept_artifact(conflicting, reference=reference, existing=content)


def test_legacy_v2_remains_readable_but_is_never_replacement_authority() -> None:
    legacy_value = legacy.benchmark_artifact("record", {"id": "historical"})
    assert legacy.benchmark_payload(legacy_value, expected_kind="record") == {"id": "historical"}
    legacy_bytes = json.dumps(legacy_value, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(contract.ArtifactContractError, match="schema"):
        contract.validate_artifact(legacy_bytes)


def _artifact() -> bytes:
    return contract.canonical_artifact_bytes(
        contract.ArtifactKind.WORKFLOW,
        {"workflow": "wf-1", "status": "complete"},
        access_class=contract.ArtifactAccessClass.OPERATOR_SAFE,
        provenance_digest=PROVENANCE,
    )


def _ordered_artifact(items: tuple[str, ...]) -> bytes:
    return contract.canonical_artifact_bytes(
        contract.ArtifactKind.RESERVATION,
        {"items": items},
        access_class=contract.ArtifactAccessClass.PRIVATE,
        provenance_digest=PROVENANCE,
    )
