"""Complete input and decision provenance contracts (Req 10.1, 10.4)."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import cast

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import canonical, provenance

STAMP_FIELDS = (
    "analyzer_revision",
    "family_contract_digest",
    "fact_set_digest",
    "acquisition_record_digest",
    "configuration_digest",
    "population_digest",
    "change_input_digest",
)


class CountingResolver:
    def __init__(self, delegate: InMemoryContentResolver) -> None:
        self.delegate = delegate
        self.resolved: list[str] = []

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        self.resolved.append(reference.artifact_id)
        return self.delegate.resolve(reference)


def _contract() -> tuple[
    provenance.ProvenanceStamp,
    provenance.NamedInputs,
    InMemoryContentResolver,
    provenance.ProvenanceTrustPolicy,
]:
    entries: list[provenance.NamedInput] = []
    artifacts: dict[str, canonical.ResolvedContent] = {}
    identities: dict[provenance.ProvenanceInputRole, str] = {}
    for role in provenance.ProvenanceInputRole:
        content = canonical.canonical_bytes({"schema_version": canonical.DETECTION_CORE_SCHEMA, "role": role.value})
        reference, resolver = stored_artifact(content, artifact_id=f"input-{role.value}")
        entries.append(provenance.NamedInput(role=role, identity=reference.content_digest, content=reference))
        artifacts.update(resolver.artifacts)
        identities[role] = reference.content_digest
    inputs = tuple(reversed(entries))
    named = provenance.NamedInputs(inputs=inputs, manifest_digest=provenance.derive_named_inputs_digest(inputs))
    stamp = provenance.ProvenanceStamp(
        analyzer_revision=identities[provenance.ProvenanceInputRole.ANALYZER],
        family_contract_digest=identities[provenance.ProvenanceInputRole.FAMILY_CONTRACT],
        fact_set_digest=identities[provenance.ProvenanceInputRole.FACT_SET],
        acquisition_record_digest=identities[provenance.ProvenanceInputRole.ACQUISITION],
        configuration_digest=identities[provenance.ProvenanceInputRole.CONFIGURATION],
        population_digest=identities[provenance.ProvenanceInputRole.POPULATION],
        change_input_digest=identities[provenance.ProvenanceInputRole.CHANGE_INPUT],
    )
    stores = ("trusted-store",)
    policy = provenance.ProvenanceTrustPolicy(
        trusted_store_identities=stores,
        maximum_input_bytes=1024,
        policy_digest=provenance.derive_trust_policy_digest(stores, 1024),
    )
    return stamp, named, InMemoryContentResolver(artifacts), policy


def _replace_stamp_digest(stamp: provenance.ProvenanceStamp, field: str, value: str) -> provenance.ProvenanceStamp:
    values = {item.name: getattr(stamp, item.name) for item in fields(stamp)}
    values[field] = value
    return provenance.ProvenanceStamp(**values)


def test_every_closed_named_input_is_resolved_before_acceptance() -> None:
    stamp, named, resolver, policy = _contract()
    counting = CountingResolver(resolver)

    provenance.validate_provenance(stamp, named, counting, policy)

    assert set(counting.resolved) == {item.content.artifact_id for item in named.inputs}
    assert len(counting.resolved) == len(provenance.ProvenanceInputRole) == 7


@pytest.mark.parametrize("field", STAMP_FIELDS)
def test_every_stamp_identity_has_a_tamper_check(field: str) -> None:
    stamp, named, resolver, policy = _contract()
    tampered = _replace_stamp_digest(stamp, field, "0" * 64)
    with pytest.raises(provenance.ProvenanceValidationError, match=field):
        provenance.validate_provenance(tampered, named, resolver, policy)


def test_named_input_roles_are_closed_complete_and_unique() -> None:
    stamp, named, resolver, policy = _contract()
    missing_change = tuple(item for item in named.inputs if item.role is not provenance.ProvenanceInputRole.CHANGE_INPUT)
    with pytest.raises(provenance.ProvenanceValidationError, match="missing.*change_input"):
        provenance.validate_provenance(stamp, replace(named, inputs=missing_change), resolver, policy)
    duplicate = named.inputs + (named.inputs[0],)
    with pytest.raises(provenance.ProvenanceValidationError, match="duplicate"):
        provenance.validate_provenance(stamp, replace(named, inputs=duplicate), resolver, policy)
    invalid = replace(named.inputs[0], role=cast(provenance.ProvenanceInputRole, "model"))
    with pytest.raises(provenance.ProvenanceValidationError, match="unknown.*role"):
        provenance.validate_provenance(stamp, replace(named, inputs=(invalid, *named.inputs[1:])), resolver, policy)


def test_manifest_and_trust_policy_identities_are_rederived() -> None:
    stamp, named, resolver, policy = _contract()
    with pytest.raises(provenance.ProvenanceValidationError, match="manifest"):
        provenance.validate_provenance(stamp, replace(named, manifest_digest="0" * 64), resolver, policy)
    with pytest.raises(provenance.ProvenanceValidationError, match="policy"):
        provenance.validate_provenance(stamp, named, resolver, replace(policy, policy_digest="0" * 64))


def test_substituted_named_input_is_resolved_then_refused() -> None:
    stamp, named, resolver, policy = _contract()
    target = named.inputs[0]
    replacement_ref, replacement_resolver = stored_artifact(b"substitute", artifact_id=target.content.artifact_id)
    replacement = replace(target, content=replacement_ref)
    replaced_inputs = (replacement, *named.inputs[1:])
    substituted = provenance.NamedInputs(
        inputs=replaced_inputs,
        manifest_digest=provenance.derive_named_inputs_digest(replaced_inputs),
    )
    artifacts = dict(resolver.artifacts)
    artifacts[target.content.artifact_id] = replacement_resolver.artifacts[target.content.artifact_id]
    counting = CountingResolver(InMemoryContentResolver(artifacts))

    with pytest.raises(provenance.ProvenanceValidationError, match="named identity"):
        provenance.validate_provenance(stamp, substituted, counting, policy)
    assert target.content.artifact_id in counting.resolved


def test_unreadable_named_input_is_never_treated_as_empty() -> None:
    stamp, named, _, policy = _contract()
    assert all(item.content.byte_length > 0 for item in named.inputs)
    with pytest.raises(canonical.ArtifactResolutionError, match="not found"):
        provenance.validate_provenance(stamp, named, InMemoryContentResolver({}), policy)


def test_named_inputs_use_receipt_trust_and_size_boundary() -> None:
    stamp, named, resolver, policy = _contract()
    with pytest.raises(canonical.ArtifactValidationError, match="trusted"):
        provenance.validate_provenance(
            stamp,
            named,
            resolver,
            replace(
                policy,
                trusted_store_identities=("other-store",),
                policy_digest=provenance.derive_trust_policy_digest(("other-store",), 1024),
            ),
        )
    tiny = replace(
        policy,
        maximum_input_bytes=1,
        policy_digest=provenance.derive_trust_policy_digest(policy.trusted_store_identities, 1),
    )
    with pytest.raises(canonical.ArtifactValidationError, match="maximum"):
        provenance.validate_provenance(stamp, named, resolver, tiny)


@pytest.mark.parametrize("value", ["", 7, None])
def test_textual_and_digest_contracts_are_runtime_checked(value: object) -> None:
    stamp, named, _, policy = _contract()
    with pytest.raises((ValueError, canonical.DigestFormatError)):
        replace(named.inputs[0], identity=cast(str, value))
    with pytest.raises(ValueError):
        replace(policy, trusted_store_identities=(cast(str, value),))
    with pytest.raises(canonical.DigestFormatError):
        replace(stamp, population_digest=cast(str, value))


def test_model_and_proof_identities_are_decision_only() -> None:
    assert not any("model" in item.name or "proof" in item.name for item in fields(provenance.ProvenanceStamp))
    decision_fields = {item.name for item in fields(provenance.DecisionProvenance)}
    assert {"model_identity", "model_result_digest", "proof_record_digest", "proof_producer_digest"} <= decision_fields
    digest = canonical.content_digest("identity")
    identity = provenance.ModelCallIdentity(
        provider="provider",
        model="model",
        program_digest=digest,
        prompt_digest=digest,
        configuration_digest=digest,
        adapter_revision="adapter-v1",
    )
    decision = provenance.DecisionProvenance(identity, digest, digest, digest, digest, digest)
    assert decision.model_identity == identity


def test_named_input_manifest_is_order_independent_but_role_sensitive() -> None:
    _, named, _, _ = _contract()
    assert provenance.derive_named_inputs_digest(named.inputs) == provenance.derive_named_inputs_digest(tuple(reversed(named.inputs)))
    swapped = replace(named.inputs[0], role=named.inputs[1].role)
    assert provenance.derive_named_inputs_digest((swapped, *named.inputs[1:])) != named.manifest_digest
