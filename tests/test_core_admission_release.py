"""Authenticated post-spend case-release contract (12.2, 12.5, 12.6, 13.4, 15.1)."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import NamedTuple

import pytest
from detection_core_fixtures import InMemoryContentResolver
from test_core_admission_context import AdmissionCase, _attestation
from test_core_admission_spend import _feasible_case, _prepare, _spend
from test_core_consumer_v2 import _request
from test_core_model import _record as _model_record
from test_core_validation_v2 import _named_inputs, _with_fact_set

from openultrasast.core import evidence, validation
from openultrasast.core.admission_case import (
    ADMISSION_CASE_RELEASE_SCHEMA,
    AdmissionCaseRelease,
    AdmissionCaseReleaseError,
    AdmissionCaseResult,
    AdmissionCaseRole,
    ReleasedCaseBinding,
    derive_admission_case_release_digest,
    derive_admission_case_release_payload_digest,
    derive_admission_case_result_digest,
    derive_released_case_binding_digest,
    validate_admission_case_release,
)
from openultrasast.core.admission_spend import AdmissionPreparation
from openultrasast.core.canonical import content_digest
from openultrasast.core.coverage import (
    CoverageFunnel,
    InputManifest,
    InputReadReceipt,
    RelationStatusCount,
    derive_input_manifest_digest,
)
from openultrasast.core.custody import PopulationUseReceipt
from openultrasast.core.measurement import ScopeKey
from openultrasast.core.semantics import RelationStatus


class _ReleaseSetup(NamedTuple):
    admission: AdmissionCase
    preparation: AdmissionPreparation
    receipt: PopulationUseReceipt
    cases: tuple[AdmissionCaseResult, ...]
    release: AdmissionCaseRelease
    resolver: InMemoryContentResolver


def _merge_resolvers(*values: InMemoryContentResolver) -> InMemoryContentResolver:
    artifacts = {}
    for value in values:
        artifacts.update(value.artifacts)
    return InMemoryContentResolver(artifacts)


def _coverage() -> CoverageFunnel:
    return CoverageFunnel(
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        0,
        (
            RelationStatusCount(RelationStatus.COMPLETE, 1),
            RelationStatusCount(RelationStatus.INCOMPLETE, 0),
            RelationStatusCount(RelationStatus.UNRESOLVED, 0),
        ),
        (),
    )


def _instrument(name: str) -> tuple[InputManifest, tuple[InputReadReceipt, ...]]:
    manifest = InputManifest((name,), derive_input_manifest_digest((name,)))
    receipt = InputReadReceipt(name, f"/{name}.py", True, 10, content_digest(name))
    return manifest, (receipt,)


def _case_result(
    value: validation.EvidenceValidationInput,
    role: AdmissionCaseRole,
    pair: str | None,
    resolver: InMemoryContentResolver,
) -> tuple[AdmissionCaseResult, InMemoryContentResolver]:
    request, combined = _request(value, resolver)
    manifest, receipts = _instrument(role.value)
    values: dict[str, object] = {
        "case_id_digest": content_digest(f"release-{role.value}"),
        "scope": ScopeKey("release-family", "python"),
        "role": role,
        "pair_id_digest": pair,
        "evidence_inputs": (value,),
        "defect_claims": (),
        "satisfactions": (),
        "silence": (),
        "proof_attachments": (),
        "coverage": _coverage(),
        "input_manifest": manifest,
        "input_receipts": receipts,
        "complexity": request.complexity,
        "budget": request.budget,
        "total_reply_ms": 10,
    }
    draft = AdmissionCaseResult(**values, result_digest="0" * 64)  # type: ignore[arg-type]
    return replace(draft, result_digest=derive_admission_case_result_digest(draft)), combined


def _canonical_evidence_inputs(
    admission: AdmissionCase,
) -> tuple[tuple[validation.EvidenceValidationInput, ...], InMemoryContentResolver]:
    contract = admission.context.evidence.family_catalog.entries[0].contract
    base = _with_fact_set(_model_record(contract), ())
    values: list[validation.EvidenceValidationInput] = []
    resolvers: list[InMemoryContentResolver] = []
    for suffix in ("vulnerable", "fixed", "ordinary"):
        scope = replace(base.packet.scope, base_revision=f"base-{suffix}", head_revision=f"head-{suffix}")
        packet = replace(base.packet, scope=scope)
        decision = replace(base.decision, bounded_scope=scope, packet_digest=evidence.derive_packet_digest(packet))
        record = evidence.EvidenceRecord(packet, decision, "")
        named_inputs, resolver = _named_inputs(record, contract, ())
        values.append(validation.make_evidence_validation_input(record=record, named_inputs=named_inputs))
        resolvers.append(resolver)
    return tuple(values), _merge_resolvers(*resolvers)


def _binding(case: AdmissionCaseResult) -> ReleasedCaseBinding:
    evidence = tuple(sorted(item.input_digest for item in case.evidence_inputs))
    changes = tuple(sorted({item.record.packet.provenance.change_input_digest for item in case.evidence_inputs}))
    draft = ReleasedCaseBinding(
        case.case_id_digest,
        case.scope,
        case.role,
        case.pair_id_digest,
        case.result_digest,
        evidence,
        changes,
        case.input_manifest.manifest_digest,
        "0" * 64,
    )
    return replace(draft, binding_digest=derive_released_case_binding_digest(draft))


def _resign_release(
    release: AdmissionCaseRelease,
    admission: AdmissionCase,
    receipt: PopulationUseReceipt,
) -> AdmissionCaseRelease:
    draft = replace(release, release_payload_digest="0" * 64, release_digest="0" * 64)
    payload = derive_admission_case_release_payload_digest(draft)
    review = _attestation(
        payload,
        receipt.custodian_identity,
        admission.manifest.review.reviewer_identity,
        admission.manifest.review.conflict_disclosure,
    )
    reviewed = replace(draft, release_payload_digest=payload, review=review)
    return replace(reviewed, release_digest=derive_admission_case_release_digest(reviewed))


def _setup() -> _ReleaseSetup:
    admission = _feasible_case()
    preparation = _prepare(admission)
    receipt = _spend(admission, preparation)
    evidence_inputs, evidence_resolver = _canonical_evidence_inputs(admission)
    pair = content_digest("release-pair")
    vulnerable_input, fixed_input, ordinary_input = evidence_inputs
    vulnerable, vulnerable_resolver = _case_result(vulnerable_input, AdmissionCaseRole.VULNERABLE, pair, evidence_resolver)
    fixed, fixed_resolver = _case_result(fixed_input, AdmissionCaseRole.FIXED, pair, evidence_resolver)
    ordinary, ordinary_resolver = _case_result(ordinary_input, AdmissionCaseRole.ORDINARY, None, evidence_resolver)
    cases = (vulnerable, fixed, ordinary)
    bindings = tuple(sorted((_binding(case) for case in cases), key=lambda item: item.case_id_digest))
    draft = AdmissionCaseRelease(
        ADMISSION_CASE_RELEASE_SCHEMA,
        admission.manifest.identity.population_digest,
        admission.manifest.manifest_digest,
        preparation.authorization.authorization_digest,
        preparation.preparation_digest,
        receipt.receipt_digest,
        receipt.custodian_identity,
        bindings,
        "0" * 64,
        admission.manifest.review,
        "0" * 64,
    )
    release = _resign_release(draft, admission, receipt)
    resolver = _merge_resolvers(admission.resolver, vulnerable_resolver, fixed_resolver, ordinary_resolver)
    return _ReleaseSetup(admission, preparation, receipt, cases, release, resolver)


def _validate(
    setup: _ReleaseSetup,
    *,
    release: AdmissionCaseRelease | None = None,
    cases: tuple[AdmissionCaseResult, ...] | None = None,
) -> None:
    validate_admission_case_release(
        setup.admission.manifest,
        setup.admission.denominator,
        setup.admission.readiness,
        setup.admission.context,
        setup.preparation,
        setup.receipt,
        release or setup.release,
        cases or setup.cases,
        setup.admission.port,
        setup.resolver,
    )


def test_exact_post_spend_release_authorizes_case_associations() -> None:
    setup = _setup()

    _validate(setup)


def test_release_is_refused_before_exact_spend_successor() -> None:
    setup = _setup()
    population = setup.admission.manifest.identity.population_digest
    setup.admission.port.logs[population] = replace(
        setup.admission.port.logs[population],
        receipts=(),
        receipt_count=0,
        head_receipt_digest=None,
        status=setup.receipt.prior_status,
        log_digest=setup.preparation.authorization.custody_log_digest,
    )

    with pytest.raises((AdmissionCaseReleaseError, ValueError), match="successor|spent|custody"):
        _validate(setup)


@pytest.mark.parametrize(
    "field,value",
    (
        ("population_digest", content_digest("other-population")),
        ("manifest_digest", content_digest("other-manifest")),
        ("authorization_digest", content_digest("other-authorization")),
        ("preparation_digest", content_digest("other-preparation")),
        ("label_release_receipt_digest", content_digest("other-receipt")),
        ("custodian_identity", content_digest("other-custodian")),
    ),
)
def test_self_consistent_release_cannot_change_spend_binding(field: str, value: str) -> None:
    setup = _setup()
    changed = _resign_release(replace(setup.release, **{field: value}), setup.admission, setup.receipt)

    with pytest.raises(AdmissionCaseReleaseError, match=field.replace("_", " ") + "|custodian"):
        _validate(setup, release=changed)


@pytest.mark.parametrize("field", ("schema_version", "release_payload_digest", "release_digest"))
def test_release_schema_and_canonical_digests_are_rederived(field: str) -> None:
    setup = _setup()
    changed = replace(setup.release, **{field: content_digest(field)})

    with pytest.raises(AdmissionCaseReleaseError, match="schema|payload digest|release digest"):
        _validate(setup, release=changed)


@pytest.mark.parametrize("mutation", ("missing", "extra", "duplicate"))
def test_release_requires_exact_one_to_one_case_population(mutation: str) -> None:
    setup = _setup()
    bindings = setup.release.bindings
    if mutation == "missing":
        changed_bindings = bindings[:-1]
    elif mutation == "extra":
        extra = replace(bindings[-1], case_id_digest=content_digest("extra-case"), binding_digest="0" * 64)
        extra = replace(extra, binding_digest=derive_released_case_binding_digest(extra))
        changed_bindings = tuple(sorted((*bindings, extra), key=lambda item: item.case_id_digest))
    else:
        changed_bindings = (*bindings, bindings[-1])
    changed = _resign_release(replace(setup.release, bindings=changed_bindings), setup.admission, setup.receipt)

    with pytest.raises(AdmissionCaseReleaseError, match="binding|case population|canonical|pair"):
        _validate(setup, release=changed)


@pytest.mark.parametrize(
    "field",
    (
        "scope",
        "role",
        "pair_id_digest",
        "case_result_digest",
        "evidence_input_digests",
        "change_input_digests",
        "input_manifest_digest",
    ),
)
def test_release_binding_mutations_are_refused(field: str) -> None:
    setup = _setup()
    original = setup.release.bindings[0]
    other_role = AdmissionCaseRole.FIXED if original.role is not AdmissionCaseRole.FIXED else AdmissionCaseRole.VULNERABLE
    values: dict[str, object] = {
        "scope": ScopeKey(original.scope.family_id, "other-ecosystem"),
        "role": other_role,
        "pair_id_digest": content_digest("other-pair"),
        "case_result_digest": content_digest("other-result"),
        "evidence_input_digests": (content_digest("other-evidence"),),
        "change_input_digests": (content_digest("other-change"),),
        "input_manifest_digest": content_digest("other-input-manifest"),
    }
    changed_binding = replace(original, **{field: values[field]}, binding_digest="0" * 64)
    changed_binding = replace(changed_binding, binding_digest=derive_released_case_binding_digest(changed_binding))
    bindings = tuple(sorted((changed_binding, *setup.release.bindings[1:]), key=lambda item: item.case_id_digest))
    changed = _resign_release(replace(setup.release, bindings=bindings), setup.admission, setup.receipt)

    with pytest.raises(AdmissionCaseReleaseError, match="binding|pair|case"):
        _validate(setup, release=changed)


def test_binding_digest_is_rederived() -> None:
    setup = _setup()
    changed_binding = replace(setup.release.bindings[0], binding_digest=content_digest("changed-binding"))
    bindings = (changed_binding, *setup.release.bindings[1:])
    changed = replace(setup.release, bindings=bindings)

    with pytest.raises(AdmissionCaseReleaseError, match="binding digest"):
        _validate(setup, release=changed)


def test_rehashed_vulnerable_fixed_operational_payload_swap_is_refused() -> None:
    setup = _setup()
    vulnerable, fixed, ordinary = setup.cases
    operational_fields = tuple(
        field.name
        for field in fields(AdmissionCaseResult)
        if field.name not in {"case_id_digest", "scope", "role", "pair_id_digest", "result_digest"}
    )
    vulnerable_values = {name: getattr(fixed, name) for name in operational_fields}
    fixed_values = {name: getattr(vulnerable, name) for name in operational_fields}
    changed_vulnerable = replace(vulnerable, **vulnerable_values, result_digest="0" * 64)
    changed_fixed = replace(fixed, **fixed_values, result_digest="0" * 64)
    changed_vulnerable = replace(changed_vulnerable, result_digest=derive_admission_case_result_digest(changed_vulnerable))
    changed_fixed = replace(changed_fixed, result_digest=derive_admission_case_result_digest(changed_fixed))

    with pytest.raises(AdmissionCaseReleaseError, match="binding"):
        _validate(setup, cases=(changed_vulnerable, changed_fixed, ordinary))


def test_release_refuses_tampered_named_input_payload_with_stale_input_digest() -> None:
    setup = _setup()
    vulnerable, fixed, ordinary = setup.cases
    evidence_input = vulnerable.evidence_inputs[0]
    first, *remaining = evidence_input.named_inputs.inputs
    tampered_named = replace(first, identity=content_digest("tampered-named-input"))
    stale_named_inputs = replace(evidence_input.named_inputs, inputs=(tampered_named, *remaining))
    stale_input = replace(evidence_input, named_inputs=stale_named_inputs)
    changed = replace(vulnerable, evidence_inputs=(stale_input,))

    with pytest.raises(AdmissionCaseReleaseError, match="named input|input digest|provenance"):
        _validate(setup, cases=(changed, fixed, ordinary))


def test_release_refuses_tampered_tracked_inputs_with_stale_manifest_digest() -> None:
    setup = _setup()
    vulnerable, fixed, ordinary = setup.cases
    stale_manifest = replace(vulnerable.input_manifest, tracked_input_ids=("substituted-input",))
    changed = replace(vulnerable, input_manifest=stale_manifest)

    with pytest.raises(AdmissionCaseReleaseError, match="manifest digest|tracked input"):
        _validate(setup, cases=(changed, fixed, ordinary))


def test_release_review_must_be_independent_and_custodian_produced() -> None:
    setup = _setup()
    payload = setup.release.release_payload_digest
    disclosure = setup.release.review.conflict_disclosure
    reviewer = setup.release.review.reviewer_identity
    wrong_producer = _attestation(payload, content_digest("wrong-producer"), reviewer, disclosure)
    self_review = _attestation(payload, reviewer, reviewer, disclosure)

    for review in (wrong_producer, self_review):
        changed = replace(setup.release, review=review, release_digest="0" * 64)
        changed = replace(changed, release_digest=derive_admission_case_release_digest(changed))
        with pytest.raises(AdmissionCaseReleaseError, match="producer|independent"):
            _validate(setup, release=changed)


def test_release_review_subject_reviewer_digest_and_disclosure_are_revalidated() -> None:
    setup = _setup()
    review = setup.release.review
    mutations = (
        replace(review, subject_digest=content_digest("wrong-subject")),
        _attestation(
            review.subject_digest,
            review.producer_identity,
            content_digest("unknown-reviewer"),
            review.conflict_disclosure,
        ),
        replace(review, attestation_digest=content_digest("wrong-attestation")),
        _attestation(
            review.subject_digest,
            review.producer_identity,
            review.reviewer_identity,
            replace(review.conflict_disclosure, artifact_id="missing-release-disclosure"),
        ),
    )

    for changed_review in mutations:
        changed = replace(setup.release, review=changed_review, release_digest="0" * 64)
        changed = replace(changed, release_digest=derive_admission_case_release_digest(changed))
        with pytest.raises(AdmissionCaseReleaseError, match="subject|reviewer|attestation|artifact"):
            _validate(setup, release=changed)
