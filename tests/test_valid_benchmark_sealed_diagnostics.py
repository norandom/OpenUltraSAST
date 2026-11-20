"""Task 6.5 sealed pre-spend diagnostics and reviewed development opening."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import stored_artifact  # noqa: E402
from test_valid_benchmark_artifact_repository import _authority, _Client, _digest, _repo  # noqa: E402
from test_valid_benchmark_isolated_executor import _authorities, _bundles  # noqa: E402
from test_valid_benchmark_lifecycle import _withdrawal  # noqa: E402
from test_valid_benchmark_observation_checkpoint import _Adapter, _frozen, _run  # noqa: E402

from benchmarks.valid import artifact_repository as repository  # noqa: E402
from benchmarks.valid import lifecycle, observation_checkpoint, reservation, sealed_diagnostics  # noqa: E402
from benchmarks.valid import population_label_blind_contract as manifest_contract  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    artifact_reference,
    canonical_artifact_bytes,
)
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.factpack import (  # noqa: E402
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)


def _custodian() -> repository.ArtifactReadAuthority:
    return _authority(
        repository.ArtifactActorRole.CUSTODIAN,
        (
            repository.ArtifactReadPermission.CUSTODIAN_SEALED,
            repository.ArtifactReadPermission.PRIVATE,
        ),
    )


def _active(population: str, freeze: str) -> tuple[lifecycle.BaselineLifecycleAuthority, str]:
    root = lifecycle.withdrawn_event(_withdrawal())
    withdrawn = lifecycle.decode_lifecycle_event(root)
    replacement = lifecycle.reviewed_replacement_event(
        predecessor_digest=withdrawn.event_digest,
        historical_withdrawal_digest=withdrawn.historical_withdrawal_digest,
        population_digest=population,
        freeze_digest=freeze,
        producer_identity="lifecycle-producer",
        reviewer_identity="lifecycle-reviewer",
        conflict_disclosed=True,
        policy_digest=_digest("lifecycle-policy"),
    )
    authority = lifecycle.BaselineLifecycleAuthority()
    authority.append(root)
    projection = authority.append(replacement)
    return authority, projection.head_event_digest


def _resolver(selection=None) -> reservation.RepositoryIdentityResolver:
    selection = _authorities()[2] if selection is None else selection
    networks = {push.network_identity_digest: reservation.build_network_identity(push.canonical_repository) for push in selection.pushes}
    assert all(
        networks[item.network_identity_digest].network_identity_digest == item.network_identity_digest for item in selection.fix_exclusions
    )
    return reservation.RepositoryIdentityResolver(tuple(networks.values()))


def _policy() -> ReviewIndependencePolicy:
    reviewer = _digest("diagnostic-reviewer")
    policy_digest = derive_review_independence_policy_digest((reviewer,), (), ("trusted-store",), 4096)
    return ReviewIndependencePolicy((reviewer,), (), ("trusted-store",), 4096, policy_digest)


def _review(subject_digest: str, policy: ReviewIndependencePolicy):
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id=f"development-access-{subject_digest[:12]}")
    producer = _digest("diagnostic-requester")
    reviewer = policy.reviewed_reviewer_digests[0]
    draft = IndependenceAttestation(subject_digest, producer, reviewer, disclosure, "0" * 64)
    review = replace(draft, attestation_digest=derive_independence_attestation_digest(draft))
    return review, resolver


def _request(
    bundle,
    predecessor: str,
    checkpoint,
    selection,
    resolver,
    manifest,
    *,
    population_digest: str | None = None,
    freeze_digest: str | None = None,
):
    policy = _policy()
    subject = sealed_diagnostics.build_development_access_subject(
        population_digest or bundle.population_digest,
        freeze_digest or bundle.freeze_digest,
        predecessor,
        checkpoint,
        bundle=bundle,
        selection=selection,
        resolver=resolver,
        manifest=manifest,
        artifact_access_policy_digest=_digest("read-policy"),
        lifecycle_review_policy_digest=policy.policy_digest,
    )
    review, review_resolver = _review(subject.subject_digest, policy)
    request = sealed_diagnostics.build_development_access_request(subject, review, policy, review_resolver)
    return request, review_resolver


def _manifest_for_population(manifest, population_digest: str, freeze_digest: str):
    changed = replace(
        manifest,
        population_digest=population_digest,
        freeze_digest=freeze_digest,
        draft_digest="",
        manifest_digest="",
    )
    draft = manifest_contract._manifest_draft(changed)
    draft = replace(draft, draft_digest=canonical.content_digest(manifest_contract._draft_value(draft, include_digest=False)))
    changed = replace(changed, draft_digest=draft.draft_digest)
    return replace(
        changed,
        manifest_digest=canonical.content_digest(manifest_contract._manifest_value(changed, include_digest=False)),
    )


def test_pre_spend_projection_contains_only_closed_codes_counts_and_digests() -> None:
    bundle, client, _, frozen = _frozen()
    projection = sealed_diagnostics.project_pre_spend_diagnostics(
        frozen,
        _repo(client),
        _custodian(),
        _digest("read-policy"),
    )

    assert projection.status is sealed_diagnostics.DiagnosticStatus.COMPLETE
    assert projection.reason is sealed_diagnostics.DiagnosticReason.NONE
    assert projection.input_count == len(bundle.case_inputs) > 0
    assert projection.required_stage_count == 3
    assert projection.observation_count > 0
    assert projection.runtime_ms == 7
    assert projection.checkpoint_digest == frozen.checkpoint_digest
    assert projection.receipt_digest
    content = sealed_diagnostics.pre_spend_diagnostic_bytes(projection).lower()
    for forbidden in (b"finding", b"path", b"exception", b"password", b"label", b"repository"):
        assert forbidden not in content


def test_impaired_pre_spend_projection_never_reads_an_artifact_or_looks_clean() -> None:
    bundle = _bundles()[0]
    client = _Client()
    result = _run(bundle, _Adapter(lambda _: (_ for _ in ()).throw(RuntimeError("private diagnostic"))), client)

    projection = sealed_diagnostics.project_pre_spend_diagnostics(
        result,
        _repo(client),
        _custodian(),
        _digest("read-policy"),
    )

    assert projection.status is sealed_diagnostics.DiagnosticStatus.IMPAIRED
    assert projection.reason is sealed_diagnostics.DiagnosticReason.ADAPTER_FAILURE
    assert projection.input_count == projection.observation_count == 0
    assert projection.checkpoint_digest == ""
    assert client.get_calls == []


def test_unreviewed_development_opening_returns_no_raw_artifact() -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    put_count = len(client.put_calls)
    policy = _policy()
    subject = sealed_diagnostics.build_development_access_subject(
        bundle.population_digest,
        bundle.freeze_digest,
        predecessor,
        frozen,
        bundle=bundle,
        artifact_access_policy_digest=_digest("read-policy"),
        lifecycle_review_policy_digest=policy.policy_digest,
        resolver=resolver,
        selection=selection,
        manifest=manifest,
    )
    review, review_resolver = _review(subject.subject_digest, policy)
    self_review = replace(review, producer_identity=review.reviewer_identity, attestation_digest="0" * 64)
    self_review = replace(self_review, attestation_digest=derive_independence_attestation_digest(self_review))

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        sealed_diagnostics.build_development_access_request(subject, self_review, policy, review_resolver)

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.REVIEW_REQUIRED
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)
    assert len(client.put_calls) == put_count


def test_reviewed_opening_persists_influences_and_terminal_lifecycle_before_raw_access() -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    reservation_authority = reservation.ReservationAuthority(resolver)
    request, review_resolver = _request(bundle, predecessor, frozen, selection, resolver, manifest)

    opened = sealed_diagnostics.open_observation_for_development(
        request,
        repository=_repo(client),
        artifact_authority=_custodian(),
        lifecycle_authority=lifecycle_authority,
        reservation_authority=reservation_authority,
        resolver=resolver,
        selection=selection,
        manifest=manifest,
        review_resolver=review_resolver,
    )

    assert opened.artifact.reference == frozen.reference
    assert opened.artifact.content
    assert opened.lifecycle_projection.state is lifecycle.PopulationLifecycleState.DEVELOPMENT_OPENED
    assert not opened.lifecycle_projection.admission_eligible
    assert len(opened.influence_references) == len({item.network_identity_digest for item in selection.fix_exclusions})
    assert all(item.artifact_kind is ArtifactKind.RESERVATION for item in opened.influence_references)
    assert all(item.access_class is ArtifactAccessClass.PRIVATE for item in opened.influence_references)
    assert opened.lifecycle_reference.artifact_kind is ArtifactKind.LIFECYCLE
    assert opened.lifecycle_reference.access_class is ArtifactAccessClass.PRIVATE
    census = reservation_authority.current_census()
    assert census.accepted_event_digests == opened.lifecycle_projection.influence_event_digests
    assert set(census.reserved_network_digests) == {item.network_identity_digest for item in selection.fix_exclusions}
    with pytest.raises(lifecycle.LifecycleError, match="eligible"):
        lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


def test_development_opening_preserves_existing_reservation_census_events() -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    reservation_authority = reservation.ReservationAuthority(resolver)
    existing = reservation.reviewed_influence_event(
        resolver,
        repository=selection.pushes[0].canonical_repository,
        event_source="reviewed_population_selection",
        disposition=reservation.InfluenceDisposition.INFLUENCED,
        influence_kind=reservation.InfluenceKind.POPULATION_SELECTION,
        subject_digest=_digest("existing-influence"),
        actor_identity="selection-producer",
        reviewer_identity="selection-reviewer",
        conflict_disclosed=True,
        policy_digest=_digest("lifecycle-policy"),
    )
    existing_digest = reservation.decode_influence_event(existing).event_digest
    reservation_authority.append_influence(existing)
    request, review_resolver = _request(bundle, predecessor, frozen, selection, resolver, manifest)

    opened = sealed_diagnostics.open_observation_for_development(
        request,
        repository=_repo(client),
        artifact_authority=_custodian(),
        lifecycle_authority=lifecycle_authority,
        reservation_authority=reservation_authority,
        resolver=resolver,
        selection=selection,
        manifest=manifest,
        review_resolver=review_resolver,
    )

    census = reservation_authority.current_census()
    assert existing_digest in census.accepted_event_digests
    assert set(opened.lifecycle_projection.influence_event_digests).issubset(census.accepted_event_digests)


def test_authority_persistence_failure_exposes_no_raw_artifact_and_preserves_active_lifecycle() -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    request, review_resolver = _request(bundle, predecessor, frozen, selection, resolver, manifest)
    client.put_error = RuntimeError("provider private path=/home/repository password=canary")

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        sealed_diagnostics.open_observation_for_development(
            request,
            repository=_repo(client),
            artifact_authority=_custodian(),
            lifecycle_authority=lifecycle_authority,
            reservation_authority=reservation.ReservationAuthority(resolver),
            resolver=resolver,
            selection=selection,
            manifest=manifest,
            review_resolver=review_resolver,
        )

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.AUTHORITY_PERSISTENCE_FAILED
    assert "private" not in str(captured.value)
    assert captured.value.__cause__ is None
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


def test_authority_commit_failure_returns_no_access_and_preserves_active_lifecycle(monkeypatch) -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    reservation_authority = reservation.ReservationAuthority(resolver)
    request, review_resolver = _request(bundle, predecessor, frozen, selection, resolver, manifest)

    def refuse_lifecycle_commit(_content: bytes):
        raise lifecycle.LifecycleError("private lifecycle failure")

    monkeypatch.setattr(lifecycle_authority, "append", refuse_lifecycle_commit)
    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        sealed_diagnostics.open_observation_for_development(
            request,
            repository=_repo(client),
            artifact_authority=_custodian(),
            lifecycle_authority=lifecycle_authority,
            reservation_authority=reservation_authority,
            resolver=resolver,
            selection=selection,
            manifest=manifest,
            review_resolver=review_resolver,
        )

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.AUTHORITY_COMMIT_FAILED
    assert captured.value.__cause__ is None
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


def test_operator_cannot_open_custodian_sealed_observation() -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    request, review_resolver = _request(bundle, predecessor, frozen, selection, resolver, manifest)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        sealed_diagnostics.open_observation_for_development(
            request,
            repository=_repo(client),
            artifact_authority=_authority(repository.ArtifactActorRole.OPERATOR),
            lifecycle_authority=lifecycle_authority,
            reservation_authority=reservation.ReservationAuthority(resolver),
            resolver=resolver,
            selection=selection,
            manifest=manifest,
            review_resolver=review_resolver,
        )

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.OBSERVATION_UNAVAILABLE
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


def test_foreign_observation_provenance_never_returns_raw_content() -> None:
    bundle, client, _, frozen = _frozen()
    accepted = _repo(client).get(
        frozen.reference,
        expected_kind=ArtifactKind.OBSERVATION,
        authority=_custodian(),
        expected_access_policy_digest=_digest("read-policy"),
    )
    foreign_content = canonical_artifact_bytes(
        ArtifactKind.OBSERVATION,
        accepted.artifact.payload,
        access_class=ArtifactAccessClass.CUSTODIAN_SEALED,
        provenance_digest=_digest("foreign-provenance"),
    )
    foreign_reference = artifact_reference(foreign_content)
    _repo(client).put_if_absent(foreign_content, reference=foreign_reference)
    foreign_result = observation_checkpoint.ArmCheckpointResultV1(
        observation_checkpoint.CheckpointStatus.COMPLETE,
        observation_checkpoint.CheckpointReason.NONE,
        frozen.plan_digest,
        frozen.arm_id,
        frozen.checkpoint_digest,
        foreign_reference,
        "",
    )
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    reads_before = len(client.get_calls)
    writes_before = len(client.put_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        _request(bundle, predecessor, foreign_result, selection, resolver, manifest)

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.INVALID_REQUEST
    assert foreign_content not in str(captured.value).encode()
    assert len(client.get_calls) == reads_before
    assert len(client.put_calls) == writes_before
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


def test_omitted_affected_network_is_rejected_before_sealed_observation_read() -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    request, _ = _request(bundle, predecessor, frozen, selection, resolver, manifest)
    assert len(request.subject.affected_networks) > 1
    reads_before = len(client.get_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        changed_subject = replace(
            request.subject,
            affected_networks=request.subject.affected_networks[:-1],
            subject_digest="",
        )
        replace(request, subject=changed_subject, request_digest="")

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.INVALID_REQUEST
    assert len(client.get_calls) == reads_before
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


@pytest.mark.parametrize("authority", ("manifest", "selection"))
def test_changed_population_authority_is_rejected_before_sealed_observation_read(authority: str) -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    request, review_resolver = _request(bundle, predecessor, frozen, selection, resolver, manifest)
    changed_manifest = replace(manifest, manifest_digest=_digest("changed-manifest")) if authority == "manifest" else manifest
    changed_selection = replace(selection, selection_digest=_digest("changed-selection")) if authority == "selection" else selection
    reads_before = len(client.get_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        sealed_diagnostics.open_observation_for_development(
            request,
            repository=_repo(client),
            artifact_authority=_custodian(),
            lifecycle_authority=lifecycle_authority,
            reservation_authority=reservation.ReservationAuthority(resolver),
            resolver=resolver,
            selection=changed_selection,
            manifest=changed_manifest,
            review_resolver=review_resolver,
        )

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.AFFECTED_AUTHORITY_MISMATCH
    assert len(client.get_calls) == reads_before
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


@pytest.mark.parametrize("mutation", ("extra", "substituted"))
def test_changed_affected_network_authority_is_rejected_before_sealed_read(mutation: str) -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    request, _ = _request(bundle, predecessor, frozen, selection, resolver, manifest)
    foreign = sealed_diagnostics.AffectedNetworkV1(
        "https://github.com/example/foreign",
        _digest("foreign-network"),
    )
    rows = (*request.subject.affected_networks, foreign)
    if mutation == "substituted":
        rows = (*request.subject.affected_networks[1:], foreign)
    reads_before = len(client.get_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        changed_subject = replace(request.subject, affected_networks=tuple(sorted(rows)), subject_digest="")
        replace(request, subject=changed_subject, request_digest="")

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.INVALID_REQUEST
    assert len(client.get_calls) == reads_before
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


@pytest.mark.parametrize("mutation", ("duplicate", "order"))
def test_noncanonical_affected_network_rows_are_not_requests(mutation: str) -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    request, _ = _request(bundle, predecessor, frozen, selection, resolver, manifest)
    rows = (*request.subject.affected_networks, request.subject.affected_networks[0])
    if mutation == "order":
        rows = tuple(reversed(request.subject.affected_networks))
    reads_before = len(client.get_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        replace(request.subject, affected_networks=rows, subject_digest="")

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.INVALID_REQUEST
    assert len(client.get_calls) == reads_before
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


def test_cross_population_checkpoint_is_rejected_before_raw_read_or_authority_write() -> None:
    bundle, client, _, frozen = _frozen()
    manifest, _, selection = _authorities()
    population_b = _digest("population-b")
    freeze_b = _digest("freeze-b")
    manifest_b = _manifest_for_population(manifest, population_b, freeze_b)
    manifest_contract.label_blind_population_manifest_bytes(manifest_b)
    lifecycle_authority, predecessor = _active(population_b, freeze_b)
    resolver = _resolver(selection)
    reads_before = len(client.get_calls)
    writes_before = len(client.put_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        sealed_diagnostics.build_development_access_subject(
            population_b,
            freeze_b,
            predecessor,
            frozen,
            bundle=bundle,
            resolver=resolver,
            selection=selection,
            manifest=manifest_b,
            artifact_access_policy_digest=_digest("read-policy"),
            lifecycle_review_policy_digest=_policy().policy_digest,
        )

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.INVALID_REQUEST
    assert len(client.get_calls) == reads_before
    assert len(client.put_calls) == writes_before
    lifecycle_authority.require_admission_eligible(population_b, freeze_b)


@pytest.mark.parametrize(
    "substitution",
    ("artifact_policy", "producer", "reviewer", "conflict", "lifecycle_policy", "review_policy"),
)
def test_post_construction_authority_substitution_is_rejected_before_raw_read_or_write(substitution: str) -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    reservation_authority = reservation.ReservationAuthority(resolver)
    request, review_resolver = _request(bundle, predecessor, frozen, selection, resolver, manifest)
    target, field, replacement = {
        "artifact_policy": (request.subject, "artifact_access_policy_digest", _digest("substituted-artifact-policy")),
        "producer": (request.review, "producer_identity", _digest("substituted-producer")),
        "reviewer": (request.review, "reviewer_identity", _digest("substituted-reviewer")),
        "conflict": (
            request.review,
            "conflict_disclosure",
            replace(request.review.conflict_disclosure, content_digest=_digest("substituted-conflict")),
        ),
        "lifecycle_policy": (request.subject, "lifecycle_review_policy_digest", _digest("substituted-lifecycle-policy")),
        "review_policy": (request.review_policy, "policy_digest", _digest("substituted-review-policy")),
    }[substitution]
    object.__setattr__(target, field, replacement)
    artifact_authority = _custodian()
    if substitution == "artifact_policy":
        artifact_authority = repository.artifact_read_authority(
            repository.ArtifactActorRole.CUSTODIAN,
            (repository.ArtifactReadPermission.CUSTODIAN_SEALED, repository.ArtifactReadPermission.PRIVATE),
            replacement,
            expected_access_policy_digest=replacement,
        )
    reads_before = len(client.get_calls)
    writes_before = len(client.put_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        sealed_diagnostics.open_observation_for_development(
            request,
            repository=_repo(client),
            artifact_authority=artifact_authority,
            lifecycle_authority=lifecycle_authority,
            reservation_authority=reservation_authority,
            resolver=resolver,
            selection=selection,
            manifest=manifest,
            review_resolver=review_resolver,
        )

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.INVALID_REQUEST
    assert len(client.get_calls) == reads_before
    assert len(client.put_calls) == writes_before
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


@pytest.mark.parametrize("forgery", ("direct", "replace", "reconstruct"))
def test_caller_created_review_authority_cannot_open_raw_observation(forgery: str) -> None:
    bundle, client, _, frozen = _frozen()
    _, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    request, _ = _request(bundle, predecessor, frozen, selection, resolver, manifest)
    forged_review = replace(
        request.review,
        producer_identity=_digest(f"forged-producer-{forgery}"),
        reviewer_identity=_digest(f"forged-reviewer-{forgery}"),
        attestation_digest="0" * 64,
    )
    forged_review = replace(forged_review, attestation_digest=derive_independence_attestation_digest(forged_review))
    reads_before = len(client.get_calls)
    writes_before = len(client.put_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        if forgery == "direct":
            sealed_diagnostics.DevelopmentAccessRequestV1(request.subject, forged_review, request.review_policy, "")
        elif forgery == "replace":
            replace(request, review=forged_review, request_digest="")
        else:
            values = {name: getattr(request, name) for name in request.__dataclass_fields__}
            values.update({"review": forged_review, "request_digest": ""})
            sealed_diagnostics.DevelopmentAccessRequestV1(**values)

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.INVALID_REQUEST
    assert len(client.get_calls) == reads_before
    assert len(client.put_calls) == writes_before


def test_forged_external_reviewer_is_not_admitted_by_review_policy() -> None:
    bundle, client, _, frozen = _frozen()
    _, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    request, review_resolver = _request(bundle, predecessor, frozen, selection, resolver, manifest)
    forged = replace(request.review, reviewer_identity=_digest("forged-external-reviewer"), attestation_digest="0" * 64)
    forged = replace(forged, attestation_digest=derive_independence_attestation_digest(forged))
    reads_before = len(client.get_calls)
    writes_before = len(client.put_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        sealed_diagnostics.build_development_access_request(
            request.subject,
            forged,
            request.review_policy,
            review_resolver,
        )

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.REVIEW_REQUIRED
    assert len(client.get_calls) == reads_before
    assert len(client.put_calls) == writes_before


def test_observation_bytes_are_not_read_until_all_authorities_are_durable_and_terminal(monkeypatch) -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _resolver(selection)
    reservation_authority = reservation.ReservationAuthority(resolver)
    request, review_resolver = _request(bundle, predecessor, frozen, selection, resolver, manifest)
    artifact_repository = _repo(client)
    original_get = artifact_repository.get

    def assert_terminal_before_get(*args, **kwargs):
        if kwargs.get("expected_kind") is ArtifactKind.OBSERVATION:
            with pytest.raises(lifecycle.LifecycleError, match="eligible"):
                lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)
            census = reservation_authority.current_census()
            assert set(census.reserved_network_digests) == {item.network_identity_digest for item in request.subject.affected_networks}
        return original_get(*args, **kwargs)

    monkeypatch.setattr(artifact_repository, "get", assert_terminal_before_get)
    sealed_diagnostics.open_observation_for_development(
        request,
        repository=artifact_repository,
        artifact_authority=_custodian(),
        lifecycle_authority=lifecycle_authority,
        reservation_authority=reservation_authority,
        resolver=resolver,
        selection=selection,
        manifest=manifest,
        review_resolver=review_resolver,
    )
