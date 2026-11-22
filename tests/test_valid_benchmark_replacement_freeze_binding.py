"""Replacement baseline freeze and causal binding integration (task 10.7).

The suite drives the complete synthetic pipeline -- fixtures, four reviewed
cohorts, positive-set closure, the validated ordinary draw -- into the one
integration freeze that closes group 10: new population/freeze identities, the
independently reviewed label-blind manifest, persisted public/private/sealed
partitions, the reviewed replacement-binding lifecycle event, and the read-only
reservation, lifecycle, capability, and custody rechecks. Every refusal path is
adversarial: a lowered bar can never produce a binding.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cohort_ingestion_fixtures import (  # noqa: E402
    _APPS,
    ECOSYSTEM_POLICY,
    ECOSYSTEM_PRODUCER,
    ECOSYSTEM_REVIEWER,
    GROUND_TRUTH_POLICY,
    READ_POLICY,
    _Client,
    _read_authority,
    _settings,
    candidate_for,
    case_for,
)
from detection_core_fixtures import stored_artifact  # noqa: E402
from test_valid_benchmark_ordinary_draw import (  # noqa: E402
    DRAW_POLICY,
    FULL_NAMES,
    SOURCE,
    OrdinaryFixtureHistory,
    _full_closed_batches,
)

from benchmarks.valid import historical_authorization as historical  # noqa: E402
from benchmarks.valid import (
    lifecycle,  # noqa: E402
    reservation,  # noqa: E402
)
from benchmarks.valid import population_label_blind as label_blind  # noqa: E402
from benchmarks.valid import population_materials as materials  # noqa: E402
from benchmarks.valid import replacement_freeze_binding as binding_module  # noqa: E402
from benchmarks.valid import replacement_freeze_binding_store as binding_store  # noqa: E402
from benchmarks.valid.artifact_repository import (  # noqa: E402
    ArtifactActorRole,
    ArtifactReadPermission,
    ArtifactRepositoryReason,
    S3ArtifactRepository,
    artifact_read_authority,
)
from benchmarks.valid.artifact_repository import ArtifactRepositoryError as StoreReadError  # noqa: E402
from benchmarks.valid.cohort_ingestion import CohortBatchStatus  # noqa: E402
from benchmarks.valid.ecosystem_review import (  # noqa: E402
    EcosystemReviewAttestationV1,
    EcosystemReviewDecision,
    review_repository_ecosystem,
)
from benchmarks.valid.ground_truth_review import (  # noqa: E402
    GroundTruthAttestationV1,
    GroundTruthStatus,
    VerifiedScope,
    review_ground_truth,
)
from benchmarks.valid.ordinary_change_contract import ReviewedPositiveInput  # noqa: E402
from benchmarks.valid.ordinary_draw import (  # noqa: E402
    MINIMUM_ORDINARY_PER_POSITIVE,
    OrdinaryPopulationHistorySource,
    draw_ordinary_population,
)
from benchmarks.valid.ordinary_draw_contract import ordinary_population_draw_bytes  # noqa: E402
from benchmarks.valid.ordinary_draw_store import decode_ordinary_population_draw  # noqa: E402
from benchmarks.valid.positive_set_closure import PositiveSetClosureStatus, project_positive_set_closure  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import ArtifactAccessClass, canonical_json_bytes  # noqa: E402
from benchmarks.valid.store_configuration import StoreCapabilityEvidence, StorePurpose  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402
from openultrasast.core.custody import PopulationStatus, empty_population_custody_log  # noqa: E402
from openultrasast.core.factpack import (  # noqa: E402
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_POLICY = content_digest({"policy": "historical-review-v1"})
BINDING_POLICY = content_digest({"policy": "replacement-binding-review-v1"})
BINDING_PRODUCER = "binding-producer@example.invalid"
BINDING_REVIEWER = "binding-reviewer@example.invalid"
PARTITION_POLICY = content_digest({"policy": "material-partition-policy-v1"})
FREEZE_POLICY = content_digest({"policy": "population-freeze-v1", "minimum": 40})
PROVENANCE = content_digest({"source": "replacement-fixture-pipeline"})
RESERVED_REPOSITORY = "https://github.com/acme/reserved"
MANIFEST_PRODUCER = content_digest({"identity": "manifest-producer"})
MANIFEST_REVIEWER = content_digest({"identity": "manifest-reviewer"})
CUSTODIAN = content_digest({"identity": "fixture-custodian"})


def _reviewed(name: str, resolved) -> ReviewedPositiveInput:
    """Rebuild the exact reviewed input the cohort ledger accepted for one name."""
    ecosystem = "python" if case_for(name)["repo"].startswith("fixture/cohort-py") else "javascript"
    candidate = candidate_for(name, resolved)
    eco = review_repository_ecosystem(
        candidate,
        EcosystemReviewAttestationV1(
            candidate.candidate_digest,
            candidate.source_evidence.evidence_digest,
            ECOSYSTEM_PRODUCER,
            ECOSYSTEM_REVIEWER,
            True,
            ECOSYSTEM_POLICY,
            True,
            EcosystemReviewDecision(ecosystem),
        ),
        expected_policy_digest=ECOSYSTEM_POLICY,
    )
    locator = f"GHSA-cohort-{name}"
    truth = review_ground_truth(
        candidate,
        eco,
        GroundTruthAttestationV1(
            candidate.candidate_digest,
            eco.review_digest,
            f"producer-{locator}@example.invalid",
            f"reviewer-{locator}@example.invalid",
            True,
            GROUND_TRUTH_POLICY,
            True,
            True,
            True,
            True,
            (VerifiedScope(case_for(name)["family"], ecosystem),),
            None,
        ),
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    assert truth.status is GroundTruthStatus.ACCEPTED
    return ReviewedPositiveInput(candidate, eco, truth)


@lru_cache(maxsize=1)
def _pipeline():
    batches, resolved = _full_closed_batches()
    reviewed = tuple(_reviewed(name, resolved) for name in FULL_NAMES)
    ledger_changes = {
        positive.change_identity_digest
        for batch in batches
        if batch.status is CohortBatchStatus.ACCEPTED
        for positive in batch.accepted_positives
    }
    assert {item.ground_truth_review.change_identity_digest for item in reviewed} == ledger_changes
    return batches, resolved, reviewed


def _networks():
    networks = [reservation.build_network_identity(app["url"]) for app in _APPS.values()]
    networks.append(reservation.build_network_identity(RESERVED_REPOSITORY))
    return reservation.RepositoryIdentityResolver(networks)


def _reserved_authority():
    resolved = _networks()
    legacy = reservation.legacy_reservation_source(
        resolved,
        repository=RESERVED_REPOSITORY,
        source_digest=content_digest({"legacy": "reserved-history"}),
    )
    authority = reservation.ReservationAuthority(resolved, legacy_sources=(legacy,))
    return resolved, authority, authority.current_census()


@lru_cache(maxsize=1)
def _draw(census_key: str = "reserved"):
    batches, _, _ = _pipeline()
    resolved, authority, census = _reserved_authority()
    history = OrdinaryFixtureHistory(FULL_NAMES)
    candidates = {name: candidate_for(name, resolved) for name in FULL_NAMES}
    by_digest = {item.candidate_digest: item for item in candidates.values()}
    sources = {
        item.network_identity_digest: OrdinaryPopulationHistorySource(
            history, item.canonical_repository, item.network_identity_digest, SOURCE
        )
        for item in by_digest.values()
    }
    draw = draw_ordinary_population(
        batches,
        candidates_by_digest=by_digest,
        history_by_network=sources,
        reservation_census=census,
        required_per_positive=MINIMUM_ORDINARY_PER_POSITIVE,
        policy_digest=DRAW_POLICY,
    )
    return draw, resolved, authority, census


def _manifest_review(draft: label_blind.LabelBlindPopulationDraftV3) -> IndependenceAttestation:
    disclosure, _ = stored_artifact(b'{"conflicts":[]}', artifact_id="binding-conflicts")
    seeded = IndependenceAttestation(
        draft.draft_digest,
        MANIFEST_PRODUCER,
        MANIFEST_REVIEWER,
        disclosure,
        "0" * 64,
    )
    return replace(seeded, attestation_digest=derive_independence_attestation_digest(seeded))


def _manifest_policy() -> ReviewIndependencePolicy:
    digest = derive_review_independence_policy_digest((MANIFEST_REVIEWER,), (), ("trusted-store",), 4096)
    return ReviewIndependencePolicy((MANIFEST_REVIEWER,), (), ("trusted-store",), 4096, digest)


def _environment() -> dict[str, str]:
    return {
        "VALID_BENCHMARK_DURABLE_S3_ENDPOINT": "https://durable.invalid:9000",
        "VALID_BENCHMARK_DURABLE_S3_BUCKET": "valid-benchmark-durable",
        "VALID_BENCHMARK_DURABLE_AWS_ACCESS_KEY_ID": "durable-key",
        "VALID_BENCHMARK_DURABLE_AWS_SECRET_ACCESS_KEY": "durable-secret",
        "VALID_BENCHMARK_TRANSIENT_S3_ENDPOINT": "https://transient.invalid:9000",
        "VALID_BENCHMARK_TRANSIENT_S3_BUCKET": "valid-benchmark-runs",
        "VALID_BENCHMARK_TRANSIENT_AWS_ACCESS_KEY_ID": "transient-key",
        "VALID_BENCHMARK_TRANSIENT_AWS_SECRET_ACCESS_KEY": "transient-secret",
    }


def _evidence(purpose: StorePurpose, *, versioning: bool = True) -> StoreCapabilityEvidence:
    current = None if purpose is StorePurpose.DURABLE else 14
    noncurrent = 30 if purpose is StorePurpose.DURABLE else 1
    return StoreCapabilityEvidence(
        purpose=purpose,
        versioning_enabled=versioning,
        conditional_create=True,
        conditional_update=True,
        current_version_expiry_days=current,
        noncurrent_version_expiry_days=noncurrent,
    )


def _capabilities(*, versioning: bool = True) -> dict[StorePurpose, StoreCapabilityEvidence]:
    return {purpose: _evidence(purpose, versioning=versioning) for purpose in StorePurpose}


def _material_inputs(changes) -> tuple[materials.PopulationMaterialInputV1, ...]:
    return tuple(
        materials.PopulationMaterialInputV1(
            change,
            materials.LicenseClass.PERMISSIVE if index % 5 else materials.LicenseClass.NON_PERMISSIVE,
            "Apache-2.0" if index % 5 else "BUSL-1.1",
            f"public source {index}".encode(),
            f"sealed label {index}".encode(),
            f"sealed review {index}".encode(),
            index % 5 == 1,
        )
        for index, change in enumerate(changes)
    )


def _historical_review(subject: str) -> bytes:
    value: dict[str, object] = {
        "schema_version": historical.HISTORICAL_REVIEW_SCHEMA,
        "subject_digest": subject,
        "decision": "authorize_exact_historical_audit",
        "producer_identity": "custodian",
        "reviewer_identity": "historical-reviewer",
        "conflict_disclosed": True,
        "policy_digest": HISTORICAL_POLICY,
    }
    value["review_digest"] = content_digest(value)
    return canonical_json_bytes(value)


def _withdrawal(guard_root: Path) -> historical.HistoricalWithdrawalV1:
    inventory = historical.pinned_historical_inventory(guard_root)
    candidate = historical.build_withdrawal_candidate(inventory)
    return historical.accept_reviewed_withdrawal(candidate, _historical_review(candidate.candidate_digest))


def _bind(
    guard_root: Path,
    *,
    positives=None,
    batches=None,
    draw=None,
    census=None,
    review=None,
    capabilities=None,
    minimums=(),
    forbidden=(),
):
    draw_value, resolved, authority, bound_census = _draw()
    batches_value, _, reviewed = _pipeline()
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="binding-conflicts")
    return binding_module.bind_replacement_baseline(
        positives if positives is not None else reviewed,
        batches if batches is not None else batches_value,
        ordinary_draw=draw if draw is not None else draw_value,
        reservation_census=census if census is not None else bound_census,
        reservation_authority=authority,
        material_inputs=_material_inputs(draw_value.positive_change_digests),
        partition_policy_digest=PARTITION_POLICY,
        manifest_review=review if review is not None else _manifest_review,
        manifest_policy=_manifest_policy(),
        disclosure_resolver=resolver,
        historical_withdrawal=_withdrawal(guard_root),
        binding_producer_identity=BINDING_PRODUCER,
        binding_reviewer_identity=BINDING_REVIEWER,
        binding_policy_digest=BINDING_POLICY,
        guard_scan_root=guard_root,
        scope_minimums=minimums,
        exclusion_counts=(("review_excluded", 2),),
        source_provenance_digest=PROVENANCE,
        freeze_policy_digest=FREEZE_POLICY,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        forbidden_historical_identities=forbidden,
        store_environ=_environment(),
        capability_evidence=capabilities if capabilities is not None else _capabilities(),
    )


class _ExactValidator:
    def __init__(self, expected) -> None:
        self.expected = expected

    def validate(self, freeze) -> bytes:
        from benchmarks.valid.population_freeze import population_freeze_bytes

        if freeze != self.expected:
            raise materials.PopulationMaterialError("freeze does not replay from exact authorities")
        return population_freeze_bytes(freeze)


def _binding_artifacts(guard_root: Path, binding):
    """Independently re-derive every artifact the binding names."""
    draw, _, _, census = _draw()
    _, _, reviewed = _pipeline()
    selection = binding_module.ordinary_selection_from_draw(draw)
    freeze = binding_module.freeze_replacement_baseline(
        reviewed,
        ordinary_selection=selection,
        reservation_census=census,
        reservation_authority=_reserved_authority()[1],
        exclusion_counts=(("review_excluded", 2),),
        source_provenance_digest=PROVENANCE,
        freeze_policy_digest=FREEZE_POLICY,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    partition = materials.build_population_material_partition(
        freeze,
        _material_inputs(freeze.positive_change_digests),
        freeze_validator=_ExactValidator(freeze),
        partition_policy_digest=PARTITION_POLICY,
    )
    draft = label_blind.build_label_blind_population_draft(freeze, partition, selection)
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="binding-conflicts")
    manifest = label_blind.review_label_blind_population_manifest(draft, _manifest_review(draft), _manifest_policy(), resolver)
    return draw, selection, freeze, partition, manifest


@pytest.fixture()
def guard_root(tmp_path: Path) -> Path:
    for relative in historical.PINNED_HISTORICAL_DIGESTS:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for name in ("benchmarks", "src", "tests", "plane"):
        (tmp_path / name).mkdir(exist_ok=True)
    return tmp_path


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("network or SZZ was invoked")

    import socket

    from benchmarks.unseen import extract

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(extract, "introducing", forbidden)
    monkeypatch.setattr(extract.Git, "blame", forbidden)


def test_pipeline_closes_with_forty_eight_reviewed_positives() -> None:
    batches, _, reviewed = _pipeline()
    closure = project_positive_set_closure(batches)
    draw, _, _, _ = _draw()

    assert closure.status is PositiveSetClosureStatus.CLOSED
    assert closure.total_accepted_positives == 48
    assert len(reviewed) == 48
    assert {item.ground_truth_review.change_identity_digest for item in reviewed} == set(draw.positive_change_digests)


def test_pipeline_freeze_is_admission_class_under_new_identities(guard_root) -> None:
    _, _, _, census = _draw()
    _, _, reviewed = _pipeline()
    draw, selection, freeze, partition, manifest = _binding_artifacts(guard_root, None)
    pilot = json.loads((ROOT / "benchmarks/valid/pilot/freeze-valid.json").read_text())

    assert freeze.population_class is binding_module.PopulationClass.ADMISSION
    assert freeze.positive_count == 48
    assert freeze.reservation_census_digest == census.census_digest
    assert selection.selection_digest == freeze.ordinary_selection_digest
    assert (freeze.population_digest, freeze.freeze_digest) != (None, pilot["freeze_digest"])
    assert freeze.freeze_digest != pilot["freeze_digest"]


def test_binding_names_every_independently_derived_artifact(guard_root) -> None:
    binding = _bind(guard_root)
    draw, selection, freeze, partition, manifest = _binding_artifacts(guard_root, binding)
    withdrawal = _withdrawal(guard_root)
    _, _, _, census = _draw()

    assert binding.population_digest == freeze.population_digest
    assert binding.freeze_digest == freeze.freeze_digest
    assert binding.closure_digest == project_positive_set_closure(_pipeline()[0]).closure_digest
    assert binding.ordinary_draw_digest == draw.draw_digest
    assert binding.ordinary_selection_digest == selection.selection_digest
    assert binding.material_manifest_digest == partition.manifest.manifest_digest
    assert binding.private_object_digest == partition.manifest.private_object_digest
    assert binding.sealed_label_digest == partition.manifest.sealed_label_digest
    assert binding.manifest_digest == manifest.manifest_digest
    assert binding.reservation_census_digest == census.census_digest
    assert binding.historical_withdrawal_digest == withdrawal.withdrawal_digest
    content = binding_module.replacement_baseline_binding_bytes(binding)
    assert content and binding_store.decode_replacement_baseline_binding(content) == binding


def test_binding_replays_byte_identically_from_permuted_inputs(guard_root) -> None:
    batches, _, reviewed = _pipeline()
    first = _bind(guard_root)
    second = _bind(guard_root, positives=tuple(reversed(reviewed)), batches=tuple(reversed(batches)))

    assert binding_module.replacement_baseline_binding_bytes(first) == binding_module.replacement_baseline_binding_bytes(second)
    assert first.binding_digest == second.binding_digest


def test_lifecycle_event_binds_exact_withdrawal_population_and_freeze(guard_root) -> None:
    binding = _bind(guard_root)
    withdrawal = _withdrawal(guard_root)
    root_event, replacement_event = binding_module.replacement_lifecycle_events(
        withdrawal,
        population_digest=binding.population_digest,
        freeze_digest=binding.freeze_digest,
        producer_identity=BINDING_PRODUCER,
        reviewer_identity=BINDING_REVIEWER,
        policy_digest=BINDING_POLICY,
    )
    authority = lifecycle.BaselineLifecycleAuthority()
    root = authority.append(root_event)
    decoded = lifecycle.decode_lifecycle_event(replacement_event)
    projection = authority.append(replacement_event)

    assert root.state is lifecycle.PopulationLifecycleState.REPLACEMENT_PENDING
    assert decoded.kind is lifecycle.PopulationLifecycleKind.REPLACEMENT_BOUND
    assert decoded.predecessor_digest == lifecycle.decode_lifecycle_event(root_event).event_digest
    assert decoded.historical_withdrawal_digest == withdrawal.withdrawal_digest
    assert (decoded.population_digest, decoded.freeze_digest) == (binding.population_digest, binding.freeze_digest)
    assert projection.state is lifecycle.PopulationLifecycleState.REPLACEMENT_COMPLETE
    assert projection.admission_eligible
    assert binding.lifecycle_projection_digest == projection.projection_digest
    assert authority.require_admission_eligible(binding.population_digest, binding.freeze_digest) == projection


def test_historical_pilot_remains_withdrawn_and_byte_identical(guard_root) -> None:
    before = {path: (ROOT / path).read_bytes() for path in historical.PINNED_HISTORICAL_DIGESTS}
    withdrawal = _withdrawal(guard_root)
    binding = _bind(guard_root)

    for path, content in before.items():
        assert (ROOT / path).read_bytes() == content
        assert hashlib.sha256(content).hexdigest() == historical.PINNED_HISTORICAL_DIGESTS[path]
    assert historical.pinned_historical_inventory(ROOT).inventory_digest == withdrawal.inventory_digest
    assert binding.historical_withdrawal_digest == withdrawal.withdrawal_digest
    with pytest.raises(historical.HistoricalAuthorizationError):
        historical.require_current_qualification(withdrawal)
    rebuilt = historical.build_withdrawal_candidate(historical.pinned_historical_inventory(guard_root))
    assert historical.accept_reviewed_withdrawal(rebuilt, _historical_review(rebuilt.candidate_digest)) == withdrawal


def test_label_blind_manifest_resolves_exactly_and_stays_label_blind(guard_root) -> None:
    binding = _bind(guard_root)
    _, selection, freeze, partition, manifest = _binding_artifacts(guard_root, binding)
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="binding-conflicts")
    content = label_blind.validate_label_blind_population_manifest(
        manifest, freeze, partition, selection, _manifest_review(
            label_blind.build_label_blind_population_draft(freeze, partition, selection)
        ), _manifest_policy(), resolver
    )

    assert content == label_blind.label_blind_population_manifest_bytes(manifest)
    assert manifest.manifest_digest == binding.manifest_digest
    assert manifest.positive_count == 48
    assert manifest.input_count == 48 + 48 * MINIMUM_ORDINARY_PER_POSITIVE
    value = json.loads(content)
    assert not any("label" in key or "judg" in key or "verdict" in key for key in value)
    assert set(manifest.input_digests) == {
        *freeze.positive_change_digests,
        *(push.push_digest for push in selection.pushes),
    }


def test_partitions_persist_under_public_private_and_sealed_access(guard_root) -> None:
    binding = _bind(guard_root)
    _, _, freeze, partition, manifest = _binding_artifacts(guard_root, binding)
    events = binding_module.replacement_lifecycle_events(
        _withdrawal(guard_root),
        population_digest=binding.population_digest,
        freeze_digest=binding.freeze_digest,
        producer_identity=BINDING_PRODUCER,
        reviewer_identity=BINDING_REVIEWER,
        policy_digest=BINDING_POLICY,
    )
    store = S3ArtifactRepository(_settings(), _Client())
    references = binding_store.persist_replacement_baseline(
        store, binding=binding, freeze=freeze, manifest=manifest, partition=partition, lifecycle_events=events
    )
    operator = _read_authority()
    custodian = artifact_read_authority(
        ArtifactActorRole.CUSTODIAN,
        (ArtifactReadPermission.PRIVATE, ArtifactReadPermission.CUSTODIAN_SEALED),
        READ_POLICY,
        expected_access_policy_digest=READ_POLICY,
    )

    assert references.public_manifest.access_class is ArtifactAccessClass.PUBLIC
    assert references.private_object.access_class is ArtifactAccessClass.PRIVATE
    assert references.sealed_labels.access_class is ArtifactAccessClass.CUSTODIAN_SEALED
    assert references.binding.access_class is ArtifactAccessClass.OPERATOR_SAFE
    public_read = store.get(
        references.public_manifest,
        expected_kind=references.public_manifest.artifact_kind,
        authority=operator,
        expected_access_policy_digest=READ_POLICY,
    )
    serialized = json.dumps(public_read.artifact.payload)
    assert "label_base64" not in serialized and "judgment_base64" not in serialized
    assert b"sealed label" not in serialized.encode() and b"sealed review" not in serialized.encode()
    for reference in (references.sealed_labels, references.private_object):
        with pytest.raises(StoreReadError) as error:
            store.get(reference, expected_kind=reference.artifact_kind, authority=operator, expected_access_policy_digest=READ_POLICY)
        assert error.value.reason is ArtifactRepositoryReason.NOT_AUTHORIZED
    sealed_read = store.get(
        references.sealed_labels,
        expected_kind=references.sealed_labels.artifact_kind,
        authority=custodian,
        expected_access_policy_digest=READ_POLICY,
    )
    assert sealed_read.artifact.access_class is ArtifactAccessClass.CUSTODIAN_SEALED
    resumed = binding_store.resume_replacement_baseline_binding(
        store, references.binding, authority=operator, expected_access_policy_digest=READ_POLICY
    )
    assert resumed == binding


def test_unclosed_positive_set_is_refused(guard_root) -> None:
    batches, _, _ = _pipeline()

    with pytest.raises(binding_module.ReplacementBindingError) as error:
        _bind(guard_root, batches=batches[:2])
    assert error.value.reason is binding_module.ReplacementBindingReason.POSITIVE_SET_NOT_CLOSED


def test_draw_bound_to_a_different_census_is_refused(guard_root) -> None:
    batches, _, _ = _pipeline()
    resolved = _networks()
    plain = reservation.ReservationAuthority(resolved)
    plain_census = plain.current_census()
    history = OrdinaryFixtureHistory(FULL_NAMES)
    candidates = {name: candidate_for(name, resolved) for name in FULL_NAMES}
    by_digest = {item.candidate_digest: item for item in candidates.values()}
    sources = {
        item.network_identity_digest: OrdinaryPopulationHistorySource(
            history, item.canonical_repository, item.network_identity_digest, SOURCE
        )
        for item in by_digest.values()
    }
    foreign = draw_ordinary_population(
        batches,
        candidates_by_digest=by_digest,
        history_by_network=sources,
        reservation_census=plain_census,
        required_per_positive=MINIMUM_ORDINARY_PER_POSITIVE,
        policy_digest=DRAW_POLICY,
    )
    assert foreign.reservation_census_digest != _draw()[3].census_digest

    with pytest.raises(binding_module.ReplacementBindingError) as error:
        _bind(guard_root, draw=foreign)
    assert error.value.reason is binding_module.ReplacementBindingReason.ORDINARY_DRAW_REFUSED


def test_truncated_draw_bytes_fail_hostile_decode_before_any_binding(guard_root) -> None:
    draw, _, _, _ = _draw()
    content = ordinary_population_draw_bytes(draw)

    with pytest.raises(Exception) as error:
        decode_ordinary_population_draw(content[:-8])
    assert isinstance(error.value, ValueError)


def test_unreviewed_manifest_is_refused(guard_root) -> None:
    def self_reviewed(draft: label_blind.LabelBlindPopulationDraftV3) -> IndependenceAttestation:
        review = _manifest_review(draft)
        return replace(review, producer_identity=review.reviewer_identity)

    def stale(draft: label_blind.LabelBlindPopulationDraftV3) -> IndependenceAttestation:
        return _manifest_review(replace(draft, draft_digest="1" * 64 if draft.draft_digest[0] != "1" else "2" * 64))

    for review in (self_reviewed, stale):
        with pytest.raises(binding_module.ReplacementBindingError) as error:
            _bind(guard_root, review=review)
        assert error.value.reason is binding_module.ReplacementBindingReason.MANIFEST_UNREVIEWED


def test_missing_store_capability_is_refused(guard_root) -> None:
    with pytest.raises(binding_module.ReplacementBindingError) as error:
        _bind(guard_root, capabilities=_capabilities(versioning=False))
    assert error.value.reason is binding_module.ReplacementBindingReason.STORE_CAPABILITY_MISSING


def test_infeasible_scope_minimum_cannot_bind_as_the_replacement(guard_root) -> None:
    minimums = (binding_module.ScopeMinimumV1("injection", "python", 999),)

    with pytest.raises(binding_module.ReplacementBindingError) as error:
        _bind(guard_root, minimums=minimums)
    assert error.value.reason is binding_module.ReplacementBindingReason.POPULATION_NOT_ADMISSION_CLASS


def test_historical_identity_reuse_is_refused(guard_root) -> None:
    binding = _bind(guard_root)
    pilot = json.loads((ROOT / "benchmarks/valid/pilot/freeze-valid.json").read_text())

    assert binding.freeze_digest != pilot["freeze_digest"]
    with pytest.raises(binding_module.ReplacementBindingError) as error:
        _bind(guard_root, forbidden=(binding.population_digest, binding.freeze_digest, pilot["freeze_digest"]))
    assert error.value.reason is binding_module.ReplacementBindingReason.FREEZE_REFUSED


def test_doctored_reservation_census_is_refused(guard_root) -> None:
    _, _, census = _reserved_authority()
    stale = replace(census, reserved_network_digests=(*census.reserved_network_digests, "3" * 64))

    with pytest.raises(binding_module.ReplacementBindingError) as error:
        _bind(guard_root, census=stale)
    assert error.value.reason is binding_module.ReplacementBindingReason.INVALID_REQUEST


def test_no_admission_run_consumed_labels_and_custody_stays_available(guard_root, monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("admission authority was invoked during the replacement binding")

    from benchmarks.valid.admission_orchestrator import AdmissionOrchestrator
    from benchmarks.valid.durable_custody_store import S3DurableCustodyStore

    monkeypatch.setattr(AdmissionOrchestrator, "preflight", forbidden)
    monkeypatch.setattr(S3DurableCustodyStore, "compare_and_swap", forbidden)
    source = (ROOT / "benchmarks/valid/replacement_freeze_binding.py").read_text()
    for forbidden_symbol in (
        "admission_orchestrator",
        "admission_execution",
        "admission_spend",
        "arm_contract",
        "compare_and_swap",
        "record_population_use",
        "authorize_evaluation",
        "decode_arm_observation_set",
    ):
        assert forbidden_symbol not in source

    binding = _bind(guard_root)
    log = empty_population_custody_log(binding.population_digest, CUSTODIAN)
    binding_module.require_baseline_custody_available(binding, log)

    assert log.status is PopulationStatus.AVAILABLE
    assert log.receipt_count == 0 and log.receipts == ()
    spent = replace(log, receipt_count=1)
    with pytest.raises(binding_module.ReplacementBindingError) as error:
        binding_module.require_baseline_custody_available(binding, spent)
    assert error.value.reason is binding_module.ReplacementBindingReason.CUSTODY_NOT_AVAILABLE
    other = empty_population_custody_log("4" * 64, CUSTODIAN)
    with pytest.raises(binding_module.ReplacementBindingError):
        binding_module.require_baseline_custody_available(binding, other)


def test_binding_decode_refuses_hostile_and_noncanonical_bytes(guard_root) -> None:
    binding = _bind(guard_root)
    good = binding_module.replacement_baseline_binding_bytes(binding)

    for content in (b"", b"{", good + b" ", b'{"schema_version": "x", "value": NaN}'):
        with pytest.raises(binding_module.ReplacementBindingStateError):
            binding_store.decode_replacement_baseline_binding(content)
    assert binding_store.decode_replacement_baseline_binding(good) == binding
