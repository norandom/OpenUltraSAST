"""Task 11.3 synthetic two-ecosystem, multi-family, multi-arm lifecycle fixtures.

The population mirrors the committed 8.1-8.2 execution fixtures but claims two
ecosystems through two families (exactly one family per ecosystem, so every
ordinary push resolves to one planned scope), seals label-blind observations
whose case identities are the core wrapper digests over real evidence records,
and mints the custodian case-content port plus the corrected-census and
recomposed-plan reviews that the 11.3 conversion adapter validates.
"""

from __future__ import annotations

import base64
import sys
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import InMemoryContentResolver, custody_contract, stored_artifact  # noqa: E402
from test_core_admission_context import _case as _core_context_case  # noqa: E402
from test_core_admission_release import _canonical_evidence_inputs, _case_result  # noqa: E402
from test_core_consumer_v2 import _proof  # noqa: E402
from test_core_evaluation_case_validation import (  # noqa: E402
    _canonical_legacy_case,
    _contract_for_scope,
    _distinct_evidence_input,
    _with_model_context,
)
from test_core_readiness import _chain as _readiness_chain  # noqa: E402
from test_valid_benchmark_admission_execution import (  # noqa: E402
    NAMESPACE,
    _Adapter,
    _read_rows,
    _stage_rows,
    _union_rule,
)
from test_valid_benchmark_admission_spend import LABEL_MARKER  # noqa: E402
from test_valid_benchmark_arm_registry import _registration  # noqa: E402
from test_valid_benchmark_orchestrator import (  # noqa: E402
    ACCESS_POLICY,
    REVIEWER,
    _attestation,
    _capability_report,
    _Client,
    _configuration,
    _digest,
    _lifecycle,
    _policy,
    _settings,
    _SpyExecutor,
)

from benchmarks.valid import admission_spend as spend  # noqa: E402
from benchmarks.valid import isolated_execution as execution  # noqa: E402
from benchmarks.valid import observation_checkpoint as checkpoint  # noqa: E402
from benchmarks.valid.admission_execution import AdmissionExecutionRequestV1  # noqa: E402
from benchmarks.valid.admission_orchestrator import (  # noqa: E402
    AdmissionExecutionBindingV1,
    AdmissionOrchestrator,
    AdmissionRunRequestV1,
    admission_census_payload_digest,
    admission_manifest_payload_digest,
    compose_plan_manifest,
    compose_population_census,
)
from benchmarks.valid.arm_combination import CombinationRuleKindV1, CombinationRuleRegistrationV1  # noqa: E402
from benchmarks.valid.arm_contract import ArmRole, register_evaluation_plan  # noqa: E402
from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.durable_custody_store import DurableCustodyStoreError, S3DurableCustodyStore  # noqa: E402
from benchmarks.valid.isolated_execution_bundle import build_component_execution_bundles  # noqa: E402
from benchmarks.valid.isolated_execution_contract import ExecutionAdapterKind  # noqa: E402
from benchmarks.valid.ordinary_change_contract import (  # noqa: E402
    OrdinaryDrawAssignmentV1,
    OrdinaryFixExclusionV1,
    OrdinaryPushV1,
    OrdinarySelectionV1,
    _fix_exclusion_value,
    _push_value,
    _selection_value,
)
from benchmarks.valid.population_freeze import CanonicalEcosystem  # noqa: E402
from benchmarks.valid.population_freeze_contract import (  # noqa: E402
    PopulationClass,
    PopulationClassificationReason,
    PopulationFreezeV3,
    PopulationScopeCountV1,
    _freeze_value,
    _population_value,
)
from benchmarks.valid.population_label_blind import review_label_blind_population_manifest  # noqa: E402
from benchmarks.valid.population_label_blind_contract import LabelBlindPopulationDraftV3, _draft_value  # noqa: E402
from benchmarks.valid.population_material_contract import (  # noqa: E402
    LicenseClass,
    OpaquePrivateMaterialRefV1,
    PublicPopulationMaterialManifestV1,
    PublicSourceRecordV1,
    _manifest_value,
)
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
)
from benchmarks.valid.store_configuration import StorePurpose, store_namespace_identity  # noqa: E402
from benchmarks.valid.workflow_journal import S3WorkflowJournal  # noqa: E402
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.admission_case import AdmissionCaseResult, AdmissionCaseRole  # noqa: E402
from openultrasast.core.admission_context import make_admission_validation_context  # noqa: E402
from openultrasast.core.canonical import ResolvedContent  # noqa: E402
from openultrasast.core.custody import (  # noqa: E402
    empty_population_custody_log,
)
from openultrasast.core.evaluation_case_outcome import (  # noqa: E402
    CaseOutcomeProjectionPolicyV3,
    CaseOutcomeProjectionV3,
    derive_component_case_outcome_projection,
)
from openultrasast.core.evaluation_measurement import ArmKindV3, ScopeKey  # noqa: E402
from openultrasast.core.evaluation_observation import ArmObservationSetV3, ObservationCaseRefV3  # noqa: E402
from openultrasast.core.evaluation_plan import (  # noqa: E402
    EcosystemOrdinaryCensusV3,
    ExactScopeCensusV3,
    PopulationCensusV3,
    derive_evaluation_census_digest,
    derive_evaluation_census_payload_digest,
    derive_evaluation_input_set_digest,
)
from openultrasast.core.evaluation_release import (  # noqa: E402
    ProofCandidateIdentityV3,
    derive_proof_candidate_identity_digest,
)
from openultrasast.core.factpack import (  # noqa: E402
    ReviewIndependencePolicy,
    derive_review_independence_policy_digest,
)
from openultrasast.core.measurement import ScopeKey as LegacyScopeKey  # noqa: E402
from openultrasast.core.validation import make_evidence_validation_context  # noqa: E402

FAMILY_PY = "reference_family"
FAMILY_JS = "other_family"
E2E_CUSTODY_POLICY = custody_contract()[1]
E2E_CUSTODIAN = custody_contract()[2]
SCOPE_PY = ScopeKey(FAMILY_PY, "python")
SCOPE_JS = ScopeKey(FAMILY_JS, "javascript")
SCOPES = (SCOPE_PY, SCOPE_JS)
PLANNED_ARMS = ("arm-combined", "arm-experimental", "arm-shipped")
ANCHOR_ARM = "arm-combined"
EXPERIMENTAL_ARM = "arm-experimental"
BRIDGE_STORE = "scoped-admission-v3-bridge"
BRIDGE_RETENTION = _digest("bridge-retention-11-3")
WORKFLOW = _digest("workflow-11-3")
PUBLIC_STATUS_SCHEMA = "openultrasast.detection-core.evaluation-public-status.v3"
ZERO = "0" * 64
PAIRS_PY = 10
PAIRS_JS = 10


class _InputIdentity:
    """One population input with its exact scope, role, and pair assignment."""

    def __init__(self, raw: str, scope: ScopeKey, role: AdmissionCaseRole, pair: str | None) -> None:
        self.raw = raw
        self.scope = scope
        self.role = role
        self.pair = pair


def _relax_precision(configuration, rule=None):
    """Relax Wilson precision the way the core multi-family fixtures do."""
    sufficiency = tuple(
        replace(
            row,
            precision_rules=tuple(
                replace(precision, maximum_wilson_width=100.0, minimum_denominator=1, rule_digest="")
                for precision in row.precision_rules
            ),
            rule_digest="",
        )
        for row in configuration.sufficiency_rules
    )
    changes: dict[str, object] = {"sufficiency_rules": sufficiency, "configuration_identity_digest": ""}
    if rule is not None:
        changes["combination_rule"] = rule
    return replace(configuration, **changes)


def _positive_identities(pairs_python: int, pairs_javascript: int) -> tuple[_InputIdentity, ...]:
    rows = []
    for scope, pairs in ((SCOPE_PY, pairs_python), (SCOPE_JS, pairs_javascript)):
        for pair in range(pairs):
            for side, role in (("vulnerable", AdmissionCaseRole.VULNERABLE), ("fixed", AdmissionCaseRole.FIXED)):
                rows.append(
                    _InputIdentity(
                        _digest(f"e2e-positive-{scope.family_id}-{scope.ecosystem}-{pair}-{side}"),
                        scope,
                        role,
                        _digest(f"e2e-pair-{scope.family_id}-{pair}"),
                    )
                )
    return tuple(sorted(rows, key=lambda item: item.raw))


def _freeze(positives: tuple[_InputIdentity, ...]) -> PopulationFreezeV3:
    counts = {SCOPE_PY: 0, SCOPE_JS: 0}
    for row in positives:
        counts[row.scope] += 1
    scope_census = tuple(
        sorted(
            (
                PopulationScopeCountV1(FAMILY_PY, CanonicalEcosystem.PYTHON, counts[SCOPE_PY]),
                PopulationScopeCountV1(FAMILY_JS, CanonicalEcosystem.JAVASCRIPT, counts[SCOPE_JS]),
            )
        )
    )
    positive_count = len(positives)
    changes = tuple(sorted(row.raw for row in positives))
    ecosystem_reviews = tuple(sorted(_digest(f"e2e-eco-{index}") for index in range(positive_count)))
    ground_truth_reviews = tuple(sorted(_digest(f"e2e-truth-{index}") for index in range(positive_count)))
    draft = PopulationFreezeV3(
        PopulationClass.DEVELOPMENT_PILOT if positive_count < 40 else PopulationClass.ADMISSION,
        (PopulationClassificationReason.BELOW_MINIMUM_POSITIVES,) if positive_count < 40 else (),
        positive_count,
        (CanonicalEcosystem.JAVASCRIPT, CanonicalEcosystem.PYTHON),
        (FAMILY_JS, FAMILY_PY),
        scope_census,
        (),
        changes,
        canonical.content_digest(
            {
                "accepted_changes": changes,
                "scope_census": tuple((row.vulnerability_family, row.ecosystem.value, row.count) for row in scope_census),
            }
        ),
        ecosystem_reviews,
        ground_truth_reviews,
        canonical.content_digest({"ecosystem_reviews": ecosystem_reviews, "ground_truth_reviews": ground_truth_reviews}),
        _digest("e2e-ordinary-selection"),
        _digest("e2e-reservation-census"),
        (("review_excluded", 1),),
        _digest("e2e-source-provenance"),
        _digest("e2e-ecosystem-policy"),
        _digest("e2e-ground-truth-policy"),
        _digest("e2e-freeze-policy"),
        ZERO,
        ZERO,
    )
    bound = replace(draft, population_digest=canonical.content_digest(_population_value(draft)))
    return replace(bound, freeze_digest=canonical.content_digest(_freeze_value(bound, include_digest=False)))


def _pushes() -> tuple[OrdinaryPushV1, ...]:
    rows = []
    for ecosystem in ("javascript", "python"):
        for index in range(10):
            draft = OrdinaryPushV1(
                "https://example.invalid/app.git",
                _digest(f"e2e-ordinary-network-{ecosystem}"),
                ecosystem,
                f"{index:040x}",
                f"{index + 1:040x}",
                64,
                _digest(f"e2e-ordinary-change-{ecosystem}-{index}"),
                _digest("e2e-ordinary-history"),
                "",
            )
            rows.append(replace(draft, push_digest=canonical.content_digest(_push_value(draft, include_digest=False))))
    return tuple(sorted(rows, key=lambda item: item.push_digest))


def _selection(freeze: PopulationFreezeV3) -> OrdinarySelectionV1:
    pushes = _pushes()
    network = pushes[0].network_identity_digest
    positives = freeze.positive_change_digests
    assignments = tuple(
        sorted(
            OrdinaryDrawAssignmentV1(positive, push.network_identity_digest, push.ecosystem, push.push_digest)
            for positive in positives
            for push in pushes
        )
    )
    fix_exclusions = tuple(
        sorted(
            OrdinaryFixExclusionV1(network, f"{7000 + index:040x}", positive, freeze.ground_truth_review_digests[index])
            for index, positive in enumerate(positives)
        )
    )
    provenance = canonical.content_digest(
        {
            "history_sources": tuple(
                sorted({(push.canonical_repository, push.network_identity_digest, push.history_source_digest) for push in pushes})
            ),
            "accepted_fix_exclusions": tuple(_fix_exclusion_value(item) for item in fix_exclusions),
            "policy_digest": _digest("e2e-ordinary-policy"),
        }
    )
    draft = OrdinarySelectionV1(20, _digest("e2e-ordinary-policy"), positives, fix_exclusions, pushes, assignments, (), provenance, "")
    return replace(draft, selection_digest=canonical.content_digest(_selection_value(draft, include_digest=False)))


def _material_manifest(freeze: PopulationFreezeV3) -> PublicPopulationMaterialManifestV1:
    positives = freeze.positive_change_digests
    public = tuple(
        sorted(
            PublicSourceRecordV1(
                change, LicenseClass.PERMISSIVE, "MIT", _digest(f"e2e-public-{index}"), 128, _digest(f"e2e-object-{index}")
            )
            for index, change in enumerate(positives[:25])
        )
    )
    private = tuple(
        sorted(
            OpaquePrivateMaterialRefV1(change, LicenseClass.NON_PERMISSIVE, _digest(f"e2e-private-{index}"), 96)
            for index, change in enumerate(positives[25:])
        )
    )
    partitions = tuple(
        sorted(
            partition
            for partition in (
                (LicenseClass.NON_PERMISSIVE, len(private)),
                (LicenseClass.PERMISSIVE, len(public)),
            )
            if partition[1] > 0
        )
    )
    draft = PublicPopulationMaterialManifestV1(
        freeze.population_digest,
        freeze.freeze_digest,
        positives,
        public,
        private,
        _digest("e2e-private-object"),
        _digest("e2e-sealed-labels"),
        partitions,
        ((_digest("e2e-review-excluded"), 1),),
        len(public),
        len(private),
        _digest("e2e-partition-policy"),
        "",
    )
    return replace(draft, manifest_digest=canonical.content_digest(_manifest_value(draft, include_digest=False)))


def _reviewed_manifest(freeze, selection, material):
    inputs = tuple(sorted({*freeze.positive_change_digests, *(push.push_digest for push in selection.pushes)}))
    draft = LabelBlindPopulationDraftV3(
        freeze.population_digest,
        freeze.freeze_digest,
        freeze.reservation_census_digest,
        freeze.review_set_digest,
        selection.selection_digest,
        material.manifest_digest,
        _digest("e2e-material-artifacts"),
        freeze.scope_census,
        inputs,
        freeze.positive_count,
        len(inputs),
        derive_evaluation_input_set_digest(inputs),
        "",
    )
    draft = replace(draft, draft_digest=canonical.content_digest(_draft_value(draft, include_digest=False)))
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="e2e-execution-disclosures")
    review = _attestation(draft.draft_digest, _digest("e2e-manifest-producer"), disclosure)
    manifest = review_label_blind_population_manifest(draft, review, _policy(), resolver)
    return manifest, review, disclosure, resolver


def _label_inputs(manifest, selection, material) -> tuple[execution.LabelBlindCaseInputV1, ...]:
    public = {row.change_digest: row for row in material.public_sources}
    private = {row.change_digest: row for row in material.private_refs}
    pushes = {row.push_digest: row for row in selection.pushes}
    rows = []
    for item in manifest.input_digests:
        if item in public:
            source, access, provenance, length, change = (
                public[item].source_digest,
                ArtifactAccessClass.PUBLIC,
                public[item].object_digest,
                public[item].byte_length,
                item,
            )
        elif item in private:
            source, access, provenance, length, change = (
                private[item].source_digest,
                ArtifactAccessClass.PRIVATE,
                material.private_object_digest,
                private[item].byte_length,
                item,
            )
        else:
            push = pushes[item]
            source, access, provenance, length, change = (
                push.change_content_digest,
                ArtifactAccessClass.PRIVATE,
                push.history_source_digest,
                push.change_byte_length,
                push.change_content_digest,
            )
        rows.append(
            execution.LabelBlindCaseInputV1(
                item,
                change,
                ArtifactReference(ArtifactKind.POPULATION, source, length, provenance, access),
                "",
            )
        )
    return tuple(rows)


def _e2e_catalog_context(context_case):
    """Catalog context whose family labels satisfy the benchmark freeze contract."""
    from dataclasses import replace as _replace  # noqa: E402

    from openultrasast.core.admission_context import make_admission_validation_context  # noqa: E402
    from openultrasast.core.family import family_contract_digest  # noqa: E402
    from openultrasast.core.family_catalog import FamilyCatalog, FamilyCatalogEntry, catalog_entry_key, derive_catalog_digest  # noqa: E402
    from openultrasast.core.validation import make_evidence_validation_context  # noqa: E402

    template = context_case.context.evidence.family_catalog.entries[0].contract
    contracts = (
        _replace(template, family_id=FAMILY_PY),
        _replace(template, family_id=FAMILY_PY, family_version="2", ecosystems=("javascript",)),
        _replace(template, family_id=FAMILY_JS),
        _replace(template, family_id=FAMILY_JS, family_version="2", ecosystems=("javascript",)),
    )
    entries = tuple(
        sorted(
            (FamilyCatalogEntry(contract, family_contract_digest(contract)) for contract in contracts),
            key=catalog_entry_key,
        )
    )
    catalog = FamilyCatalog(entries, derive_catalog_digest(entries))
    old = context_case.context.evidence
    evidence_context = make_evidence_validation_context(
        family_catalog=catalog,
        fact_packs=old.fact_packs,
        model_programs=(),
        lineages=(),
        fact_review_policy=old.fact_review_policy,
        provenance_trust_policy=old.provenance_trust_policy,
        custody_policy=E2E_CUSTODY_POLICY,
    )
    context = make_admission_validation_context(
        evidence=evidence_context,
        admission_review_policy=context_case.context.admission_review_policy,
        proof_trust_policy=context_case.context.proof_trust_policy,
    )
    return _replace(context_case, context=context)


def _execution_evidence(population):
    from benchmarks.valid.observation_receipt import (  # noqa: E402
        InputReadReceiptV1,
        InputReadStatus,
        RequiredExecutionStage,
        StageExecutionReceiptV1,
        StageExecutionStatus,
        input_read_evidence_digest,
        stage_execution_evidence_digest,
    )

    reads = tuple(
        InputReadReceiptV1(
            row.input_identity_digest,
            row.code_reference.byte_length,
            row.code_reference.byte_length,
            InputReadStatus.COMPLETED,
            "",
        )
        for row in population.cases
    )
    stages = tuple(
        StageExecutionReceiptV1(
            stage,
            StageExecutionStatus.COMPLETED,
            _digest(f"stage-{stage.value}"),
            "",
        )
        for stage in RequiredExecutionStage
    )
    return input_read_evidence_digest(reads), stage_execution_evidence_digest(stages)


def _candidate(arm_id: str, scope: ScopeKey, raw: str, change: str) -> ProofCandidateIdentityV3:
    draft = ProofCandidateIdentityV3(
        arm_id,
        _digest(f"e2e-pre-observation-{arm_id}"),
        scope.family_id,
        scope,
        _digest(f"e2e-location-{arm_id}-{raw}"),
        change,
        ZERO,
    )
    return replace(draft, candidate_digest=derive_proof_candidate_identity_digest(draft))


def _combined_projection(rule, component: CaseOutcomeProjectionV3) -> CaseOutcomeProjectionV3:
    outcomes = tuple(component.normalized_outcome for _arm in rule.component_arm_ids)
    outcome = component.normalized_outcome
    for row in rule.decision_rows:
        if row.component_outcomes == outcomes:
            outcome = row.combined_outcome
            break
    return CaseOutcomeProjectionV3(
        component.case_input_digest,
        CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
        tuple(component.projection_digest for _arm in rule.component_arm_ids),
        outcome,
        "",
    )


def _plan_row(population, arm_id: str):
    return next(row for row in population.plan.registrations if row.arm_id == arm_id)


class _CaseContent:
    """Deterministic per-arm case contents, observation refs, and candidates."""

    def __init__(self, population) -> None:
        self.by_wrapper: dict[tuple[str, str], AdmissionCaseResult] = {}
        self.candidates: dict[tuple[str, str], ProofCandidateIdentityV3 | None] = {}
        self.references: dict[tuple[str, str], ObservationCaseRefV3] = {}
        self.observations: dict[tuple[str, str], ArmObservationSetV3] = {}
        self.coverage_sites: dict[ScopeKey, int] = {SCOPE_PY: 0, SCOPE_JS: 0}
        self.model_calls: dict[ScopeKey, int] = {SCOPE_PY: 0, SCOPE_JS: 0}
        self.pairs: dict[ScopeKey, set[str]] = {SCOPE_PY: set(), SCOPE_JS: set()}
        self.wrappers: dict[str, str] = {}
        self._build(population)

    def _build(self, population) -> None:
        from test_core_admission_spend import _feasible_case  # noqa: E402

        context_case = _e2e_catalog_context(_core_context_case())
        template_inputs, template_resolver = _canonical_evidence_inputs(_feasible_case())
        merged = InMemoryContentResolver(dict(template_resolver.artifacts))
        programs: dict[str, object] = {}
        lineages: dict[str, object] = {}
        artifacts: dict[str, ResolvedContent] = dict(template_resolver.artifacts)
        for role in (AdmissionCaseRole.VULNERABLE, AdmissionCaseRole.FIXED, AdmissionCaseRole.ORDINARY):
            _base, base_resolver = _case_result(template_inputs[0], role, _digest("e2e-base-pair"), merged)
            artifacts.update(base_resolver.artifacts)
        bases = {
            role: _case_result(template_inputs[index], role, _digest("e2e-base-pair"), merged)[0]
            for index, role in enumerate(
                (AdmissionCaseRole.VULNERABLE, AdmissionCaseRole.FIXED, AdmissionCaseRole.ORDINARY)
            )
        }
        read_evidence, stage_evidence = _execution_evidence(population)
        rule = population.combination_rule
        for index, identity in enumerate(population.identities):
            contract = _contract_for_scope(context_case, identity.scope)
            evidence, evidence_artifacts = _distinct_evidence_input(
                template_inputs[0],
                index,
                contract,
                identity.scope.ecosystem,
                shared_change=True,
                model_context=context_case,
                model_programs=programs,
                model_lineages=lineages,
            )
            artifacts.update(evidence_artifacts)
            records = (evidence.record,)
            component = derive_component_case_outcome_projection(records)
            self.wrappers[identity.raw] = component.case_input_digest
            if identity.pair is not None:
                self.pairs[identity.scope].add(identity.pair)
            attachment = None
            if identity.role is AdmissionCaseRole.VULNERABLE:
                attachment, _trust, proof_resolver = _proof(evidence.record)
                artifacts.update(proof_resolver.artifacts)
            for arm_id in PLANNED_ARMS:
                projection = _combined_projection(rule, component) if arm_id == ANCHOR_ARM else component
                attachments = () if attachment is None or arm_id != EXPERIMENTAL_ARM else (attachment,)
                legacy = replace(
                    bases[identity.role],
                    case_id_digest=_digest(f"e2e-case-{arm_id}-{index}"),
                    scope=LegacyScopeKey(identity.scope.family_id, identity.scope.ecosystem),
                    pair_id_digest=identity.pair,
                    evidence_inputs=(evidence,),
                    proof_attachments=attachments,
                    complexity=replace(
                        bases[identity.role].complexity,
                        transition_count=sum(len(item.record.packet.transitions) for item in (evidence,)),
                    ),
                    result_digest=ZERO,
                )
                canonical_case = _canonical_legacy_case(legacy, contract, records)
                if arm_id == ANCHOR_ARM:
                    self.coverage_sites[identity.scope] += canonical_case.coverage.sites_considered
                    self.model_calls[identity.scope] += sum(1 for item in canonical_case.evidence_inputs if item.model_result is not None)
                candidate = (
                    _candidate(arm_id, identity.scope, identity.raw, evidence.record.packet.provenance.change_input_digest)
                    if arm_id == EXPERIMENTAL_ARM
                    else None
                )
                attachments = () if attachment is None or arm_id != EXPERIMENTAL_ARM else (attachment,)
                slot = population.slot_for(arm_id, identity.raw)
                legacy_content = canonical_case
                reference = ObservationCaseRefV3(
                    legacy_content.case_id_digest,
                    component.case_input_digest,
                    identity.raw,
                    legacy_content.result_digest,
                    projection,
                    candidate.candidate_digest if candidate is not None else None,
                )
                row = _plan_row(population, arm_id)
                observation = ArmObservationSetV3(
                    slot.slot_digest,
                    arm_id,
                    slot.input_identity_digest,
                    slot.execution_identity,
                    row.configuration.registered_budget_digest,
                    row.configuration.configuration_identity_digest,
                    read_evidence,
                    stage_evidence,
                    (reference,),
                    "",
                )
                for key in {identity.raw, component.case_input_digest}:
                    self.by_wrapper[(arm_id, key)] = legacy_content
                    self.candidates[(arm_id, key)] = (
                        replace(candidate, observation_digest=observation.observation_digest)
                        if candidate is not None
                        else None
                    )
                self.references[(arm_id, identity.raw)] = reference
                self.observations[(arm_id, identity.raw)] = observation
        population.model_programs = tuple(programs[key] for key in sorted(programs))
        population.model_lineages = tuple(lineages[key] for key in sorted(lineages))
        population._evidence_artifacts = artifacts
        population.catalog_context_case = context_case

    def port(self, arm_id: str, wrapper: str, scope: ScopeKey) -> AdmissionCaseResult:
        content = self.by_wrapper[(arm_id, wrapper)]
        if (content.scope.family_id, content.scope.ecosystem) != (scope.family_id, scope.ecosystem):
            raise KeyError((arm_id, wrapper))
        return content

    def candidate_port(self, arm_id: str, wrapper: str, scope: ScopeKey):
        return self.candidates.get((arm_id, wrapper))


class E2EPopulation:
    """Full synthetic two-ecosystem admission population with core case content."""

    def __init__(self, *, pairs_python: int = PAIRS_PY, pairs_javascript: int = PAIRS_JS, mint_cases: bool = True) -> None:
        positives = _positive_identities(pairs_python, pairs_javascript)
        self.freeze = _freeze(positives)
        self.selection = _selection(self.freeze)
        self.material = _material_manifest(self.freeze)
        self.manifest, self.manifest_review, self.disclosure, manifest_resolver = _reviewed_manifest(
            self.freeze, self.selection, self.material
        )
        self.ordinary_census = (EcosystemOrdinaryCensusV3("javascript", 10), EcosystemOrdinaryCensusV3("python", 10))
        scopes = tuple(sorted(((FAMILY_PY, "python"), (FAMILY_JS, "javascript"))))
        self.plan = register_evaluation_plan(
            registrations=(
                _registration(
                    ArmRole.COMBINED,
                    _relax_precision(
                        _configuration("arm-combined", scopes, combined=True, minimum_ordinary=2, label="e2e-combined"),
                        _union_rule(),
                    ),
                ),
                _registration(
                    ArmRole.EXPERIMENTAL,
                    _relax_precision(
                        _configuration("arm-experimental", scopes, minimum_ordinary=2, label="e2e-experimental")
                    ),
                ),
                _registration(
                    ArmRole.SHIPPED,
                    _relax_precision(_configuration("arm-shipped", scopes, minimum_ordinary=2, label="e2e-shipped")),
                ),
            ),
            population_digest=self.manifest.population_digest,
            freeze_digest=self.manifest.freeze_digest,
            input_set_digest=self.manifest.input_set_digest,
            input_identity_digests=self.manifest.input_digests,
        )
        combined = next(row for row in self.plan.registrations if row.arm_id == ANCHOR_ARM)
        self.combination_rule = combined.configuration.combination_rule
        assert self.combination_rule is not None
        self.positive_rows = {row.raw: row for row in positives}
        self.identities = self._identities()
        self.durable_identity = store_namespace_identity(_settings(StorePurpose.DURABLE))
        self.transient_identity = store_namespace_identity(_settings(StorePurpose.TRANSIENT))
        self.report, self.transient_profile = _capability_report(self.durable_identity, self.transient_identity)
        self.custody_log_digest = empty_population_custody_log(self.freeze.population_digest, E2E_CUSTODIAN).log_digest
        self.census_review = _attestation(
            admission_census_payload_digest(self.plan, self.manifest, self.ordinary_census, self.manifest_review),
            _digest("e2e-census-producer"),
            self.disclosure,
        )
        self.census = compose_population_census(self.plan, self.manifest, self.ordinary_census, self.census_review)
        self.plan_review = _attestation(
            admission_manifest_payload_digest(
                self.plan, self.census, (self.report.report_digest,), self.custody_log_digest, self.manifest_review
            ),
            _digest("e2e-plan-producer"),
            self.disclosure,
        )
        self.plan_manifest = compose_plan_manifest(
            self.plan, self.census, (self.report.report_digest,), self.custody_log_digest, self.plan_review
        )
        self.cases = _label_inputs(self.manifest, self.selection, self.material)
        self.budgets = tuple(
            execution.ArmExecutionBudgetV1(
                row.arm_id,
                row.configuration.registered_budget_digest,
                120,
                512 * 1024 * 1024,
                1024 * 1024 * 1024,
                4 * 1024 * 1024,
                "",
            )
            for row in self.plan.registrations
            if row.configuration.kind is ArmKindV3.COMPONENT
        )
        self.bundles = build_component_execution_bundles(
            self.plan,
            self.manifest,
            self.selection,
            self.material,
            self.cases,
            self.budgets,
            adapter_kind=ExecutionAdapterKind.LOCAL,
            output_namespace_digest=NAMESPACE,
        )
        self.bindings = tuple(
            AdmissionExecutionBindingV1(
                bundle.arm.arm_id,
                bundle.bundle_digest,
                bundle.budget.budget_digest,
                bundle.environment.environment_digest,
                bundle.output_destination.destination_digest,
            )
            for bundle in self.bundles
        )
        self.combination_registrations = (
            CombinationRuleRegistrationV1(ANCHOR_ARM, CombinationRuleKindV1.UNION, self.combination_rule.rule_digest, ""),
        )
        self.context = None
        self.manifest_resolver = manifest_resolver
        self.evidence_resolver = manifest_resolver
        self.catalog_context_case = None
        self.readiness: tuple = ()
        self.content: _CaseContent | None = None
        self.labels = b""
        self.adapter_census_review = None
        self.adapter_plan_review = None
        if mint_cases:
            self._mint_case_content()

    def _identities(self) -> tuple[_InputIdentity, ...]:
        rows = list(self.positive_rows.values())
        pushes = {push.push_digest: push for push in self.selection.pushes}
        for raw in self.manifest.input_digests:
            if raw in pushes:
                ecosystem = pushes[raw].ecosystem
                scope = SCOPE_PY if ecosystem == "python" else SCOPE_JS
                rows.append(_InputIdentity(raw, scope, AdmissionCaseRole.ORDINARY, None))
        return tuple(sorted(rows, key=lambda item: item.raw))

    def _mint_case_content(self) -> None:
        self.content = _CaseContent(self)
        final_context_case = _with_model_context(
            (self.catalog_context_case,), self.model_programs, self.model_lineages
        )[0]
        old = final_context_case.context.evidence
        evidence_context = make_evidence_validation_context(
            family_catalog=old.family_catalog,
            fact_packs=old.fact_packs,
            model_programs=old.model_programs,
            lineages=old.lineages,
            fact_review_policy=old.fact_review_policy,
            provenance_trust_policy=old.provenance_trust_policy,
            custody_policy=E2E_CUSTODY_POLICY,
        )
        policy = ReviewIndependencePolicy(
            (REVIEWER,),
            (),
            ("trusted-store", BRIDGE_STORE),
            1 << 20,
            derive_review_independence_policy_digest((REVIEWER,), (), ("trusted-store", BRIDGE_STORE), 1 << 20),
        )
        self.context = make_admission_validation_context(
            evidence=evidence_context,
            admission_review_policy=policy,
            proof_trust_policy=final_context_case.context.proof_trust_policy,
        )
        status_payload = canonical.canonical_bytes(
            {"schema_version": PUBLIC_STATUS_SCHEMA, "status_code": "sealed", "count": 0, "digest": _digest("e2e-bridge-status")}
        )
        _status_ref, status_resolver = stored_artifact(status_payload, artifact_id="e2e-bridge-attempt-status")
        self.status_ref = _status_ref
        artifacts = dict(self._evidence_artifacts)
        artifacts.update(status_resolver.artifacts)
        artifacts.update(self.manifest_resolver.artifacts)
        self.evidence_resolver = InMemoryContentResolver(artifacts)
        self.readiness = tuple(_readiness_chain())
        self.labels = _label_bytes(self.identities)
        self.adapter_census_review, self.adapter_plan_review = self._adapter_reviews()

    def _adapter_reviews(self):
        assert self.content is not None
        ordinary = {"javascript": 0, "python": 0}
        for push in self.selection.pushes:
            ordinary[push.ecosystem] += 1
        scope_rows = tuple(
            sorted(
                ExactScopeCensusV3(
                    scope,
                    len(self.content.pairs[scope]),
                    len(self.content.pairs[scope]),
                    len(self.content.pairs[scope]),
                    self.content.coverage_sites[scope],
                    self.content.model_calls[scope],
                )
                for scope in SCOPES
            )
        )
        ordinary_rows = tuple(EcosystemOrdinaryCensusV3(eco, ordinary[eco]) for eco in sorted(ordinary))
        provisional = _attestation(ZERO, _digest("e2e-provisional-producer"), self.disclosure)
        draft = PopulationCensusV3(
            self.freeze.population_digest,
            scope_rows,
            ordinary_rows,
            len(self.manifest.input_digests),
            False,
            ZERO,
            provisional,
            ZERO,
        )
        census_payload = derive_evaluation_census_payload_digest(draft)
        census_review = _attestation(census_payload, _digest("e2e-adapter-census-producer"), self.disclosure)
        census = replace(draft, payload_digest=census_payload, review=census_review)
        census = replace(census, census_digest=derive_evaluation_census_digest(census))
        readiness_digests = tuple(sorted(item.result_digest for item in self.readiness))
        plan_payload = admission_manifest_payload_digest(self.plan, census, readiness_digests, self.custody_log_digest, census_review)
        plan_review = _attestation(plan_payload, _digest("e2e-adapter-plan-producer"), self.disclosure)
        return census_review, plan_review

    def slot_for(self, arm_id: str, raw: str):
        return next(
            slot
            for slot in self.plan.declaration.expected_observation_slots
            if slot.arm_id == arm_id and slot.input_identity_digest == raw
        )

    def run_request(self, **overrides: object) -> AdmissionRunRequestV1:
        value: dict[str, object] = {
            "population_digest": self.freeze.population_digest,
            "freeze_digest": self.freeze.freeze_digest,
            "freeze": self.freeze,
            "manifest": self.manifest,
            "plan": self.plan,
            "current_registrations": self.plan.registrations,
            "ordinary_census": self.ordinary_census,
            "census_review": self.census_review,
            "plan_review": self.plan_review,
            "review_policy": _policy(),
            "resolver": self.evidence_resolver,
            "capability_report": self.report,
            "expected_durable_store_identity": self.durable_identity,
            "expected_transient_store_identity": self.transient_identity,
            "transient_retention_profile": self.transient_profile,
            "execution_bindings": self.bindings,
            "workflow_digest": WORKFLOW,
            "attempt_id": "attempt-1",
            "lease_owner_id": "owner-a",
            "heartbeat_at": "2026-11-23T09:00:00Z",
            "lease_expires_at": "2026-11-23T09:30:00Z",
            "recorded_runtime_ms": 250,
        }
        value.update(overrides)
        return AdmissionRunRequestV1(**value)


def _label_bytes(identities) -> bytes:
    rows = []
    for identity in identities:
        if identity.role is AdmissionCaseRole.ORDINARY:
            continue
        label = canonical.canonical_bytes(
            {
                "schema_version": spend.GROUND_TRUTH_LABEL_SCHEMA,
                "role": identity.role.value,
                "pair_id_digest": identity.pair,
                "family_id": identity.scope.family_id,
                "ecosystem": identity.scope.ecosystem,
            }
        )
        judgment = b'{"judgment":"defect-present"}' + LABEL_MARKER
        rows.append(
            {
                "change_digest": identity.raw,
                "label_digest": canonical.bytes_digest(label),
                "judgment_digest": canonical.bytes_digest(judgment),
                "label_base64": base64.b64encode(label).decode("ascii"),
                "judgment_base64": base64.b64encode(judgment).decode("ascii"),
            }
        )
    return canonical.canonical_bytes(
        {"schema_version": spend.SEALED_LABEL_OBJECT_SCHEMA, "records": tuple(sorted(rows, key=lambda row: row["change_digest"]))}
    )


@lru_cache(maxsize=1)
def _population() -> E2EPopulation:
    return E2EPopulation()


class _NoPopulationCustody:
    """Fallback custody view for populations minted without case content."""

    def current_log(self, population_digest: str):
        raise DurableCustodyStoreError("durable_custody_not_found")


class _ChainedCustodyPort:
    """Benchmark custody first; the model-lineage fixture port serves model populations."""

    def __init__(self, primary, fallback) -> None:
        self._primary = primary
        self._fallback = fallback

    def current_log(self, population_digest: str):
        try:
            return self._primary.current_log(population_digest)
        except DurableCustodyStoreError:
            return self._fallback.current_log(population_digest)


class E2EEnvironment:
    """Durable stores, orchestrator, and execution chain over the e2e population."""

    def __init__(self, population: E2EPopulation | None = None) -> None:
        self.case = population if population is not None else _population()
        self.durable = _Client()
        self.transient = _Client()
        self.custody_policy = E2E_CUSTODY_POLICY
        self.repository = S3ArtifactRepository(_settings(StorePurpose.DURABLE), self.durable)
        self.store = S3DurableCustodyStore(
            _settings(StorePurpose.DURABLE),
            self.durable,
            self.custody_policy,
            self.case.report,
            self.case.transient_identity,
            self.case.transient_profile,
        )
        assert self.store.initialize(empty_population_custody_log(self.case.freeze.population_digest, E2E_CUSTODIAN))
        fallback = self.case.catalog_context_case.port if self.case.catalog_context_case is not None else _NoPopulationCustody()
        self.custody = _ChainedCustodyPort(self.store, fallback)
        self.journal = S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), self.transient)
        self.adapter = _Adapter(self._factory())
        self.orchestrator = AdmissionOrchestrator(
            self.lifecycle(), self.repository, self.custody, self.journal, _SpyExecutor(), ACCESS_POLICY
        )
        self.last_execution = None

    def lifecycle(self):
        return _lifecycle(self.case.freeze.population_digest, self.case.freeze.freeze_digest)

    def preflight(self):
        return self.orchestrator.preflight(self.case.run_request())

    def _factory(self):
        case = self.case

        def factory(bundle):
            reads, stages = _read_rows(bundle), _stage_rows()
            observations = tuple(
                case.content.observations[(bundle.arm.arm_id, slot.input_identity_digest)]
                for slot in case.plan.declaration.expected_observation_slots
                if slot.arm_id == bundle.arm.arm_id
            )
            output = checkpoint.component_observation_output_bytes(observations)
            outcome = execution.completed_adapter_outcome(bundle, output, runtime_ms=9)
            return checkpoint.ArmExecutionCaptureV1(outcome, reads, stages, (), observations)

        return factory

    def execution_request(self, preflight, *, review, attempt_review, status_ref):
        case = self.case
        return AdmissionExecutionRequestV1(
            preflight,
            case.run_request(),
            case.selection,
            case.material,
            case.cases,
            case.budgets,
            self.adapter,
            (None, None),
            case.combination_registrations,
            review,
            attempt_review,
            status_ref,
            case.durable_identity,
            BRIDGE_RETENTION,
            NAMESPACE,
        )

    def execute(self, preflight, *, review, attempt_review, status_ref):
        from benchmarks.valid.admission_execution import execute_planned_observations  # noqa: E402

        product = execute_planned_observations(
            self.lifecycle(),
            self.repository,
            self.custody,
            self.journal,
            ACCESS_POLICY,
            self.execution_request(preflight, review=review, attempt_review=attempt_review, status_ref=status_ref),
        )
        self.last_execution = product
        return product


@lru_cache(maxsize=1)
def _execution_review_subject() -> str:
    harvest = E2EEnvironment()
    preflight = harvest.preflight()
    product = harvest.execute(
        preflight,
        review=None,
        attempt_review=_attempt_review(harvest.case, preflight),
        status_ref=harvest.case.status_ref,
    )
    return product.manifest_subject_digest


def _attempt_review(case, preflight):
    from benchmarks.valid.admission_execution import initial_attempt_event_payload_digest  # noqa: E402

    return _attestation(
        initial_attempt_event_payload_digest(preflight.plan_manifest, case.status_ref),
        _digest("e2e-attempt-producer"),
        case.disclosure,
    )


def _admission_review(case):
    return _attestation(_execution_review_subject(), _digest("e2e-admission-producer"), case.disclosure)


def authorized_execution(environment: E2EEnvironment):
    """Run the label-blind execution chain to its sealed, spend-authorized product."""
    preflight = environment.preflight()
    return environment.execute(
        preflight,
        review=_admission_review(environment.case),
        attempt_review=_attempt_review(environment.case, preflight),
        status_ref=environment.case.status_ref,
    )
