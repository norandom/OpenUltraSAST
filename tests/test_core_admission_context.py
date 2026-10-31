"""Exact pre-feasibility admission context validation (Reqs 12.1, 12.2, 13.1)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TypeVar

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_admission_review import _attestation, _policy
from test_core_model import ApplicationCase, _application_case
from test_core_readiness import _chain
from test_core_validation_v2 import _catalog, _review_policy, _trust_policy

from openultrasast.core import canonical, custody, validation
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_review import (
    AdmissionManifestV2,
    AdmissionThreshold,
    PopulationCensus,
    ScopeCensus,
    derive_census_digest,
    derive_census_payload_digest,
    derive_manifest_digest,
    derive_manifest_payload_digest,
    derive_threshold_set_digest,
)
from openultrasast.core.family_catalog import FamilyCatalogEntry
from openultrasast.core.lineage import LineageManifest, LineageUse, derive_lineage_manifest_digest
from openultrasast.core.measurement import (
    BaselineIdentity,
    Comparator,
    DenominatorKind,
    DenominatorPolicy,
    IntervalMethod,
    MetricId,
    MetricRule,
    NumeratorKind,
    ScopeKey,
    Statistic,
    derive_denominator_policy_digest,
    derive_identity_set_digest,
    standard_metric_rules,
)
from openultrasast.core.model import ModelProgramDeclaration
from openultrasast.core.readiness import (
    AnalysisIdentity,
    FixtureResult,
    FixtureRole,
    ReadinessEvidenceUse,
    ReadinessResult,
    ReadinessStage,
    StageResult,
)
from openultrasast.core.validation import EvidenceValidationContext

_T = TypeVar("_T")


class MultiPopulationCustody:
    def __init__(self, logs: tuple[custody.PopulationCustodyLog, ...], policy: custody.PopulationCustodyPolicy) -> None:
        self.logs = {item.population_digest: item for item in logs}
        self.policy = policy

    def current_log(self, population_digest: str) -> custody.PopulationCustodyLog:
        try:
            return self.logs[population_digest]
        except KeyError as exc:
            raise custody.PopulationCustodyError("population custody log not found") from exc

    def append(self, request: custody.PopulationUseRequest, custodian: str) -> custody.PopulationUseReceipt:
        prior = self.current_log(request.population_digest)
        receipt = custody.record_population_use(request, prior, custodian, self.policy)
        self.logs[request.population_digest] = custody.append_population_use(prior, receipt, self.policy)
        return receipt


class _PolicySubclass(DenominatorPolicy):
    pass


class _RuleSubclass(MetricRule):
    pass


class _TupleSubclass(tuple[MetricRule, ...]):
    pass


class _ScopeSubclass(ScopeKey):
    pass


class _ScalarSubclass(str):
    pass


class _AdmissionContextSubclass(AdmissionValidationContext):
    pass


class _EvidenceContextSubclass(EvidenceValidationContext):
    pass


class _CatalogEntrySubclass(FamilyCatalogEntry):
    pass


class _ModelProgramSubclass(ModelProgramDeclaration):
    pass


class _LineageSubclass(LineageManifest):
    pass


class _ReadinessResultSubclass(ReadinessResult):
    pass


class _AnalysisIdentitySubclass(AnalysisIdentity):
    pass


class _FixtureResultSubclass(FixtureResult):
    pass


class _ReadinessTupleSubclass(tuple[ReadinessResult, ...]):
    pass


def _as_subclass(value: object, subtype: type[_T]) -> _T:
    changed = object.__new__(subtype)
    for field, item in vars(value).items():
        object.__setattr__(changed, field, item)
    return changed


@dataclass(frozen=True)
class AdmissionCase:
    manifest: AdmissionManifestV2
    denominator: DenominatorPolicy
    readiness: tuple[ReadinessResult, ...]
    context: AdmissionValidationContext
    port: MultiPopulationCustody
    resolver: InMemoryContentResolver


@dataclass(frozen=True)
class ContextSetup:
    model_case: ApplicationCase
    port: MultiPopulationCustody
    context: AdmissionValidationContext
    threshold: AdmissionThreshold
    threshold_lineage: LineageManifest
    admission_population: str


def _append_lineage(
    port: MultiPopulationCustody,
    population: str,
    arm: str,
    purpose: custody.LineagePurpose,
    artifact: str,
    custodian: str,
    *,
    labels: bool = False,
) -> LineageManifest:
    current = port.current_log(population)
    request = custody.PopulationUseRequest(population, arm, purpose, labels, artifact, current.log_digest)
    receipt = port.append(request, custodian)
    use = LineageUse(purpose, population, labels, artifact, receipt.receipt_digest)
    return LineageManifest(arm, artifact, (use,), derive_lineage_manifest_digest(arm, artifact, (use,)))


def _reviewed_census(population: str, scope: ScopeKey, disclosure: canonical.ContentRef) -> PopulationCensus:
    producer = canonical.content_digest("benchmark-producer")
    reviewer = canonical.content_digest("independent-reviewer")
    row = ScopeCensus(scope, 8, 2, 2, 2, 4, 12, 3)
    provisional_review = _attestation("0" * 64, producer, reviewer, disclosure)
    provisional = PopulationCensus(population, (row,), False, "0" * 64, provisional_review, "0" * 64)
    payload = derive_census_payload_digest(provisional)
    census = replace(provisional, census_payload_digest=payload, review=_attestation(payload, producer, reviewer, disclosure))
    return replace(census, census_digest=derive_census_digest(census))


def _resign_manifest(
    manifest: AdmissionManifestV2,
    disclosure: canonical.ContentRef,
) -> AdmissionManifestV2:
    producer = canonical.content_digest("benchmark-producer")
    reviewer = canonical.content_digest("independent-reviewer")
    provisional = replace(
        manifest,
        manifest_payload_digest="0" * 64,
        review=_attestation("0" * 64, producer, reviewer, disclosure),
        manifest_digest="0" * 64,
    )
    payload = derive_manifest_payload_digest(provisional)
    reviewed = replace(provisional, manifest_payload_digest=payload, review=_attestation(payload, producer, reviewer, disclosure))
    return replace(reviewed, manifest_digest=derive_manifest_digest(reviewed))


def _support_lineages(
    port: MultiPopulationCustody,
    source_population: str,
    custodian: str,
) -> tuple[LineageManifest, LineageManifest]:
    matcher = _append_lineage(
        port,
        source_population,
        "matcher-arm",
        custody.LineagePurpose.MATCHING_BEHAVIOR,
        canonical.content_digest("matcher"),
        custodian,
    )
    promotion = _append_lineage(
        port,
        source_population,
        "promotion-arm",
        custody.LineagePurpose.PROMOTION,
        canonical.content_digest("promotion"),
        custodian,
    )
    return matcher, promotion


def _context_setup() -> ContextSetup:
    from openultrasast.core import admission_context

    model_case = _application_case()
    contract = model_case.contract
    catalog = _catalog(contract)
    admission_population = canonical.content_digest("admission-population")
    custodian = model_case.custodian
    admission_log = custody.empty_population_custody_log(admission_population, custodian)
    source_log = model_case.custody.current_log(canonical.content_digest("population"))
    port = MultiPopulationCustody((source_log, admission_log), model_case.custody_policy)
    matcher, promotion = _support_lineages(port, source_log.population_digest, custodian)
    threshold = AdmissionThreshold(MetricId.VULNERABLE_RECALL, Statistic.WILSON_LOWER, Comparator.AT_LEAST, 0.5)
    threshold_set = derive_threshold_set_digest((threshold,))
    threshold_lineage = _append_lineage(
        port,
        source_log.population_digest,
        "reference-arm",
        custody.LineagePurpose.THRESHOLD,
        threshold_set,
        custodian,
    )
    evidence_context = validation.make_evidence_validation_context(
        family_catalog=catalog,
        fact_packs=(),
        model_programs=(model_case.request.program,),
        lineages=(model_case.request.lineage, matcher, promotion, threshold_lineage),
        fact_review_policy=_review_policy(),
        provenance_trust_policy=_trust_policy(),
        custody_policy=model_case.custody_policy,
    )
    review_policy = _policy(canonical.content_digest("independent-reviewer"))
    context = admission_context.make_admission_validation_context(
        evidence=evidence_context,
        admission_review_policy=review_policy,
        proof_trust_policy=None,
    )
    return ContextSetup(model_case, port, context, threshold, threshold_lineage, admission_population)


def _baseline(setup: ContextSetup, denominator: DenominatorPolicy, scope: ScopeKey) -> BaselineIdentity:
    from openultrasast.core import admission_context

    catalog = setup.context.evidence.family_catalog
    program_digest = setup.model_case.request.program.declaration_digest
    threshold_set = derive_threshold_set_digest((setup.threshold,))
    return BaselineIdentity(
        "reference-arm",
        setup.admission_population,
        canonical.content_digest("admission-freeze"),
        (scope,),
        (catalog.entries[0].contract_digest,),
        catalog.catalog_digest,
        admission_context.derive_fact_schema_digest(),
        validation.derive_fact_set_digest(()),
        canonical.content_digest("acquisition"),
        "analyzer@abc123",
        canonical.content_digest("configuration"),
        (program_digest,),
        derive_identity_set_digest("model_program", (program_digest,)),
        denominator.policy_digest,
        threshold_set,
        admission_context.derive_outcome_mapping_digest(catalog),
    )


def _manifest(
    setup: ContextSetup,
    baseline: BaselineIdentity,
    census: PopulationCensus,
    readiness: tuple[ReadinessResult, ...],
    disclosure: canonical.ContentRef,
) -> AdmissionManifestV2:
    provisional_review = _attestation(
        "0" * 64,
        canonical.content_digest("benchmark-producer"),
        canonical.content_digest("independent-reviewer"),
        disclosure,
    )
    provisional = AdmissionManifestV2(
        "0" * 64,
        provisional_review,
        True,
        False,
        baseline,
        census,
        tuple(sorted(item.result_digest for item in readiness)),
        setup.port.current_log(setup.admission_population).log_digest,
        baseline.denominator_policy_digest,
        (setup.threshold,),
        baseline.threshold_set_digest,
        setup.threshold_lineage.manifest_digest,
        setup.context.context_digest,
        "0" * 64,
    )
    return _resign_manifest(provisional, disclosure)


def _case() -> AdmissionCase:
    from openultrasast.core import admission_context

    setup = _context_setup()
    contract = setup.model_case.contract
    scope = ScopeKey(contract.family_id, "python")
    denominator = DenominatorPolicy(standard_metric_rules((scope,)), IntervalMethod.WILSON_95, "")
    baseline = _baseline(setup, denominator, scope)
    program_digest = setup.model_case.request.program.declaration_digest
    catalog = setup.context.evidence.family_catalog
    current_identity = admission_context.derive_analysis_identity(baseline, catalog, scope, program_digest)
    readiness = _chain(identity=current_identity)[:6]
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="admission-context-conflicts")
    census = _reviewed_census(setup.admission_population, scope, disclosure)
    manifest = _manifest(setup, baseline, census, readiness, disclosure)
    return AdmissionCase(manifest, denominator, readiness, setup.context, setup.port, resolver)


def _validate(case: AdmissionCase) -> None:
    from openultrasast.core.admission_context import validate_admission_context

    validate_admission_context(
        case.manifest,
        case.denominator,
        case.readiness,
        case.context,
        case.port,
        case.resolver,
    )


def _rebind_denominator(case: AdmissionCase, denominator: DenominatorPolicy) -> AdmissionCase:
    object.__setattr__(denominator, "policy_digest", derive_denominator_policy_digest(denominator))
    identity = replace(case.manifest.identity, denominator_policy_digest=denominator.policy_digest)
    manifest = _resign_manifest(
        replace(case.manifest, identity=identity, denominator_policy_digest=denominator.policy_digest),
        case.manifest.review.conflict_disclosure,
    )
    return replace(case, manifest=manifest, denominator=denominator)


def _forged_policy(template: DenominatorPolicy, rules: tuple[MetricRule, ...]) -> DenominatorPolicy:
    changed = object.__new__(DenominatorPolicy)
    object.__setattr__(changed, "rules", rules)
    object.__setattr__(changed, "interval_method", template.interval_method)
    object.__setattr__(changed, "policy_digest", template.policy_digest)
    return changed


def _smuggled_denominator(case: AdmissionCase, kind: str) -> DenominatorPolicy:
    policy = case.denominator
    first = policy.rules[0]
    if kind == "policy_subclass":
        changed_policy = object.__new__(_PolicySubclass)
        object.__setattr__(changed_policy, "rules", policy.rules)
        object.__setattr__(changed_policy, "interval_method", policy.interval_method)
        object.__setattr__(changed_policy, "policy_digest", policy.policy_digest)
        return changed_policy
    if kind == "policy_state":
        object.__setattr__(policy, "hidden", "state")
        return policy
    changed: MetricRule
    if kind == "rule_subclass":
        changed = _RuleSubclass(first.metric_id, first.scopes, first.numerator, first.denominator)
    elif kind == "rule_state":
        changed = replace(first)
        object.__setattr__(changed, "hidden", "state")
    elif kind == "scope_subclass":
        scope = first.scopes[0]
        changed = replace(first, scopes=(_ScopeSubclass(scope.family_id, scope.ecosystem),))
    elif kind == "scope_state":
        scope = replace(first.scopes[0])
        object.__setattr__(scope, "hidden", "state")
        changed = replace(first, scopes=(scope,))
    elif kind == "scalar_subclass":
        scope = first.scopes[0]
        changed = replace(first, scopes=(ScopeKey(_ScalarSubclass(scope.family_id), scope.ecosystem),))
    else:
        return _forged_policy(policy, _TupleSubclass(policy.rules))
    return _forged_policy(policy, (changed, *policy.rules[1:]))


def test_exact_reviewed_context_is_accepted_before_feasibility() -> None:
    case = _case()
    _validate(case)
    assert case.port.current_log(case.manifest.identity.population_digest).status is custody.PopulationStatus.AVAILABLE


@pytest.mark.parametrize(
    "field",
    ("family_contract_set_digest", "fact_set_digest", "model_program_digests", "outcome_mapping_digest"),
)
def test_claimed_digest_sets_are_rederived_from_canonical_objects(field: str) -> None:
    case = _case()
    if field == "model_program_digests":
        models = (canonical.content_digest("other-model"),)
        identity = replace(
            case.manifest.identity,
            model_program_digests=models,
            model_program_set_digest=derive_identity_set_digest("model_program", models),
        )
    elif field == "family_contract_set_digest":
        identity = replace(case.manifest.identity, family_contract_set_digest=canonical.content_digest("other-catalog"))
    elif field == "fact_set_digest":
        identity = replace(case.manifest.identity, fact_set_digest=canonical.content_digest("other-facts"))
    else:
        identity = replace(case.manifest.identity, outcome_mapping_digest=canonical.content_digest("other-mapping"))
    changed = _resign_manifest(
        replace(case.manifest, identity=identity),
        case.manifest.review.conflict_disclosure,
    )
    with pytest.raises(ValueError, match="catalog|fact set|model program|outcome mapping"):
        _validate(replace(case, manifest=changed))


def test_scope_and_denominator_are_exact_not_digest_only() -> None:
    case = _case()
    other_scope = ScopeKey("other-family", "python")
    denominator = DenominatorPolicy(standard_metric_rules((other_scope,)), IntervalMethod.WILSON_95, "")
    identity = replace(case.manifest.identity, denominator_policy_digest=denominator.policy_digest)
    changed = _resign_manifest(
        replace(
            case.manifest,
            identity=identity,
            denominator_policy_digest=denominator.policy_digest,
        ),
        case.manifest.review.conflict_disclosure,
    )
    with pytest.raises(ValueError, match="denominator scope"):
        _validate(replace(case, manifest=changed, denominator=denominator))


def test_rederived_denominator_digest_cannot_hide_fixed_algebra_mutation() -> None:
    case = _case()
    first = case.denominator.rules[0]
    changed_rule = replace(first, numerator=NumeratorKind.FIXED_DEFECT_CASES)
    object.__setattr__(case.denominator, "rules", (changed_rule, *case.denominator.rules[1:]))
    object.__setattr__(case.denominator, "policy_digest", derive_denominator_policy_digest(case.denominator))
    identity = replace(case.manifest.identity, denominator_policy_digest=case.denominator.policy_digest)
    changed = _resign_manifest(
        replace(
            case.manifest,
            identity=identity,
            denominator_policy_digest=case.denominator.policy_digest,
        ),
        case.manifest.review.conflict_disclosure,
    )

    with pytest.raises(ValueError, match="fixed algebra"):
        _validate(replace(case, manifest=changed))


@pytest.mark.parametrize(
    "kind",
    (
        "policy_subclass",
        "policy_state",
        "rule_subclass",
        "rule_state",
        "tuple_subclass",
        "scope_subclass",
        "scope_state",
        "scalar_subclass",
    ),
)
def test_denominator_graph_rejects_subclasses_and_injected_state(kind: str) -> None:
    case = _case()
    changed = _rebind_denominator(case, _smuggled_denominator(case, kind))

    with pytest.raises(ValueError, match="closed"):
        _validate(changed)


@pytest.mark.parametrize(
    "member",
    (
        MetricId.PAIRED_CORRECTNESS,
        NumeratorKind.CORRECT_PAIRS,
        DenominatorKind.PAIRS,
        IntervalMethod.WILSON_95,
        Statistic.WILSON_LOWER,
        Comparator.AT_LEAST,
    ),
)
def test_admission_graph_rejects_injected_enum_singleton_state(member: object) -> None:
    case = _case()
    object.__setattr__(member, "hidden", "state")
    try:
        with pytest.raises(ValueError, match="closed"):
            _validate(case)
    finally:
        object.__delattr__(member, "hidden")


@pytest.mark.parametrize("kind", ("subclass", "state"))
def test_admission_context_root_is_exact(kind: str) -> None:
    case = _case()
    context: AdmissionValidationContext
    if kind == "subclass":
        context = _as_subclass(case.context, _AdmissionContextSubclass)
    else:
        context = case.context
        object.__setattr__(context, "hidden", "state")

    with pytest.raises(ValueError, match="closed|exact"):
        _validate(replace(case, context=context))


@pytest.mark.parametrize(
    "kind",
    (
        "root_subclass",
        "root_state",
        "entry_subclass",
        "entry_state",
        "program_subclass",
        "program_state",
        "lineage_subclass",
        "lineage_state",
    ),
)
def test_evidence_context_graph_is_closed_before_digest_validation(kind: str) -> None:
    case = _case()
    evidence = case.context.evidence
    changed: EvidenceValidationContext
    if kind == "root_subclass":
        changed = _as_subclass(evidence, _EvidenceContextSubclass)
    elif kind == "root_state":
        changed = evidence
        object.__setattr__(changed, "hidden", "state")
    elif kind.startswith("entry"):
        entry = evidence.family_catalog.entries[0]
        changed_entry = _as_subclass(entry, _CatalogEntrySubclass) if kind.endswith("subclass") else entry
        if kind.endswith("state"):
            object.__setattr__(changed_entry, "hidden", "state")
        catalog = replace(evidence.family_catalog, entries=(changed_entry,))
        changed = replace(evidence, family_catalog=catalog)
    elif kind.startswith("program"):
        program = evidence.model_programs[0]
        changed_program = _as_subclass(program, _ModelProgramSubclass) if kind.endswith("subclass") else program
        if kind.endswith("state"):
            object.__setattr__(changed_program, "hidden", "state")
        changed = replace(evidence, model_programs=(changed_program,))
    else:
        lineage = evidence.lineages[0]
        changed_lineage = _as_subclass(lineage, _LineageSubclass) if kind.endswith("subclass") else lineage
        if kind.endswith("state"):
            object.__setattr__(changed_lineage, "hidden", "state")
        changed = replace(evidence, lineages=(changed_lineage, *evidence.lineages[1:]))
    context = replace(case.context, evidence=changed)

    with pytest.raises(ValueError, match="closed"):
        _validate(replace(case, context=context))


@pytest.mark.parametrize(
    "kind",
    (
        "root_subclass",
        "root_state",
        "identity_subclass",
        "identity_state",
        "fixture_subclass",
        "fixture_state",
        "tuple_subclass",
    ),
)
def test_readiness_graph_and_container_are_closed(kind: str) -> None:
    case = _case()
    first = case.readiness[0]
    changed_first: ReadinessResult
    if kind == "root_subclass":
        changed_first = _as_subclass(first, _ReadinessResultSubclass)
    elif kind == "root_state":
        changed_first = first
        object.__setattr__(changed_first, "hidden", "state")
    elif kind.startswith("identity"):
        identity = _as_subclass(first.identity, _AnalysisIdentitySubclass) if kind.endswith("subclass") else first.identity
        if kind.endswith("state"):
            object.__setattr__(identity, "hidden", "state")
        changed_first = _as_subclass(first, ReadinessResult)
        object.__setattr__(changed_first, "identity", identity)
    elif kind.startswith("fixture"):
        fixture = first.fixture_results[0]
        changed_fixture = _as_subclass(fixture, _FixtureResultSubclass) if kind.endswith("subclass") else fixture
        if kind.endswith("state"):
            object.__setattr__(changed_fixture, "hidden", "state")
        changed_first = _as_subclass(first, ReadinessResult)
        object.__setattr__(changed_first, "fixture_results", (changed_fixture, *first.fixture_results[1:]))
    else:
        readiness: tuple[ReadinessResult, ...] = _ReadinessTupleSubclass(case.readiness)
        with pytest.raises(ValueError, match="tuple"):
            _validate(replace(case, readiness=readiness))
        return
    readiness = (changed_first, *case.readiness[1:])

    with pytest.raises(ValueError, match="closed"):
        _validate(replace(case, readiness=readiness))


@pytest.mark.parametrize(
    "member",
    (
        ReadinessStage.INSTRUMENT,
        ReadinessEvidenceUse.REGRESSION_FIXTURE,
        StageResult.PASSED,
        FixtureRole.POSITIVE,
    ),
)
def test_readiness_graph_rejects_injected_enum_singleton_state(member: object) -> None:
    case = _case()
    object.__setattr__(member, "hidden", "state")
    try:
        with pytest.raises(ValueError, match="closed readiness graph"):
            _validate(case)
    finally:
        object.__delattr__(member, "hidden")


def test_missing_or_stale_readiness_is_refused() -> None:
    case = _case()
    shortened = case.readiness[:-1]
    missing = _resign_manifest(
        replace(case.manifest, readiness_digests=tuple(sorted(item.result_digest for item in shortened))),
        case.manifest.review.conflict_disclosure,
    )
    with pytest.raises(ValueError, match="development readiness"):
        _validate(replace(case, manifest=missing, readiness=shortened))

    stale_identity = replace(case.readiness[0].identity, acquisition_record_digest=canonical.content_digest("drift"))
    stale = _chain(identity=stale_identity)[:6]
    stale_manifest = _resign_manifest(
        replace(case.manifest, readiness_digests=tuple(sorted(item.result_digest for item in stale))),
        case.manifest.review.conflict_disclosure,
    )
    with pytest.raises(ValueError, match="stale|analysis identity|acquisition"):
        _validate(replace(case, manifest=stale_manifest, readiness=stale))


def test_context_substitution_and_lineage_object_tampering_are_refused() -> None:
    case = _case()
    evidence_context = case.context.evidence
    substituted_evidence = validation.make_evidence_validation_context(
        family_catalog=evidence_context.family_catalog,
        fact_packs=evidence_context.fact_packs,
        model_programs=evidence_context.model_programs,
        lineages=evidence_context.lineages[:-1],
        fact_review_policy=evidence_context.fact_review_policy,
        provenance_trust_policy=evidence_context.provenance_trust_policy,
        custody_policy=evidence_context.custody_policy,
    )
    from openultrasast.core import admission_context

    substituted = admission_context.make_admission_validation_context(
        evidence=substituted_evidence,
        admission_review_policy=case.context.admission_review_policy,
        proof_trust_policy=None,
    )
    with pytest.raises(ValueError, match="validation context"):
        _validate(replace(case, context=substituted))

    object.__setattr__(evidence_context.lineages[0].uses[0], "labels_accessed", True)
    with pytest.raises(ValueError, match="lineage|label"):
        _validate(case)


def test_label_influenced_promotion_is_refused_while_admission_population_is_available() -> None:
    case = _case()
    promotion = next(item for item in case.context.evidence.lineages if item.uses[0].purpose is custody.LineagePurpose.PROMOTION)
    source = promotion.uses[0].source_population_digest
    current = case.port.current_log(source)
    request = custody.PopulationUseRequest(
        source,
        promotion.arm_id,
        custody.LineagePurpose.PROMOTION,
        True,
        promotion.subject_digest,
        current.log_digest,
    )
    case.port.append(request, current.custodian_identity)
    assert case.port.current_log(case.manifest.identity.population_digest).status is custody.PopulationStatus.AVAILABLE
    with pytest.raises(ValueError, match="omitted current label-influenced use"):
        _validate(case)


def test_current_custody_head_must_remain_available() -> None:
    case = _case()
    population = case.manifest.identity.population_digest
    current = case.port.current_log(population)
    request = custody.PopulationUseRequest(
        population,
        case.manifest.identity.arm_id,
        custody.LineagePurpose.ADMISSION_LABEL_OPEN,
        True,
        case.manifest.manifest_digest,
        current.log_digest,
    )
    case.port.append(request, current.custodian_identity)
    spent = _resign_manifest(
        replace(case.manifest, custody_log_digest=case.port.current_log(population).log_digest),
        case.manifest.review.conflict_disclosure,
    )
    with pytest.raises(ValueError, match="spent|available"):
        _validate(replace(case, manifest=spent))
