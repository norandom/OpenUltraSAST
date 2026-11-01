"""Reproducible downstream conformance handoff for reviewed entry facts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from openultrasast.core import canonical, evidence, family, provenance, semantics
from openultrasast.core.factapply import apply_fact
from openultrasast.core.factmatch import validate_fact_match
from openultrasast.core.factpack import validate_fact_pack
from openultrasast.core.factvalidate import validate_fact_relations
from openultrasast.mapping._entry_fact_conformance_fs import (
    ConformanceFilesystemError,
    ensure_real_directory,
    persist_regular_nofollow,
    read_regular_nofollow,
    require_real_directory,
)
from openultrasast.mapping.entry_fact_matcher import EntryFactMatchResult, match_entry_fact
from openultrasast.mapping.entry_packs import load_installed_entry_fact_authority
from openultrasast.mapping.fact_authority import EntryFactAuthorityContext
from openultrasast.mapping.fact_match_store import FactMatchArtifactWriter
from openultrasast.mapping.installed_fact_authority import fact_pack_bytes

ENTRY_FACT_CONFORMANCE_SCHEMA = "openultrasast.access-control.entry-fact-conformance.v1"
_CORE_ENTRY_POINTS = (
    "openultrasast.core.factapply.apply_fact",
    "openultrasast.core.factmatch.validate_fact_match",
    "openultrasast.core.factpack.validate_fact_pack",
    "openultrasast.core.factvalidate.validate_fact_relations",
)
_SOURCE_CASES = {
    "complete": "sources/complete.js",
    "name_only": "sources/name-only.js",
    "partial": "sources/partial.js",
    "authority_substitution": "sources/complete.js",
    "producer_reviewer_conflict": "sources/complete.js",
    "resolver_byte_substitution": "sources/complete.js",
    "lineage_omission": "sources/complete.js",
    "custody_contamination": "sources/complete.js",
    "legacy_projection_only": "sources/legacy-only.js",
    "deterministic_replay": "sources/complete.js",
}


class EntryFactConformanceError(ValueError):
    """The target-owned conformance fixture cannot be reproduced safely."""


class _UnusedCustody:
    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        raise AssertionError(f"authority load read custody: {population_digest}")


class _Custody:
    def __init__(self, logs: tuple[provenance.PopulationCustodyLog, ...], policy: provenance.PopulationCustodyPolicy):
        self.logs = {item.population_digest: item for item in logs}
        self.policy = policy

    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        try:
            return self.logs[population_digest]
        except KeyError as exc:
            raise provenance.PopulationCustodyError("population custody log not found") from exc

    def append(self, request: provenance.PopulationUseRequest) -> provenance.PopulationUseReceipt:
        prior = self.current_log(request.population_digest)
        custodian = self.policy.reviewed_custodian_digests[0]
        receipt = provenance.record_population_use(request, prior, custodian, self.policy)
        self.logs[request.population_digest] = provenance.append_population_use(prior, receipt, self.policy)
        return receipt


@dataclass(frozen=True)
class _SubstitutingResolver:
    delegate: canonical.ContentResolver
    digest: str

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        resolved = self.delegate.resolve(reference)
        if reference.content_digest != self.digest:
            return resolved
        return canonical.ResolvedContent(b"!" + resolved.content[1:], resolved.receipt)


def _installed_entries() -> Path:
    import openultrasast

    return Path(openultrasast.__file__).resolve().parent / "ruleset" / "entries"


def _context() -> tuple[EntryFactAuthorityContext, str, _Custody]:
    loaded = load_installed_entry_fact_authority(_UnusedCustody())
    bundle = loaded.bundle
    custodian = bundle.custody_policy.reviewed_custodian_digests[0]
    logs: dict[str, provenance.PopulationCustodyLog] = {}
    for lineage in bundle.lineages:
        for use in lineage.uses:
            prior = logs.setdefault(
                use.source_population_digest,
                provenance.empty_population_custody_log(use.source_population_digest, custodian),
            )
            request = provenance.PopulationUseRequest(
                use.source_population_digest,
                lineage.arm_id,
                use.purpose,
                use.labels_accessed,
                use.influenced_artifact_digest,
                prior.log_digest,
            )
            receipt = provenance.record_population_use(request, prior, custodian, bundle.custody_policy)
            if receipt.receipt_digest != use.population_use_receipt_digest:
                raise EntryFactConformanceError("installed lineage receipt cannot be reproduced")
            logs[use.source_population_digest] = provenance.append_population_use(prior, receipt, bundle.custody_policy)
    evaluation = canonical.content_digest("access-control-entry-conformance-population-v1")
    logs[evaluation] = provenance.empty_population_custody_log(evaluation, custodian)
    custody = _Custody(tuple(logs.values()), bundle.custody_policy)
    return replace(loaded, custody=custody), evaluation, custody


def _read_sources(root: Path) -> dict[str, tuple[str, bytes]]:
    values: dict[str, tuple[str, bytes]] = {}
    try:
        require_real_directory(root / "sources")
    except ConformanceFilesystemError as exc:
        raise EntryFactConformanceError("sources require a real non-symlink directory") from exc
    for case_id, relative in _SOURCE_CASES.items():
        try:
            content = read_regular_nofollow(root / relative)
        except ConformanceFilesystemError as exc:
            raise EntryFactConformanceError(f"{case_id} requires a nonempty readable fixture") from exc
        if not content:
            raise EntryFactConformanceError(f"{case_id} requires a nonempty readable fixture")
        values[case_id] = (relative, content)
    return values


def _persist(output: Path, content: bytes, kind: str) -> dict[str, canonical.JsonValue]:
    if not content:
        raise EntryFactConformanceError("handoff artifacts must be nonempty")
    digest = canonical.bytes_digest(content)
    relative = f"artifacts/sha256/{digest}"
    target = output / relative
    try:
        ensure_real_directory(output)
        ensure_real_directory(output / "artifacts")
        ensure_real_directory(target.parent)
        persist_regular_nofollow(target, content)
    except ConformanceFilesystemError as exc:
        raise EntryFactConformanceError("artifact path is unsafe or not a regular file") from exc
    return {"kind": kind, "path": relative, "content_digest": digest, "byte_length": len(content)}


def _validator(name: str, status: str, reason: str | None = None) -> dict[str, canonical.JsonValue]:
    return {"name": name, "status": status, "reason": reason}


def _case(
    case_id: str,
    source: tuple[str, bytes],
    expected: str,
    reason: str | None,
    artifacts: tuple[dict[str, canonical.JsonValue], ...],
    validators: tuple[dict[str, canonical.JsonValue], ...],
    downstream_validators: tuple[dict[str, canonical.JsonValue], ...] = (),
) -> dict[str, canonical.JsonValue]:
    path, content = source
    return {
        "case_id": case_id,
        "fixture_path": path,
        "fixture_digest": canonical.bytes_digest(content),
        "fixture_byte_length": len(content),
        "expected_status": expected,
        "reason": reason,
        "artifacts": artifacts,
        "validators": validators,
        "downstream_validators": downstream_validators,
    }


def _match(root: Path, output: Path, context: EntryFactAuthorityContext, evaluation: str, relative: str) -> EntryFactMatchResult:
    writer = FactMatchArtifactWriter(
        output,
        context.bundle.review_policy.trusted_store_identities[0],
        canonical.content_digest("retain-access-control-conformance-v1"),
    )
    results = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language="javascript",
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=writer,
        evaluation_population_digest=evaluation,
    )
    if len(results) != 1:
        raise EntryFactConformanceError("fixture must produce exactly one structural candidate")
    return results[0]


def _match_artifacts(output: Path, result: EntryFactMatchResult) -> tuple[dict[str, canonical.JsonValue], ...]:
    refs = tuple(item.evidence for item in result.match.observations) + (result.match_reference,)
    return tuple(_persist(output, result.resolver.resolve(ref).content, "match-evidence") for ref in refs)


def _stamp(contract: str, evaluation: str, source_digest: str, result: EntryFactMatchResult) -> provenance.ProvenanceStamp:
    return provenance.ProvenanceStamp(
        canonical.content_digest("entry-conformance-analyzer"),
        contract,
        canonical.content_digest((result.pack.normalized_content_digest,)),
        canonical.content_digest("entry-conformance-acquisition"),
        canonical.content_digest("entry-conformance-configuration"),
        evaluation,
        source_digest,
    )


def _record(result: EntryFactMatchResult, evaluation: str, source_digest: str) -> evidence.EvidenceRecord:
    location = result.match.product_location
    source = semantics.SemanticNode("constraint-source", "security_object", location)
    target = semantics.SemanticNode("constraint-target", "operation", location)
    product = semantics.EvidenceProvenance(semantics.ProvenanceKind.PRODUCT_CODE, source_digest, None, None, None)
    constraint = semantics.make_relation(
        kind=semantics.RelationKind.CONSTRAINT_EFFECT,
        role="constraint",
        source=source,
        target=target,
        location=location,
        status=semantics.RelationStatus.INCOMPLETE,
        conditions=(),
        reasons=("missing_constraint_relation",),
        provenance=product,
    )
    fields = (
        semantics.FieldValue("operation", semantics.FieldKind.TEXT, "entry-registration"),
        semantics.FieldValue("boundary", semantics.FieldKind.TEXT, "express"),
    )
    scope = evidence.AnalyzedScope("base", "head", source_digest, (evidence.SourceRegion(location.path, 1, 4),))
    contract = result.pack.family_contract_digest
    packet = evidence.EvidencePacket(
        evidence.EVIDENCE_PACKET_SCHEMA,
        result.pack.family_id,
        contract,
        family.derive_security_object_id(_context_contract().security_object, fields),
        result.pack.ecosystem,
        scope,
        (*result.relations, constraint),
        (),
        fields,
        ("missing_constraint_relation",),
        _stamp(contract, evaluation, source_digest, result),
    )
    decision = evidence.Decision(
        "indeterminate",
        evidence.NeutralOutcome.INDETERMINATE,
        evidence.EvidenceBasis.DETERMINISTIC,
        scope,
        ("missing_constraint_relation",),
        evidence.derive_packet_digest(packet),
        provenance.DecisionProvenance(None, None, None, None, None, None),
    )
    return evidence.EvidenceRecord(packet, decision, "")


def _context_contract() -> family.FamilyContract:
    from openultrasast.semantic.obligations.core_contract import production_access_control_contract

    return production_access_control_contract()


def _complete_case(
    fixture_root: Path,
    output: Path,
    source: tuple[str, bytes],
    context: EntryFactAuthorityContext,
    evaluation: str,
) -> tuple[dict[str, canonical.JsonValue], EntryFactMatchResult]:
    result = _match(fixture_root, output, context, evaluation, source[0])
    record = _validate_complete(result, context, evaluation, source)
    artifacts = _match_artifacts(output, result)
    artifacts += (_persist(output, fact_pack_bytes(result.pack), "fact-pack"),)
    artifacts += (_persist(output, evidence.evidence_record_bytes(record), "evidence-record"),)
    validators = tuple(_validator(name, "passed") for name in _CORE_ENTRY_POINTS)
    return _case("complete", source, "passed", None, artifacts, validators), result


def _validate_complete(
    result: EntryFactMatchResult,
    context: EntryFactAuthorityContext,
    evaluation: str,
    source: tuple[str, bytes],
) -> evidence.EvidenceRecord:
    bundle = context.bundle
    validate_fact_pack(
        result.pack,
        bundle.contract,
        evaluation,
        bundle.lineages,
        context.custody,
        bundle.custody_policy,
        bundle.review_policy,
        result.resolver,
    )
    validate_fact_match(
        result.pack,
        result.match.fact_id,
        result.match,
        evaluation,
        bundle.lineages,
        context.custody,
        bundle.custody_policy,
        bundle.review_policy,
        result.resolver,
    )
    apply_fact(
        result.pack,
        result.match.fact_id,
        result.match,
        result.match_reference,
        bundle.contract,
        evaluation,
        bundle.lineages,
        context.custody,
        bundle.custody_policy,
        bundle.review_policy,
        result.resolver,
    )
    record = _record(result, evaluation, canonical.bytes_digest(source[1]))
    _validate_record(record, result, context, evaluation)
    return record


def _validate_record(
    record: evidence.EvidenceRecord,
    result: EntryFactMatchResult,
    context: EntryFactAuthorityContext,
    evaluation: str,
) -> None:
    bundle = context.bundle
    validate_fact_relations(
        record,
        bundle.contract,
        bundle.packs,
        evaluation,
        bundle.lineages,
        context.custody,
        bundle.custody_policy,
        bundle.review_policy,
        result.resolver,
    )


def build_entry_fact_conformance(fixture_root: Path, output_root: Path) -> bytes:
    """Run the target adapter and return its canonical immutable handoff manifest."""
    fixture_root, output_root = Path(fixture_root), Path(output_root)
    sources = _read_sources(fixture_root)
    context, evaluation, _ = _context()
    complete, result = _complete_case(fixture_root, output_root, sources["complete"], context, evaluation)
    from openultrasast.mapping._entry_fact_conformance_negative import negative_cases
    from openultrasast.mapping._entry_fact_conformance_replay import attach_replay, replay_material

    cases = (complete, *negative_cases(fixture_root, output_root, sources, context, evaluation, result))
    replay, dependencies = replay_material(output_root, context, evaluation, result, sources["complete"])
    cases = attach_replay(tuple(sorted(cases, key=lambda item: str(item["case_id"]))), replay, dependencies)
    payload: dict[str, canonical.JsonValue] = {
        "schema_version": ENTRY_FACT_CONFORMANCE_SCHEMA,
        "core_entry_points": _CORE_ENTRY_POINTS,
        "cases": cases,
    }
    manifest = {**payload, "handoff_digest": canonical.content_digest(payload)}
    return canonical.canonical_record_bytes(manifest, known_schema_versions=(ENTRY_FACT_CONFORMANCE_SCHEMA,))


def write_entry_fact_conformance(fixture_root: Path, output_root: Path) -> Path:
    """Generate artifacts and atomically-equivalent canonical manifest bytes."""
    output = Path(output_root)
    content = build_entry_fact_conformance(fixture_root, output)
    target = output / "manifest.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


__all__ = [
    "ENTRY_FACT_CONFORMANCE_SCHEMA",
    "EntryFactConformanceError",
    "build_entry_fact_conformance",
    "write_entry_fact_conformance",
]
