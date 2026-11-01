"""Isolated generic-core consumer for the downstream fact handoff."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from entry_fact_core_wire import (
    FileResolver,
    MemoryCustody,
    contract,
    custody_log,
    fact_match,
    fact_pack,
    lineage_manifest,
    load_envelope,
    obj,
    reference,
    seq,
)
from entry_fact_evidence_wire import record

from openultrasast.core import custody
from openultrasast.core.factapply import apply_fact
from openultrasast.core.factmatch import derive_fact_match_digest, validate_fact_match
from openultrasast.core.factpack import (
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    validate_fact_pack,
)
from openultrasast.core.factvalidate import validate_fact_relations


def _inputs(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = obj(json.loads((root / "manifest.json").read_bytes()))
    envelope_path = next(
        artifact["path"] for case in manifest["cases"] for artifact in case["artifacts"] if artifact["kind"] == "core-replay-envelope"
    )
    return manifest, load_envelope(root / envelope_path)


def _review_policy(value: object) -> ReviewIndependencePolicy:
    row = obj(value)
    return ReviewIndependencePolicy(
        tuple(seq(row["reviewed_reviewer_digests"])),
        tuple(tuple(pair) for pair in seq(row["forbidden_identity_pairs"])),
        tuple(seq(row["trusted_store_identities"])),
        row["maximum_evidence_bytes"],
        row["policy_digest"],
    )


def _custody_policy(value: object) -> custody.PopulationCustodyPolicy:
    row = obj(value)
    return custody.PopulationCustodyPolicy(tuple(seq(row["reviewed_custodian_digests"])), row["policy_digest"])


def _resolver(root: Path, envelope: dict[str, Any]) -> FileResolver:
    entries = {}
    for raw in envelope["resolver_entries"]:
        item = obj(raw)
        ref = reference(item["reference"])
        entries[ref.content_digest] = (ref, item["path"], item["store_identity"])
    return FileResolver(root, entries)


def _changed_match(value: object, mutation: str):
    match = fact_match(value)
    if mutation in {"qualified_name_only", "receiver_omission", "arguments_omission"}:
        keep = {
            "qualified_name_only": {"qualified_target"},
            "receiver_omission": {"qualified_target", "call_shape", "arguments"},
            "arguments_omission": {"qualified_target", "call_shape", "receiver"},
        }[mutation]
        match = replace(
            match, observations=tuple(item for item in match.observations if item.requirement_id in keep), match_digest="0" * 64
        )
    elif mutation == "match_pack_digest_substitution":
        match = replace(match, pack_digest="0" * 64, match_digest="0" * 64)
    return replace(match, match_digest=derive_fact_match_digest(match)) if match.match_digest == "0" * 64 else match


def _self_authored(value: object):
    pack = fact_pack(value)
    first = pack.review_evidence[0]
    attestation = replace(
        first.independence,
        producer_identity=first.reviewer_identity,
        reviewer_identity=first.reviewer_identity,
        attestation_digest="0" * 64,
    )
    attestation = replace(attestation, attestation_digest=derive_independence_attestation_digest(attestation))
    evidence = replace(first, producer_identity=first.reviewer_identity, independence=attestation)
    return replace(pack, review_evidence=(evidence, *pack.review_evidence[1:]))


def replay_all(root: Path) -> dict[str, tuple[str, str | None]]:
    manifest, envelope = _inputs(root)
    contract_value = contract(envelope["contract"])
    pack = fact_pack(envelope["pack"])
    base_match = fact_match(envelope["match"])
    match_reference = reference(envelope["match_reference"])
    lineages = tuple(lineage_manifest(item) for item in seq(envelope["lineages"]))
    policy = _review_policy(envelope["review_policy"])
    custody_policy = _custody_policy(envelope["custody_policy"])
    base_logs = tuple(custody_log(item) for item in seq(envelope["custody_logs"]))
    population = envelope["evaluation_population_digest"]
    expected = {case["case_id"]: (case["expected_status"], case["reason"]) for case in manifest["cases"]}
    results: dict[str, tuple[str, str | None]] = {}
    for raw_plan in envelope["case_plans"]:
        plan = obj(raw_plan)
        case_id, mutation = plan["case_id"], plan["mutation"]
        match = _changed_match(envelope["match"], mutation)
        selected_lineages = lineages
        logs = base_logs
        resolver = _resolver(root, envelope)
        selected_pack = pack
        if mutation == "matcher_lineage_omission":
            selected_lineages = tuple(item for item in lineages if item.manifest_digest != base_match.matcher_lineage_manifest_digest)
        elif mutation == "contaminated_custody":
            contaminated = custody_log(envelope["contaminated_custody_log"])
            logs = tuple(contaminated if item.population_digest == population else item for item in base_logs)
        elif mutation == "resolver_byte_substitution":
            resolver.substitution = (base_match.observations[0].evidence.content_digest, envelope["substituted_content_path"])
        elif mutation == "self_authored_pack":
            selected_pack = _self_authored(envelope["pack"])
        current = MemoryCustody({item.population_digest: item for item in logs})
        results[case_id] = _run_case(
            case_id,
            plan["validator"],
            selected_pack,
            contract_value,
            match,
            match_reference,
            population,
            selected_lineages,
            current,
            custody_policy,
            policy,
            resolver,
            record(envelope["evidence_record"]),
        )
        assert results[case_id] == expected[case_id]
    return results


def _run_case(
    case_id,
    validator,
    pack,
    contract_value,
    match,
    match_reference,
    population,
    lineages,
    current,
    custody_policy,
    policy,
    resolver,
    evidence_record,
):
    try:
        if validator in {"all", "openultrasast.core.factpack.validate_fact_pack"}:
            validate_fact_pack(pack, contract_value, population, lineages, current, custody_policy, policy, resolver)
        if validator in {"all", "openultrasast.core.factmatch.validate_fact_match"}:
            decision = validate_fact_match(pack, match.fact_id, match, population, lineages, current, custody_policy, policy, resolver)
            if not decision.effect_eligible:
                return "refused", _decision_reason(case_id, decision.reasons)
        if validator == "all":
            apply_fact(
                pack, match.fact_id, match, match_reference, contract_value, population, lineages, current, custody_policy, policy, resolver
            )
            validate_fact_relations(
                evidence_record, contract_value, (pack,), population, lineages, current, custody_policy, policy, resolver
            )
        return "passed", None
    except (TypeError, ValueError) as exc:
        return "refused", _error_reason(case_id, str(exc))


def _decision_reason(case_id: str, reasons: tuple[str, ...]) -> str:
    expected = {
        "custody_contamination": "protected_population_contamination",
        "legacy_projection_only": "name_only_match",
        "name_only": "missing_observation:receiver",
        "partial": "missing_observation:arguments",
    }[case_id]
    assert expected in reasons or any(item.startswith("protected_population_labels:") for item in reasons)
    return expected


def _error_reason(case_id: str, message: str) -> str:
    expected = {
        "authority_substitution": ("match pack digest", "match_pack_identity_substituted"),
        "lineage_omission": ("matcher lineage", "matcher_lineage_omitted"),
        "producer_reviewer_conflict": ("producer and reviewer", "self_authored_review_evidence"),
        "resolver_byte_substitution": ("resolved content digest", "resolver_byte_substitution"),
    }[case_id]
    assert expected[0] in message
    return expected[1]
