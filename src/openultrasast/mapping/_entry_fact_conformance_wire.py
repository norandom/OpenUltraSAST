"""Canonical generic-core replay envelope for the entry-fact handoff."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from openultrasast.core import canonical, evidence, provenance
from openultrasast.mapping._installed_fact_authority_codec import wire_value
from openultrasast.mapping.entry_fact_matcher import EntryFactMatchResult
from openultrasast.mapping.fact_authority import EntryFactAuthorityContext

ENTRY_FACT_REPLAY_SCHEMA = "openultrasast.access-control.entry-fact-core-replay.v1"


def _case_plans() -> tuple[Mapping[str, canonical.JsonValue], ...]:
    match = "openultrasast.core.factmatch.validate_fact_match"
    return (
        {"case_id": "authority_substitution", "replay_kind": "core", "validator": match, "mutation": "match_pack_digest_substitution"},
        {"case_id": "complete", "replay_kind": "core", "validator": "all", "mutation": "none"},
        {"case_id": "custody_contamination", "replay_kind": "core", "validator": match, "mutation": "contaminated_custody"},
        {"case_id": "deterministic_replay", "replay_kind": "core", "validator": match, "mutation": "none"},
        {"case_id": "legacy_projection_only", "replay_kind": "core", "validator": match, "mutation": "qualified_name_only"},
        {"case_id": "lineage_omission", "replay_kind": "core", "validator": match, "mutation": "matcher_lineage_omission"},
        {"case_id": "name_only", "replay_kind": "core", "validator": match, "mutation": "qualified_name_only"},
        {"case_id": "partial", "replay_kind": "core", "validator": match, "mutation": "arguments_omission"},
        {
            "case_id": "producer_reviewer_conflict",
            "replay_kind": "core",
            "validator": "openultrasast.core.factpack.validate_fact_pack",
            "mutation": "self_authored_pack",
        },
        {"case_id": "resolver_byte_substitution", "replay_kind": "core", "validator": match, "mutation": "resolver_byte_substitution"},
    )


def replay_envelope_bytes(
    *,
    context: EntryFactAuthorityContext,
    evaluation_population_digest: str,
    result: EntryFactMatchResult,
    record: evidence.EvidenceRecord,
    base_logs: Sequence[provenance.PopulationCustodyLog],
    contaminated_log: provenance.PopulationCustodyLog,
    resolver_entries: Sequence[Mapping[str, canonical.JsonValue]],
    substituted_content_path: str,
) -> bytes:
    """Serialize every family-neutral input needed for independent core replay."""
    payload: Mapping[str, canonical.JsonValue] = {
        "schema_version": ENTRY_FACT_REPLAY_SCHEMA,
        "contract": wire_value(context.bundle.contract),
        "pack": wire_value(result.pack),
        "fact_id": result.match.fact_id,
        "match": wire_value(result.match),
        "match_reference": wire_value(result.match_reference),
        "evidence_record": wire_value(record),
        "evaluation_population_digest": evaluation_population_digest,
        "lineages": wire_value(context.bundle.lineages),
        "review_policy": wire_value(context.bundle.review_policy),
        "custody_policy": wire_value(context.bundle.custody_policy),
        "custody_logs": wire_value(tuple(base_logs)),
        "contaminated_custody_log": wire_value(contaminated_log),
        "resolver_entries": tuple(resolver_entries),
        "substituted_content_path": substituted_content_path,
        "case_plans": tuple(_case_plans()),
    }
    envelope = {**payload, "envelope_digest": canonical.content_digest(payload)}
    return canonical.canonical_record_bytes(envelope, known_schema_versions=(ENTRY_FACT_REPLAY_SCHEMA,))


__all__ = ["ENTRY_FACT_REPLAY_SCHEMA", "replay_envelope_bytes"]
