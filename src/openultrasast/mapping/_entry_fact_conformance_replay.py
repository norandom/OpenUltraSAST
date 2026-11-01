"""Materialize the self-sufficient generic-core replay artifact."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from openultrasast.core import canonical, provenance
from openultrasast.mapping._installed_fact_authority_codec import wire_value
from openultrasast.mapping.authority_ceremony import INSTALLED_ARTIFACT_STORE_IDENTITY
from openultrasast.mapping.entry_fact_matcher import EntryFactMatchResult
from openultrasast.mapping.fact_authority import EntryFactAuthorityContext


def _resolver_material(
    output: Path,
    result: EntryFactMatchResult,
) -> tuple[tuple[dict[str, canonical.JsonValue], ...], tuple[dict[str, canonical.JsonValue], ...], str]:
    from openultrasast.mapping.entry_fact_conformance import _persist

    refs = [item.content for item in result.pack.review_evidence]
    refs.extend(item.independence.conflict_disclosure for item in result.pack.review_evidence)
    refs.extend(item.evidence for item in result.match.observations)
    refs.append(result.match_reference)
    artifacts: list[dict[str, canonical.JsonValue]] = []
    entries: list[dict[str, canonical.JsonValue]] = []
    for reference in refs:
        artifact = _persist(output, result.resolver.resolve(reference).content, "resolver-content")
        artifacts.append(artifact)
        entries.append(
            {
                "reference": wire_value(reference),
                "path": artifact["path"],
                "store_identity": INSTALLED_ARTIFACT_STORE_IDENTITY,
            }
        )
    target = result.match.observations[0].evidence
    original = result.resolver.resolve(target).content
    substituted = _persist(output, b"!" + original[1:], "substituted-content")
    artifacts.append(substituted)
    return tuple(entries), tuple(artifacts), str(substituted["path"])


def replay_material(
    output: Path,
    context: EntryFactAuthorityContext,
    evaluation: str,
    result: EntryFactMatchResult,
    source: tuple[str, bytes],
) -> tuple[dict[str, canonical.JsonValue], tuple[dict[str, canonical.JsonValue], ...]]:
    from openultrasast.mapping._entry_fact_conformance_wire import replay_envelope_bytes
    from openultrasast.mapping.entry_fact_conformance import EntryFactConformanceError, _Custody, _persist, _record

    custody = context.custody
    if not isinstance(custody, _Custody):
        raise EntryFactConformanceError("conformance custody has the wrong type")
    contaminated = custody.current_log(evaluation)
    custodian = context.bundle.custody_policy.reviewed_custodian_digests[0]
    base_evaluation = provenance.empty_population_custody_log(evaluation, custodian)
    base_logs = tuple(base_evaluation if digest == evaluation else log for digest, log in sorted(custody.logs.items()))
    entries, artifacts, substituted_path = _resolver_material(output, result)
    record = _record(result, evaluation, canonical.bytes_digest(source[1]))
    content = replay_envelope_bytes(
        context=context,
        evaluation_population_digest=evaluation,
        result=result,
        record=record,
        base_logs=base_logs,
        contaminated_log=contaminated,
        resolver_entries=entries,
        substituted_content_path=substituted_path,
    )
    return _persist(output, content, "core-replay-envelope"), artifacts


def attach_replay(
    cases: tuple[dict[str, canonical.JsonValue], ...],
    envelope: dict[str, canonical.JsonValue],
    dependencies: tuple[dict[str, canonical.JsonValue], ...],
) -> tuple[dict[str, canonical.JsonValue], ...]:
    values = []
    for case in cases:
        artifacts = case["artifacts"]
        if not isinstance(artifacts, tuple):
            raise TypeError("case artifacts must be a tuple")
        if not all(isinstance(item, Mapping) for item in artifacts):
            raise TypeError("case artifact entries must be objects")
        existing = {str(item["path"]): item for item in artifacts if isinstance(item, Mapping)}
        existing[str(envelope["path"])] = envelope
        if case["case_id"] == "complete":
            existing.update({str(item["path"]): item for item in dependencies})
        values.append({**case, "artifacts": tuple(existing[path] for path in sorted(existing))})
    return tuple(values)


__all__ = ["attach_replay", "replay_material"]
