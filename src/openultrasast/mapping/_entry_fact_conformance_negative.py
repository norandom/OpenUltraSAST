"""Negative and replay cases for the downstream entry-fact handoff."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn

from openultrasast.core import canonical, provenance
from openultrasast.core.factmatch import validate_fact_match
from openultrasast.core.factpack import derive_independence_attestation_digest
from openultrasast.mapping.authority_ceremony import load_installed_authority_ceremony
from openultrasast.mapping.entry_fact_matcher import EntryFactMatchResult, match_entry_fact
from openultrasast.mapping.entry_packs import load_entry_pack_patterns
from openultrasast.mapping.fact_authority import EntryFactAuthorityContext, authenticate_entry_fact_authority
from openultrasast.mapping.fact_match_store import FactMatchArtifactWriter
from openultrasast.mapping.installed_fact_authority import fact_pack_bytes, installed_authority_bytes

_AUTHENTICATE = "openultrasast.mapping.fact_authority.authenticate_entry_fact_authority"


def negative_cases(
    fixture_root: Path,
    output: Path,
    sources: dict[str, tuple[str, bytes]],
    context: EntryFactAuthorityContext,
    evaluation: str,
    complete: EntryFactMatchResult,
) -> tuple[dict[str, canonical.JsonValue], ...]:
    from openultrasast.mapping.entry_fact_conformance import (
        _CORE_ENTRY_POINTS,
        _case,
        _persist,
        _validator,
    )

    common = (_persist(output, fact_pack_bytes(complete.pack), "fact-pack"),)
    rows = _structural_refusals(fixture_root, output, sources, context, evaluation, common)
    rows.extend(_authority_cases(output, sources, context))
    rows.append(_resolver_case(sources["resolver_byte_substitution"], common, context, evaluation, complete))
    rows.extend(_lineage_cases(sources, context, evaluation, complete, common))
    rows.append(_contaminated_case(sources["custody_contamination"], common, context, evaluation, complete))
    _legacy_only(fixture_root, output, sources, context, evaluation)
    rows.append(
        _case(
            "legacy_projection_only",
            sources["legacy_projection_only"],
            "refused",
            "name_only_match",
            common,
            (_validator(_CORE_ENTRY_POINTS[1], "refused", "name_only_match"),),
        )
    )
    return tuple(rows)


def _authority_cases(
    output: Path,
    sources: dict[str, tuple[str, bytes]],
    context: EntryFactAuthorityContext,
) -> tuple[dict[str, canonical.JsonValue], ...]:
    from openultrasast.mapping.entry_fact_conformance import _case, _installed_entries, _persist, _validator

    bundle = context.bundle
    ceremony = load_installed_authority_ceremony(_installed_entries())
    substituted = replace(bundle, bundle_digest="0" * 64)
    _expect_error(
        lambda: authenticate_entry_fact_authority(substituted, ceremony.bootstrap, context.custody, context.resolver),
        "authority bundle digest",
    )
    substituted_case = _case(
        "authority_substitution",
        sources["authority_substitution"],
        "refused",
        "match_pack_identity_substituted",
        (_persist(output, installed_authority_bytes(substituted), "authority"),),
        (_validator("openultrasast.core.factmatch.validate_fact_match", "refused", "match_pack_identity_substituted"),),
        (_validator(_AUTHENTICATE, "refused", "authority_bundle_digest_substituted"),),
    )
    review = replace(bundle.authority_review, producer_identity=bundle.authority_review.reviewer_identity, attestation_digest="0" * 64)
    review = replace(review, attestation_digest=derive_independence_attestation_digest(review))
    conflicted = replace(bundle, authority_review=review)
    _expect_error(
        lambda: authenticate_entry_fact_authority(conflicted, ceremony.bootstrap, context.custody, context.resolver),
        "producer and reviewer",
    )
    conflict_case = _case(
        "producer_reviewer_conflict",
        sources["producer_reviewer_conflict"],
        "refused",
        "self_authored_review_evidence",
        (_persist(output, installed_authority_bytes(conflicted), "authority"),),
        (_validator("openultrasast.core.factpack.validate_fact_pack", "refused", "self_authored_review_evidence"),),
        (_validator(_AUTHENTICATE, "refused", "producer_reviewer_conflict"),),
    )
    return substituted_case, conflict_case


def _resolver_case(
    source: tuple[str, bytes],
    artifacts: tuple[dict[str, canonical.JsonValue], ...],
    context: EntryFactAuthorityContext,
    evaluation: str,
    complete: EntryFactMatchResult,
) -> dict[str, canonical.JsonValue]:
    from openultrasast.mapping.entry_fact_conformance import _CORE_ENTRY_POINTS, _case, _SubstitutingResolver, _validator

    bundle = context.bundle
    target = complete.match.observations[0].evidence.content_digest
    resolver = _SubstitutingResolver(complete.resolver, target)
    _expect_error(
        lambda: validate_fact_match(
            complete.pack,
            complete.match.fact_id,
            complete.match,
            evaluation,
            bundle.lineages,
            context.custody,
            bundle.custody_policy,
            bundle.review_policy,
            resolver,
        ),
        "resolved content digest",
    )
    return _case(
        "resolver_byte_substitution",
        source,
        "refused",
        "resolver_byte_substitution",
        artifacts,
        (_validator(_CORE_ENTRY_POINTS[1], "refused", "resolver_byte_substitution"),),
    )


def _structural_refusals(
    root: Path,
    output: Path,
    sources: dict[str, tuple[str, bytes]],
    context: EntryFactAuthorityContext,
    evaluation: str,
    artifacts: tuple[dict[str, canonical.JsonValue], ...],
) -> list[dict[str, canonical.JsonValue]]:
    from openultrasast.mapping.entry_fact_conformance import _CORE_ENTRY_POINTS, _case, _match, _match_artifacts, _validator

    rows = []
    for case_id, reason in (("name_only", "missing_observation:receiver"), ("partial", "missing_observation:arguments")):
        result = _match(root, output, context, evaluation, sources[case_id][0])
        if result.decision.effect_eligible or reason not in result.decision.reasons:
            _fail(f"{case_id} did not refuse with its stable reason")
        case_artifacts = (*artifacts, *_match_artifacts(output, result))
        rows.append(
            _case(
                case_id,
                sources[case_id],
                "refused",
                reason,
                case_artifacts,
                (_validator(_CORE_ENTRY_POINTS[1], "refused", reason),),
            )
        )
    return rows


def _lineage_cases(
    sources: dict[str, tuple[str, bytes]],
    context: EntryFactAuthorityContext,
    evaluation: str,
    complete: EntryFactMatchResult,
    artifacts: tuple[dict[str, canonical.JsonValue], ...],
) -> tuple[dict[str, canonical.JsonValue], ...]:
    from openultrasast.mapping.entry_fact_conformance import _CORE_ENTRY_POINTS, _case, _validator

    bundle = context.bundle
    omitted = tuple(item for item in bundle.lineages if item.manifest_digest != complete.match.matcher_lineage_manifest_digest)
    _expect_error(
        lambda: validate_fact_match(
            complete.pack,
            complete.match.fact_id,
            complete.match,
            evaluation,
            omitted,
            context.custody,
            bundle.custody_policy,
            bundle.review_policy,
            complete.resolver,
        ),
        "matcher lineage",
    )
    omitted_case = _case(
        "lineage_omission",
        sources["lineage_omission"],
        "refused",
        "matcher_lineage_omitted",
        artifacts,
        (_validator(_CORE_ENTRY_POINTS[1], "refused", "matcher_lineage_omitted"),),
    )
    replay = validate_fact_match(
        complete.pack,
        complete.match.fact_id,
        complete.match,
        evaluation,
        bundle.lineages,
        context.custody,
        bundle.custody_policy,
        bundle.review_policy,
        complete.resolver,
    )
    if not replay.effect_eligible:
        _fail("deterministic replay did not remain complete")
    replay_case = _case(
        "deterministic_replay", sources["deterministic_replay"], "passed", None, artifacts, (_validator(_CORE_ENTRY_POINTS[1], "passed"),)
    )
    return omitted_case, replay_case


def _contaminated_case(
    source: tuple[str, bytes],
    artifacts: tuple[dict[str, canonical.JsonValue], ...],
    context: EntryFactAuthorityContext,
    evaluation: str,
    complete: EntryFactMatchResult,
) -> dict[str, canonical.JsonValue]:
    from openultrasast.mapping.entry_fact_conformance import _CORE_ENTRY_POINTS, _case, _Custody, _validator

    custody = context.custody
    if not isinstance(custody, _Custody):
        _fail("conformance custody has the wrong type")
    prior = custody.current_log(evaluation)
    lineage = next(item for item in context.bundle.lineages if item.manifest_digest == complete.match.matcher_lineage_manifest_digest)
    custody.append(
        provenance.PopulationUseRequest(
            evaluation,
            lineage.arm_id,
            provenance.LineagePurpose.MATCHING_BEHAVIOR,
            True,
            complete.match.matcher_behavior_digest,
            prior.log_digest,
        )
    )
    decision = validate_fact_match(
        complete.pack,
        complete.match.fact_id,
        complete.match,
        evaluation,
        context.bundle.lineages,
        custody,
        context.bundle.custody_policy,
        context.bundle.review_policy,
        complete.resolver,
    )
    reason = next((item for item in decision.reasons if item.startswith("protected_population_labels:")), None)
    if decision.effect_eligible or reason is None:
        _fail("protected population contamination was not refused")
    return _case(
        "custody_contamination",
        source,
        "refused",
        "protected_population_contamination",
        artifacts,
        (_validator(_CORE_ENTRY_POINTS[1], "refused", "protected_population_contamination"),),
    )


def _legacy_only(
    root: Path, output: Path, sources: dict[str, tuple[str, bytes]], context: EntryFactAuthorityContext, evaluation: str
) -> None:
    content = sources["legacy_projection_only"][1].decode("utf-8")
    patterns = load_entry_pack_patterns()["javascript"]
    writer = FactMatchArtifactWriter(
        output, context.bundle.review_policy.trusted_store_identities[0], canonical.content_digest("retain-access-control-conformance-v1")
    )
    matches = match_entry_fact(
        repository_root=root,
        relative_path=sources["legacy_projection_only"][0],
        language="javascript",
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=writer,
        evaluation_population_digest=evaluation,
    )
    if not any(pattern.search(content) for pattern in patterns) or matches:
        _fail("legacy-only fixture did not isolate projection recognition")


def _expect_error(action: Any, fragment: str) -> None:
    try:
        action()
    except (TypeError, ValueError) as exc:
        if fragment not in str(exc):
            _fail(f"validator refusal changed: {exc}", exc)
        return
    _fail("negative conformance case unexpectedly passed")


def _fail(message: str, cause: Exception | None = None) -> NoReturn:
    from openultrasast.mapping.entry_fact_conformance import EntryFactConformanceError

    if cause is not None:
        raise EntryFactConformanceError(message) from cause
    raise EntryFactConformanceError(message)
