"""Independent current-state validation of complete V3 evaluation replay."""

from __future__ import annotations

from dataclasses import replace

import pytest
from detection_core_fixtures import InMemoryContentResolver
from test_core_evaluation_case_validation import _bundle, _scoped_authority_case
from test_core_evaluation_plan import _digest
from test_core_evaluation_replay import _assemble, _inputs

from openultrasast.core.evaluation_measurement import ScopeKey


def _bundle_case():
    scope = ScopeKey("reference-family", "python")
    authority_case = _scoped_authority_case(
        {"arm-a": scope, "arm-b": scope, "arm-combined": scope},
        ordinary_count=1,
        whole_count=3,
        scope_counts=(1, 1, 1, 6, 3),
        minimum_pairs=1,
        minimum_ordinary_pushes=1,
        relaxed_precision=True,
    )
    return _bundle(
        authority_case=authority_case,
        aligned_combination_cases=True,
        shared_underlying_by_ecosystem=True,
        model_evidence=True,
    )


def _case():
    bundle = _bundle_case()
    replay = _assemble(*_inputs(bundle=bundle, canonical_sources=True))
    context_case = bundle[5][0]
    return replay, context_case.context, context_case.port, bundle[4]


def _validate(replay, context, custody, resolver):
    from openultrasast.core.evaluation_replay_validation import validate_evaluation_replay_v3

    return validate_evaluation_replay_v3(replay, context, custody, resolver)


def test_complete_replay_re_resolves_and_reproduces_exact_reports() -> None:
    replay, context, custody, resolver = _case()

    reports = _validate(replay, context, custody, resolver)

    assert reports == replay.reports
    assert reports is not replay.reports


@pytest.mark.parametrize("artifact", ("observation", "attempt", "review"))
def test_missing_current_source_artifact_refuses_replay(artifact: str) -> None:
    replay, context, custody, resolver = _case()
    if artifact == "observation":
        artifact_id = replay.admission_manifest.observations[0].observation.artifact_id
    elif artifact == "attempt":
        artifact_id = replay.admission_manifest.attempt_history.events[0].event.artifact_id
    else:
        artifact_id = replay.plan_manifest.review.conflict_disclosure.artifact_id
    missing = InMemoryContentResolver({key: value for key, value in resolver.artifacts.items() if key != artifact_id})

    with pytest.raises(Exception, match="artifact|resolve|review|observation|attempt"):
        _validate(replay, context, custody, missing)


def test_current_custody_mutation_refuses_stale_replay() -> None:
    replay, context, custody, resolver = _case()
    population = replay.plan_manifest.declaration.population_digest
    current = custody.current_log(population)
    custody.logs[population] = replace(current, log_digest=_digest("changed-current-custody"))

    with pytest.raises(Exception, match="custody|spend|receipt|log"):
        _validate(replay, context, custody, resolver)


def test_current_context_mutation_refuses_replay() -> None:
    replay, context, custody, resolver = _case()
    changed = replace(context, context_digest=_digest("changed-validation-context"))

    with pytest.raises(Exception, match="context|authority|canonical"):
        _validate(replay, changed, custody, resolver)


def test_coordinated_caller_summary_rehash_refuses_replay() -> None:
    bundle = _bundle_case()
    summarized = _assemble(*_inputs(bundle=bundle))
    context_case = bundle[5][0]

    with pytest.raises(Exception, match="canonical|source|replay"):
        _validate(summarized, context_case.context, context_case.port, bundle[4])


def test_mixed_nested_contract_refuses_replay() -> None:
    replay, context, custody, resolver = _case()

    class SourceSubclass(type(replay.report_source)):
        """Mixed-version shape substitution used only by this regression."""

    source = object.__new__(SourceSubclass)
    for field, value in replay.report_source.__dict__.items():
        object.__setattr__(source, field, value)
    mixed = object.__new__(type(replay))
    for field, value in replay.__dict__.items():
        object.__setattr__(mixed, field, source if field == "report_source" else value)

    with pytest.raises(Exception, match="exact|canonical|source|replay"):
        _validate(mixed, context, custody, resolver)


def test_replay_validator_refuses_v2_and_subclass_roots() -> None:
    from openultrasast.core.admission_report import AdmissionReplay

    replay, context, custody, resolver = _case()

    with pytest.raises(Exception, match="exact|V3|replay"):
        _validate(object.__new__(AdmissionReplay), context, custody, resolver)

    class ReplaySubclass(type(replay)):
        """Exact-root substitution used only by this regression."""

    substituted = object.__new__(ReplaySubclass)
    for field, value in replay.__dict__.items():
        object.__setattr__(substituted, field, value)
    with pytest.raises(Exception, match="exact|V3|replay"):
        _validate(substituted, context, custody, resolver)
