"""Admission funnel fields are derived from canonical evidence, never runner counts."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_core_admission_metrics import _derive, _release_for, _run, _setup

from openultrasast.core.admission_metrics import AdmissionMetricsError, derive_admission_case_result_digest
from openultrasast.core.coverage import CoverageFunnel, ReasonCount, RelationStatusCount
from openultrasast.core.semantics import RelationStatus


def _mutate(value: CoverageFunnel, field: str) -> CoverageFunnel:
    if field == "inputs_read":
        return replace(value, inputs_read=2)
    if field == "questions_formed":
        return replace(value, questions_formed=2)
    if field == "sites_considered":
        return replace(value, sites_considered=3)
    if field == "sites_recognized":
        return replace(value, sites_recognized=1)
    if field == "transitions_materialized":
        counts = tuple(RelationStatusCount(status, 2 if status is RelationStatus.COMPLETE else 0) for status in RelationStatus)
        return replace(value, transitions_materialized=2, relation_status_counts=counts)
    if field == "security_objects_constructed":
        return replace(value, security_objects_constructed=2)
    if field == "constraints_evaluated":
        return replace(value, constraints_evaluated=2)
    if field == "determinate_outcomes":
        return replace(value, determinate_outcomes=0)
    if field == "findings_emitted":
        return replace(value, findings_emitted=1)
    counts = tuple(RelationStatusCount(status, int(status is RelationStatus.INCOMPLETE)) for status in RelationStatus)
    return replace(value, relation_status_counts=counts, unresolved_by_reason=(ReasonCount("fabricated_incomplete_relation", 1),))


@pytest.mark.parametrize(
    "field",
    (
        "inputs_read",
        "questions_formed",
        "sites_considered",
        "sites_recognized",
        "transitions_materialized",
        "security_objects_constructed",
        "constraints_evaluated",
        "determinate_outcomes",
        "findings_emitted",
        "relation_accounting",
    ),
)
def test_every_case_funnel_field_is_rederived_from_canonical_evidence(field: str) -> None:
    run = _run(_setup())
    cases = run.setup.cases
    changed = replace(cases[1], coverage=_mutate(cases[1].coverage, field))
    changed = replace(changed, result_digest=derive_admission_case_result_digest(changed))
    changed_cases = (cases[0], changed, cases[2])

    with pytest.raises(AdmissionMetricsError, match="coverage aggregate"):
        _derive(run, cases=changed_cases, release=_release_for(run, changed_cases))
