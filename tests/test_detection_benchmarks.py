"""Detection-quality gate for the in-scope languages.

Runs quick-mode scans against the C/C++, Python, JavaScript, and Java benchmark
corpora and asserts the project goal: at least 90% recall of known vulnerabilities
and under a 10% false-positive rate per language. The corpus map and aggregation
live in ``openultrasast.gate`` (the same gate CI runs as a first-class step).
"""

import pytest

from openultrasast.gate import (
    FALSE_POSITIVE_CEILING,
    LANGUAGE_MANIFESTS,
    RECALL_FLOOR,
    detection_gate,
    language_metrics,
)


@pytest.mark.parametrize("language", sorted(LANGUAGE_MANIFESTS))
def test_language_meets_recall_and_false_positive_goal(language: str) -> None:
    metrics = language_metrics(LANGUAGE_MANIFESTS[language])

    assert metrics.recall >= RECALL_FLOOR, (
        f"{language} recall {metrics.recall:.2%} below {RECALL_FLOOR:.0%} ({metrics.matched}/{metrics.expected})"
    )
    assert metrics.false_positive_rate < FALSE_POSITIVE_CEILING, (
        f"{language} false-positive rate {metrics.false_positive_rate:.2%} at or above "
        f"{FALSE_POSITIVE_CEILING:.0%} ({metrics.false_positives}/{metrics.actual})"
    )


def test_overall_detection_goal_is_met() -> None:
    verdict = detection_gate({language: language_metrics(names) for language, names in LANGUAGE_MANIFESTS.items()})
    assert verdict.passed, verdict.reasons
