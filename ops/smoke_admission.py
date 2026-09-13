"""Verify that captured real comparison evidence remains diagnostic by default."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from openultrasast.model.contracts import ChangeContext, QuestionOutcome, ScopeDecision
from openultrasast.model.ladder import Rung
from openultrasast.model.pipeline import ModelFinding
from openultrasast.model.scan import ModelScanResult
from openultrasast.push.contracts import ComparisonAnalysis, PushComparison
from openultrasast.push.policy import AdmissionCandidate, CapabilityKey, admission_push_result, admit_candidates, compare_evidence


def restore_scan(data: dict) -> ModelScanResult:
    """Restore only the recorded evidence consumed by the comparison policy."""
    return ModelScanResult(
        findings=tuple(ModelFinding(**{**finding, "rung": Rung(finding["rung"])}) for finding in data["findings"]),
        scope=ScopeDecision.from_payload(data["scope"]),
        question_outcomes=tuple(QuestionOutcome.from_payload(outcome) for outcome in data["question_outcomes"]),
        degradations=tuple(data["degradations"]),
    )


def main() -> None:
    artifact = Path("benchmarks/measurements/2026-09-13-delta-comparison-smoke.json")
    raw = artifact.read_bytes()
    assert raw, "comparison artifact is unreadable or empty"
    recorded = json.loads(raw)
    report = {
        "purpose": "Current policy applied to captured actual engine evidence; no new engine execution or evaluated capability",
        "input_bytes": len(raw),
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "cases": {},
    }
    for case, record in recorded["cases"].items():
        evidence = record["evidence"]
        head = restore_scan(evidence["head"])
        base = restore_scan(evidence["delta"]["base_scan"])
        context = ChangeContext.from_payload(evidence["context"])
        comparison = PushComparison.from_payload(evidence["comparison"])
        semantics = evidence["delta"]["semantics"]
        deltas = compare_evidence(head, base, context=context, head_semantics=semantics, base_semantics=semantics)
        assert deltas and all(delta.novelty == evidence["expected_novelty"] for delta in deltas)
        candidates = []
        for delta in deltas:
            operation = delta.head_operation
            assert operation is not None
            key = CapabilityKey(
                operation.question.language, "unspecified", "unspecified", delta.family, operation.mechanism, "unreviewed", semantics
            )
            candidates.append(AdmissionCandidate(delta, key, comparison))
        admission = admit_candidates(candidates)
        assert not admission.defects and len(admission.dispositions) == len(candidates)
        assert all(not disposition.admitted for disposition in admission.dispositions)
        assert "capability_unavailable" in admission.coverage_reasons
        assert head.scope is not None
        analysis = ComparisonAnalysis(comparison, (head.scope,), tuple(q.identity for q in head.question_outcomes), "complete_within_scope")
        result = admission_push_result(admission, (analysis,))
        assert result.finding_status == "none" and result.coverage_status == "incomplete" and result.push_disposition == "allow"
        report["cases"][case] = {"admission": admission.to_payload(), "result": result.to_payload()}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
