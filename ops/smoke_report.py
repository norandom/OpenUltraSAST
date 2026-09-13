"""Packaged comparison/admission/report integration over captured and synthetic evidence."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from dataclasses import asdict, replace
from pathlib import Path

from openultrasast.config import PushConfig
from openultrasast.model.contracts import ChangeContext, ExecutionBudget, FamilyCoverage, QuestionOutcome, RankedQuestion, ScopeDecision
from openultrasast.model.ladder import Rung
from openultrasast.model.partitions import PartitionCoverage
from openultrasast.model.pipeline import ModelFinding
from openultrasast.model.scan import ModelScanResult
from openultrasast.push.contracts import ComparisonAnalysis, PushComparison
from openultrasast.push.policy import (
    AdmissionCandidate,
    CapabilityKey,
    admission_push_result,
    admit_candidates,
    compare_evidence,
)
from openultrasast.push.report import PushReport, ScanRecord, deliver_report


def restore(data: dict) -> ModelScanResult:
    values = dict(data)
    values["findings"] = tuple(ModelFinding(**{**f, "rung": Rung(f["rung"])}) for f in data["findings"])
    values["scope"] = ScopeDecision.from_payload(data["scope"]) if data["scope"] else None
    values["question_outcomes"] = tuple(QuestionOutcome.from_payload(q) for q in data["question_outcomes"])
    values["change_context"] = ChangeContext.from_payload(data["change_context"]) if data["change_context"] else None
    values["family_coverage"] = tuple(FamilyCoverage.from_payload(c) for c in data["family_coverage"])
    values["partitions"] = tuple(
        PartitionCoverage(**{**p, **{k: tuple(p[k]) for k in ("paths", "boundaries", "excluded_paths", "unshipped_paths")}})
        for p in data["partitions"]
    )
    values["degradations"] = tuple(data["degradations"])
    values["tiers"] = tuple(tuple(t) for t in data["tiers"])
    values["tier_counts"] = {int(k): v for k, v in data["tier_counts"].items()}
    result = ModelScanResult(**values)
    assert json.loads(json.dumps(asdict(result))) == data, "record restoration lost evidence"
    return result


def main() -> None:
    measured = Path("benchmarks/measurements")
    raw = (measured / "2026-09-13-delta-comparison-smoke.json").read_bytes()
    controls = json.loads(raw)
    synthetic_bytes = (measured / "2026-09-13-admission-policy-smoke.json").read_bytes()
    assert raw and synthetic_bytes
    synthetic = json.loads(synthetic_bytes)["synthetic_controls"]["javascript"]
    policy = Path("src/openultrasast/push/policy.py").read_bytes()
    reporter = Path("src/openultrasast/push/report.py").read_bytes()
    provenance = {
        "repository": "captured immutable Git fixture comparisons",
        "engine": controls["runtime"]["image"],
        "facts": "covered by recorded comparison semantics",
        "queries": "covered by recorded comparison semantics",
        "policy": hashlib.sha256(policy + reporter).hexdigest(),
    }
    summary = {
        "purpose": "Packaged reporting over captured actual engine evidence and explicitly synthetic admission controls; no new Joern run",
        "input_bytes": len(raw) + len(synthetic_bytes),
        "comparison_artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "policy_sha256": hashlib.sha256(policy).hexdigest(),
        "report_sha256": hashlib.sha256(reporter).hexdigest(),
        "cases": {},
    }
    with tempfile.TemporaryDirectory(prefix="ousast-report-smoke-") as directory:
        root = Path(directory)

        def emit(name: str, report: PushReport, *, fail: bool = False) -> None:
            target = root / (name + ".json")
            if fail:
                target.mkdir()
            delivery = deliver_report(report, target, execution_budget=ExecutionBudget(time.monotonic() + 10, 1.0))
            assert delivery.result == report.result and delivery.exit_code == int(report.result.push_disposition == "block")
            assert delivery.text.count("Notice:") <= 1
            artifact = json.loads(target.read_text()) if delivery.artifact else None
            if fail:
                assert delivery.error and delivery.artifact is None and target.is_dir()
            else:
                assert delivery.error is None and artifact is not None
                assert artifact["result"] == report.result.to_payload()
                assert artifact["admission"] == report.admission.to_payload()
                assert artifact["scans"] == json.loads(json.dumps([asdict(s) for s in report.scans]))
            summary["cases"][name] = {
                "exit_code": delivery.exit_code,
                "text": delivery.text,
                "error": delivery.error,
                "reporting_seconds": delivery.reporting_seconds,
                "artifact": artifact,
            }

        for name, record in controls["cases"].items():
            evidence = record["evidence"]
            head = restore(evidence["head"])
            base = restore(evidence["delta"]["base_scan"])
            context = ChangeContext.from_payload(evidence["context"])
            comparison = PushComparison.from_payload(evidence["comparison"])
            semantics = evidence["delta"]["semantics"]
            deltas = compare_evidence(head, base, context=context, head_semantics=semantics, base_semantics=semantics)
            assert deltas and all(d.novelty == evidence["expected_novelty"] for d in deltas)
            candidates = []
            for delta in deltas:
                op = delta.head_operation
                assert op is not None
                key = CapabilityKey(op.question.language, "unspecified", "unspecified", delta.family, op.mechanism, "unreviewed", semantics)
                candidates.append(AdmissionCandidate(delta, key, comparison))
            admission = admit_candidates(candidates)
            assert not admission.defects and head.scope is not None
            analysis = ComparisonAnalysis(
                comparison, (head.scope,), tuple(q.identity for q in head.question_outcomes), "complete_within_scope"
            )
            result = admission_push_result(admission, (analysis,))
            assert result.coverage_status == "incomplete"
            report = PushReport(
                result,
                admission,
                (ScanRecord(comparison, "head", head), ScanRecord(comparison, "base", base)),
                {**provenance, "comparison_semantics": semantics},
                {"total_seconds": record["completion"]["elapsed_seconds"]},
            )
            emit(name, report)

        # These five normalized controls test display/decision separation only.
        from openultrasast.push.policy import CandidateDisposition

        disposition = CandidateDisposition.from_payload(synthetic["admission"]["dispositions"][0])
        cap = disposition.capability_evaluations[0]
        candidate = disposition.candidate
        candidates = []
        questions = []
        findings = []
        outcomes = []
        for i in range(5):
            old = candidate.delta.head_operation
            assert old is not None
            q = replace(old.question, path=f"handler{i}.src")
            op = replace(old, question=q, path=q.path)
            delta = replace(
                candidate.delta,
                defect_id=f"synthetic-defect-{i}",
                head_operation=op,
                site=f"{q.path}:{op.line}:handler",
                change_evidence=(f"head:{q.path}:2-2",),
            )
            candidates.append(replace(candidate, delta=delta))
            questions.append(q)
            findings.append(ModelFinding(delta.site, delta.family, Rung(delta.rung), delta.witness or "synthetic witness"))
            outcomes.append(QuestionOutcome(q, "completed", "synthetic-normalized-control", "[]"))
        scope = ScopeDecision("synthetic-ranker", "static", True, tuple(RankedQuestion(q, 1.0, ()) for q in questions), (), ())
        scan = ModelScanResult(findings=tuple(findings), scope=scope, question_outcomes=tuple(outcomes))
        base_scan = replace(scan, findings=())
        analysis = ComparisonAnalysis(candidate.comparison, (scope,), tuple(questions), "complete_within_scope")
        admission = admit_candidates(candidates, capabilities=(cap,))
        assert len(admission.defects) == 5
        result = admission_push_result(admission, (analysis,), config=PushConfig(mode="blocking"))
        report = PushReport(
            result,
            admission,
            (ScanRecord(candidate.comparison, "head", scan), ScanRecord(candidate.comparison, "base", base_scan)),
            {**provenance, "repository": "synthetic normalized policy controls", "engine": "synthetic; no engine execution"},
            {"total_seconds": 0.0},
        )
        emit("synthetic-display-cap", report)
        text = summary["cases"]["synthetic-display-cap"]["text"]
        assert text.count("- injection at ") == 3 and "2 more" in text
        emit("synthetic-write-failure", report, fail=True)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
