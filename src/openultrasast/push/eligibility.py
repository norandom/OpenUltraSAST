"""Versioned, locally shipped capability eligibility from frozen evaluation evidence.

This verifies integrity and recomputes gates; it is not a signature verifier. Registry
files are trusted release inputs, never repository configuration or model responses.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from openultrasast.cpg.artifact import digest_value
from openultrasast.push.policy import CapabilityAdmission
from openultrasast.push_scoring import _metrics, score

_BINDINGS = ("core", "engine", "engine_runtime", "facts", "queries", "policy", "semantics")
_WORKLOADS = ("identical-tip", "function-edit", "dependency-edit", "configuration-edit", "cold", "growth", "multi-ref")
_DEFAULT = Path(__file__).with_name("eligibility.json")


@dataclass(frozen=True)
class EligibilityLoad:
    capabilities: tuple[CapabilityAdmission, ...]
    status: str
    reasons: tuple[str, ...]


def fingerprint() -> str:
    try:
        return digest_value(json.loads(_DEFAULT.read_bytes()))
    except (OSError, ValueError):
        return "eligibility_unavailable"


def _runtime_pass(runtime: Mapping[str, Any], current: Mapping[str, str]) -> bool:
    if runtime.get("runtime_verdict") != "PASS" or any(runtime.get("provenance", {}).get(k) != current.get(k) for k in _BINDINGS):
        return False
    try:
        for name in _WORKLOADS:
            row = runtime["workloads"][name]
            values = [
                row[k]
                for k in (
                    "population",
                    "observed",
                    "missing",
                    "latency_samples",
                    "p95_seconds",
                    "completion",
                    "complete_coverage_cases",
                    "cancellation_overrun_seconds",
                    "timeouts",
                )
            ]
            if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
                return False
            population = row["population"]
            if (
                population < 1
                or row["observed"] != population
                or row["latency_samples"] != population
                or row["missing"]
                or row["timeouts"]
                or row["completion"] < 0.95
                or row["complete_coverage_cases"] / population < 0.95
                or row["cancellation_overrun_seconds"] > 2
                or (name != "cold" and row["p95_seconds"] > 30)
            ):
                return False
    except (KeyError, TypeError, ZeroDivisionError):
        return False
    return True


def create_decision(
    profile: dict[str, Any],
    validation: dict[str, Any],
    run: dict[str, Any],
    *,
    current: Mapping[str, str],
    runtime: dict[str, Any],
    declarations: Sequence[CapabilityAdmission],
) -> dict[str, Any]:
    scored = score(profile, validation, run)
    bindings = {k: current.get(k, "") for k in _BINDINGS}
    common = []
    if any(not bindings[k] or profile["config"].get(k) != bindings[k] for k in _BINDINGS):
        common.append("evaluation_provenance_mismatch")
    if not _runtime_pass(runtime, current):
        common.append("runtime_gate_or_provenance_failed")
    entries = []
    for declaration in declarations:
        key = declaration.key
        capability = f"{key.language}/{key.framework}/{key.family}"
        rows = [r for r in scored["cases"] if r["capability"] == capability and r["label"] != "regression"]
        metrics = _metrics(rows)
        reasons = list(common)
        labels = {r["label"] for r in rows}
        if not {"vulnerable", "fixed", "benign"} <= labels:
            reasons.append("paired_positive_fixed_benign_population_missing")
        if any(r["label"] in ("unsupported", "unreviewed") or r["input_status"] != "ready" or r.get("prerequisites") for r in rows):
            reasons.append("unresolved_input_or_unsupported_population")
        if not declaration.untouched_workload or any(
            r.get("role") not in ("independent", "reserved") or r.get("workload") != declaration.untouched_workload for r in rows
        ):
            reasons.append("independent_workload_missing")
        semantic = profile["config"].get("capability_semantics", {}).get(digest_value(key.to_payload()), {})
        if (
            semantic.get("key") != key.to_payload()
            or semantic.get("operation_symbols") != list(declaration.operation_symbols)
            or semantic.get("review_id") != declaration.evaluation_id
            or semantic.get("consequence_template") != declaration.consequence_template
            or semantic.get("repair_template") != declaration.repair_template
            or not declaration.operation_symbols
            or key.semantics != bindings["semantics"]
            or key.context in ("unreviewed", "unspecified", "")
            or not declaration.calibration_artifact
        ):
            reasons.append("semantic_scope_unreviewed_or_mismatched")
        for name, threshold in (("precision", 0.95), ("actionable_recall", 0.90), ("completion", 0.95), ("query_completion", 0.95)):
            if metrics[name]["value"] is None or metrics[name]["value"] < threshold:
                reasons.append(name + "_gate_failed")
        if metrics["fixed_side_silence"]["value"] != 1 or metrics["benign_interruption"]["value"] != 0:
            reasons.append("fixed_or_benign_gate_failed")
        warm = metrics["latency"]["warm_changed"]
        if not warm["samples"] or warm["p95"] > 30:
            reasons.append("independent_warm_latency_missing_or_failed")
        positive = metrics["recall"]["numerator"]
        reviewed = metrics["precision"]["numerator"]
        if positive < 1 or reviewed < 1:
            reasons.append("positive_controls_or_reviewed_alerts_missing")
        accepted = not reasons
        resolved = replace(
            declaration, verdict="PASS" if accepted else "NO-GO", enabled=accepted, positive_controls=positive, reviewed_alerts=reviewed
        )
        entries.append(dict(declaration=resolved.to_payload(), metrics=metrics, reasons=sorted(set(reasons))))
    result = dict(
        schema_version=1,
        bindings=bindings,
        verdict="PASS" if any(not e["reasons"] for e in entries) else "NO-GO",
        entries=entries,
        inputs=dict(profile=profile, validation=validation, run=run, runtime=runtime, declarations=[d.to_payload() for d in declarations]),
    )
    result["artifact_sha256"] = digest_value(result)
    return result


def load_registry(*, current: Mapping[str, str], path: Path | None = None) -> EligibilityLoad:
    try:
        with (path or _DEFAULT).open("rb") as stream:
            content = stream.read(2 * 1024**2 + 1)
        if len(content) > 2 * 1024**2:
            raise ValueError("registry_size_limit")
        data = json.loads(content)
        if data.get("schema_version") != 1 or data.get("bindings") != {k: current.get(k, "") for k in _BINDINGS}:
            return EligibilityLoad((), "stale", ("eligibility_provenance_mismatch",))
        inputs = data["inputs"]
        declarations = tuple(CapabilityAdmission.from_payload(d) for d in inputs["declarations"])
        recomputed = create_decision(
            inputs["profile"], inputs["validation"], inputs["run"], current=current, runtime=inputs["runtime"], declarations=declarations
        )
        if recomputed != data:
            raise ValueError("registry_evidence_mismatch")
        capabilities = tuple(CapabilityAdmission.from_payload(e["declaration"]) for e in data["entries"] if not e["reasons"])
        return EligibilityLoad(capabilities, data["verdict"], tuple(sorted({reason for e in data["entries"] for reason in e["reasons"]})))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return EligibilityLoad((), "unavailable", ("eligibility_invalid_or_unavailable",))
