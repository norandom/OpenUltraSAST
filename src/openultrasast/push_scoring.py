"""Versioned diagnostic scorer for recorded push experiments, independent of replay.

Answers and reviewed alerts are supplied by the experiment; rank is never an answer.
This instrument checks provenance and exact witness associations, not witness semantics.
Capability admission remains the later independent evaluation gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

_CONTEXT = ("ranking_mode", "engine", "facts", "queries", "policy", "scope", "hardware", "budget_seconds", "core")


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _unique(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    indexed = {row[key]: row for row in rows}
    if len(indexed) != len(rows):
        raise ValueError(f"duplicate {key}")
    return indexed


def freeze_profile(manifest: bytes, config: dict[str, Any]) -> dict[str, Any]:
    """Freeze BEFORE executing queries; changing any comparison identity needs a new profile."""
    data = json.loads(manifest)
    cases = data["cases"]
    if data.get("schema_version") != 1 or not cases:
        raise ValueError("unsupported or empty input manifest")
    _unique(cases, "id")
    for name in ("version", *_CONTEXT):
        if name not in config or config[name] in (None, ""):
            raise ValueError(f"profile requires {name}")
    if config["ranking_mode"] not in ("static", "evidence"):
        raise ValueError("unknown ranking mode")
    if not math.isfinite(config["budget_seconds"]) or config["budget_seconds"] <= 0:
        raise ValueError("budget must be finite and positive")
    for case in cases:
        if case["label"] not in ("unsupported", "unreviewed"):
            target = config.get("targets", {}).get(case["id"], {})
            if not target.get("path") or not target.get("family") or not target.get("function") or not target.get("lines"):
                raise ValueError(f"declare target before measuring {case['id']}")
            if any(type(line) is not int or line < 1 for line in target["lines"]):
                raise ValueError("target lines must be positive integers")
    profile: dict[str, Any] = dict(
        schema_version=1,
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        cases=cases,
        config=config,
        gates=dict(precision=0.95, recall=0.90, completion=0.95, warm_p95_seconds=30.0, fixed_false_alerts=0, benign_false_alerts=0),
    )
    # Own copies: mutating the caller's config cannot mutate a frozen profile.
    profile = json.loads(json.dumps(profile, allow_nan=False))
    profile["profile_sha256"] = _digest(profile)
    return profile


def _rate(numerator: int, denominator: int) -> dict[str, Any]:
    """Observed rate and Wilson 95% interval; no samples is undefined, never perfect."""
    result: dict[str, Any] = dict(numerator=numerator, denominator=denominator, value=None, wilson95=None)
    if denominator:
        p, z = numerator / denominator, 1.959963984540054
        center = (p + z * z / (2 * denominator)) / (1 + z * z / denominator)
        half = z * math.sqrt(p * (1 - p) / denominator + z * z / (4 * denominator**2)) / (1 + z * z / denominator)
        result.update(value=p, wilson95=[max(0.0, center - half), min(1.0, center + half)])
    return result


def _witness(query: dict[str, Any], target: dict[str, Any]) -> dict[str, Any] | None:
    finding = query.get("finding", {})
    sites = {f"{target['path']}:{line}" for line in target["lines"]}
    if (
        query.get("status") == "answered"
        and query.get("outcome") == "positive"
        and finding.get("site") in sites
        and finding.get("family") == target["family"]
        and finding.get("rung") in ("model_entailed", "execution_confirmed")
        and isinstance(finding.get("witness"), str)
        and finding["witness"].strip()
    ):
        return dict(question_id=query["id"], **finding)
    return None


def _case(
    case: dict[str, Any], record: dict[str, Any] | None, profile: dict[str, Any], snapshots: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    row = dict(case, outcome="unresolved", reached_transitively=False, witnesses=[], complete=False, recorded=record)
    if record is None:
        row["problem"] = "no recorded execution"
        return row
    if case["label"] in ("unsupported", "unreviewed"):
        row["problem"] = f"{case['label']} population; no detection claim"
        return row
    if any(
        snapshots.get(case[key], {}).get("status") != "ready" or snapshots.get(case[key], {}).get("bytes_read", 0) <= 0
        for key in ("base", "tip")
    ):
        row["problem"] = "input bytes not verified"
        return row
    selected, deferred = record["selected"], record["deferred"]
    if len(set(selected + deferred)) != len(selected + deferred):
        raise ValueError("duplicate or overlapping selected/deferred questions")
    queries = _unique(record["queries"], "id")
    if not set(queries).issubset(selected):
        row["problem"] = "query absent from selected scope"
        return row
    target = profile["config"]["targets"][case["id"]]
    witnesses = [w for q in queries.values() if (w := _witness(q, target)) is not None]
    complete = (
        bool(selected)
        and not deferred
        and set(queries) == set(selected)
        and all(q.get("status") == "answered" and q.get("outcome") in ("positive", "negative") for q in queries.values())
        and record.get("coverage") == "complete"
    )
    negative = any(
        q.get("status") == "answered"
        and q.get("outcome") == "negative"
        and q.get("target") == target
        and isinstance(q.get("witness"), str)
        and bool(q["witness"].strip())
        for q in queries.values()
    )
    target_region = {key: target[key] for key in ("path", "function")}
    transitive = any(
        q.get("flow")
        and len(q["flow"]) > 1
        and q["flow"][0] == q.get("origin")
        and q["flow"][-1] == target_region
        and q.get("origin") != target_region
        and _witness(q, target)
        for q in queries.values()
    )
    row.update(
        witnesses=witnesses,
        complete=complete and bool(witnesses or negative),
        outcome="positive" if witnesses else "negative" if complete and negative else "unresolved",
        reached_transitively=bool(transitive),
    )
    if row["outcome"] == "unresolved":
        row["problem"] = "target unmatched, unanswered, or lacks exact witnessed answer"
    return row


def _actionable(row: dict[str, Any], alert: dict[str, Any]) -> bool:
    return (
        alert.get("review") == "actionable_true"
        and bool(alert.get("review_evidence"))
        and any(alert.get("question_id") == w["question_id"] and alert.get("site") == w["site"] for w in row["witnesses"])
        and row["label"] == "vulnerable"
        and row["outcome"] == "positive"
        and (row["recorded"] or {}).get("delta") in ("new", "worsened")
    )


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    positive = [r for r in rows if r["label"] == "vulnerable"]
    fixed = [r for r in rows if r["label"] == "fixed"]
    benign = [r for r in rows if r["label"] == "benign"]
    supported = [r for r in rows if r["label"] not in ("unsupported", "unreviewed")]
    alerts = [(r, a) for r in rows for a in (r["recorded"] or {}).get("alerts", [])]
    # Unreviewed emitted alerts remain in the precision denominator. A high rung alone is not actionability.
    actionable = sum(_actionable(r, a) for r, a in alerts)
    result = dict(
        recall=_rate(
            sum(r["outcome"] == "positive" and (r["recorded"] or {}).get("delta") in ("new", "worsened") for r in positive), len(positive)
        ),
        precision=_rate(actionable, len(alerts)),
        fixed_side_silence=_rate(sum(r["outcome"] == "negative" and not r["recorded"].get("alerts") for r in fixed), len(fixed)),
        benign_interruption=_rate(sum(bool((r["recorded"] or {}).get("alerts")) for r in benign), len(benign)),
        completion=_rate(sum(r["complete"] for r in supported), len(supported)),
    )
    latency = {}
    for state in ("cold", "warm_changed", "identical_tip"):
        values = sorted(r["recorded"]["timings"]["total"] for r in rows if r["recorded"] and r["recorded"].get("cache_state") == state)
        latency[state] = dict(
            samples=len(values),
            p50=values[math.ceil(len(values) * 0.5) - 1] if values else None,
            p95=values[math.ceil(len(values) * 0.95) - 1] if values else None,
        )
    regression = [r for r in rows if r["label"] == "regression"]
    result["regression_detection"] = _rate(sum(r["outcome"] == "positive" for r in regression), len(regression))
    unknown_benign = sum(r["recorded"] is None for r in benign)
    result["benign_interruption"]["unobserved"] = unknown_benign
    if unknown_benign:
        result["benign_interruption"]["value"] = None
        result["benign_interruption"]["wilson95"] = None
    result["actionable_recall"] = _rate(
        sum(any(_actionable(r, a) for a in (r["recorded"] or {}).get("alerts", [])) for r in positive), len(positive)
    )
    declared_queries = sum(len(r["recorded"]["selected"]) + len(r["recorded"]["deferred"]) for r in supported if r["recorded"])
    answered_queries = sum(
        q.get("status") == "answered" and q.get("outcome") in ("positive", "negative") and q.get("id") in r["recorded"]["selected"]
        for r in supported
        if r["recorded"]
        for q in r["recorded"]["queries"]
    )
    result["query_completion"] = _rate(answered_queries, declared_queries)
    result["query_completion"]["unmeasured_cases"] = sum(r["recorded"] is None for r in supported)
    if result["query_completion"]["unmeasured_cases"]:
        result["query_completion"]["value"] = None
        result["query_completion"]["wilson95"] = None
    result["latency"] = latency
    result["unresolved"] = sum(r["outcome"] == "unresolved" for r in rows)
    result["timeouts"] = sum((r["recorded"] or {}).get("coverage") == "timeout" for r in rows)
    return result


def score(profile: dict[str, Any], validation: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    """Score a recorded experiment against its predeclared population, never a filtered result list."""
    identity = profile["profile_sha256"]
    if _digest({k: v for k, v in profile.items() if k != "profile_sha256"}) != identity:
        raise ValueError("mutated frozen profile")
    if run["profile_sha256"] != identity or validation["manifest_sha256"] != profile["manifest_sha256"]:
        raise ValueError("profile or manifest mismatch")
    for key in _CONTEXT:
        if run.get("context", {}).get(key) != profile["config"][key]:
            raise ValueError(f"actual run context mismatch: {key}")
    cases = _unique(profile["cases"], "id")
    validated = _unique(validation["cases"], "id")
    if set(cases) != set(validated) or any(
        any(validated[key].get(field) != case.get(field) for field in case) for key, case in cases.items()
    ):
        raise ValueError("validation population or labels differ from frozen manifest")
    records = _unique(run["records"], "case_id")
    if not set(records).issubset(cases):
        raise ValueError("undeclared result case")
    for record in records.values():
        for field in ("rank", "selected", "deferred", "queries", "alerts", "delta", "coverage"):
            if field not in record:
                raise ValueError(f"record requires observed {field}")
        if record["delta"] not in ("new", "worsened", "removed", "unchanged", "unknown"):
            raise ValueError("unknown delta disposition")
        if record["coverage"] not in ("complete", "incomplete", "timeout", "error"):
            raise ValueError("unknown coverage status")
        if record["ranking_mode"] != profile["config"]["ranking_mode"]:
            raise ValueError("actual ranking mode differs from frozen profile")
        times = record["timings"]
        if not {"total", "build", "query"}.issubset(times) or any(
            type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in times.values()
        ):
            raise ValueError("timings must contain finite nonnegative build, query and total elapsed seconds")
        if record.get("cache_state") not in ("cold", "warm_changed", "identical_tip"):
            raise ValueError("declare cold, warm_changed or identical_tip cache state")
    snapshots = _unique(validation["snapshots"], "id")
    rows = [_case(case, records.get(key), profile, snapshots) for key, case in cases.items()]
    for row in rows:
        row["input_status"] = validated[row["id"]]["status"]
        row["input_problem"] = validated[row["id"]].get("problem")
        if row["input_status"] == "invalid_input":
            row.update(outcome="unresolved", complete=False, witnesses=[], reached_transitively=False, problem="invalid validated input")
    return dict(
        schema_version=1,
        profile_sha256=identity,
        profile=profile,
        population=len(rows),
        recorded_cases=len(records),
        measurement_status="recorded" if records else "unmeasured",
        cases=rows,
        metrics=_metrics(rows),
        by_capability={cap: _metrics([r for r in rows if r["capability"] == cap]) for cap in sorted({r["capability"] for r in rows})},
        admission="experimental",
        gates_passed=False,
        note=(
            "Diagnostic instrument only. No admission without independent capability evaluation. "
            "Missing runs contribute only conservative full-population bounds, not observed detector performance. "
            "Witness association is checked; semantic/actionability review is supplied evidence, not inferred from rank."
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze")
    freeze.add_argument("manifest", type=Path)
    freeze.add_argument("config", type=Path)
    measure = sub.add_parser("score")
    measure.add_argument("profile", type=Path)
    measure.add_argument("validation", type=Path)
    measure.add_argument("run", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "freeze":
            result = freeze_profile(args.manifest.read_bytes(), json.loads(args.config.read_text()))
        else:
            result = score(json.loads(args.profile.read_text()), json.loads(args.validation.read_text()), json.loads(args.run.read_text()))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(json.dumps(dict(status="invalid_measurement", problem=str(exc))))
        return 2
    print(json.dumps(result, indent=2, allow_nan=False))
    return 1 if args.command == "score" and result["metrics"]["unresolved"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
