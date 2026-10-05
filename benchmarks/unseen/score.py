"""Push-level unseen evaluation, explicit coverage and paired adoption evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

from openultrasast.model.taxonomy import load_families
from openultrasast.push.report import CAPABILITY_VETOES

STATES = ("instrument_failure", "unanalysable", "quick_only", "engine_covered")


def coverage(record):
    instrument = record.get("instrument", {})
    push = record.get("push")
    if (
        not isinstance(push, dict)
        or not instrument.get("head_verified")
        or not instrument.get("base_verified")
        or instrument.get("suspect_fast")
        or instrument.get("failure")
        or instrument.get("hook_exit") not in (0, 1)
        or sum(instrument.get("changed_bytes", {}).values()) <= 0
    ):
        return "instrument_failure"
    if "language_not_covered" in json.dumps([push.get("skipped", []), push.get("admission", {}).get("coverage_reasons", [])]) and not any(
        tier.get("bytes_read", 0) for tier in push.get("quick_tier", [])
    ):
        return "unanalysable"
    if instrument.get("hook_bytes_read", 0) <= 0:
        return "instrument_failure"
    changed = set(instrument["changed_bytes"])
    if any(
        outcome.get("status") == "completed" and outcome.get("identity", {}).get("path") in changed
        for scan in push.get("scans", [])
        if scan.get("side") == "head"
        for outcome in scan.get("scan", {}).get("question_outcomes", [])
    ):
        return "engine_covered"
    return "quick_only"


def findings(record):
    push = record.get("push", {})
    admission = push.get("admission", {})
    for defect in admission.get("defects", []):
        for path, line in defect.get("locations", []):
            yield "alerts", {**defect, "path": path, "line": line}
    seen = set()
    for disposition in admission.get("dispositions", []):
        delta = disposition.get("candidate", {}).get("delta", {})
        operation = delta.get("head_operation")
        if (
            disposition.get("admitted")
            or delta.get("novelty") not in {"new", "worsened"}
            or not set(disposition.get("reasons", [])) <= CAPABILITY_VETOES
            or operation is None
            or delta.get("witness") is None
            or delta.get("defect_id") in seen
        ):
            continue
        seen.add(delta.get("defect_id"))
        yield "advisory", {**operation, "family": delta.get("family")}
    taxonomy = load_families()
    for tier in push.get("quick_tier", []):
        for finding in tier.get("findings", []):
            family = taxonomy.family_of_cwe(finding.get("cwe") or "")
            yield "quick", {**finding, "family": family.id if family else None}


def location_match(record, finding):
    for file in record.get("files", []):
        if finding.get("path") != file["path"]:
            continue
        line = finding.get("line", 0)
        if any(start - 10 <= line <= end + 10 for start, end in file.get("head_lines", [])):
            return True
        if record.get("family") != "config_secrets" and file["path"] == record.get("path", file["path"]):
            function = record.get("function")
            if function and function != "<global>" and finding.get("function") == function:
                return True
            span = record.get("function_lines") or file.get("function_lines")
            if span and span[0] <= line <= span[1]:
                return True
    return False


def catches(record):
    return sorted(
        {
            stream
            for stream, finding in findings(record)
            if finding.get("family") == record.get("family") and location_match(record, finding)
        }
    )


def false_alarm(record, *, alerts_only=False):
    return any(not alerts_only or stream == "alerts" for stream, _ in findings(record))


def wilson(successes, n):
    if n == 0:
        return [None, None]
    p, z = successes / n, 1.96
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [max(0, centre - half), min(1, centre + half)]


def required_n(p, width):
    for n in range(1, 1000000):
        low, high = wilson(p * n, n)
        if max(p - low, high - p) <= width:
            return n
    raise ValueError("requested precision exceeds sizing range")


def rate(values):
    n, k = len(values), sum(values)
    return {"n": n, "count": k, "rate": k / n if n else None, "wilson95": wilson(k, n)}


def cluster_interval(rows, *, seed=0, draws=2000):
    clusters = defaultdict(list)
    for repo, value in rows:
        clusters[repo].append(value)
    if not clusters:
        return [None, None]
    rng = random.Random(seed)
    groups = list(clusters.values())
    samples = []
    for _ in range(draws):
        values = [value for group in rng.choices(groups, k=len(groups)) for value in group]
        samples.append(sum(values) / len(values))
    samples.sort()
    return [samples[int(0.025 * (draws - 1))], samples[int(0.975 * (draws - 1))]]


def icc(rows):
    clusters = defaultdict(list)
    for repo, value in rows:
        clusters[repo].append(value)
    n, k = len(rows), len(clusters)
    if k < 2 or n <= k:
        return None
    mean = sum(v for _, v in rows) / n
    between = sum(len(v) * (sum(v) / len(v) - mean) ** 2 for v in clusters.values()) / (k - 1)
    within = sum(sum((x - sum(v) / len(v)) ** 2 for x in v) for v in clusters.values()) / (n - k)
    size = (n - sum(len(v) ** 2 for v in clusters.values()) / n) / (k - 1)
    denominator = between + (size - 1) * within
    return (between - within) / denominator if denominator else 0.0


def mcnemar(a, b):
    pairs = list(zip(a, b, strict=True))
    losses = sum(x and not y for x, y in pairs)
    gains = sum(y and not x for x, y in pairs)
    n = losses + gains
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(min(losses, gains) + 1)) / 2**n) if n else 1.0


def score(records, *, seed=0):
    counts = Counter(coverage(r) for r in records)
    if not records or counts["instrument_failure"] / len(records) > 0.05:
        raise ValueError("slice exceeds 5% instrument_failure (or is empty)")
    usable = [r for r in records if coverage(r) != "instrument_failure"]

    def metrics(rows):
        ordinary = [r for r in rows if r["kind"] == "ordinary"]
        vulnerable = [r for r in rows if r["kind"] != "ordinary"]
        clustered = [(r["repo"], int(false_alarm(r))) for r in ordinary]
        return {
            "catch": rate([bool(catches(r)) for r in vulnerable]),
            "false_alarm": {
                **rate([false_alarm(r) for r in ordinary]),
                "cluster95": cluster_interval(clustered, seed=seed),
                "icc": icc(clustered),
            },
            "alerts_only": rate([false_alarm(r, alerts_only=True) for r in ordinary]),
        }

    breakdown = {}
    for key in ("family", "method", "post_cutoff"):
        groups = defaultdict(list)
        for r in usable:
            groups[str(r.get(key, "unknown"))].append(r)
        breakdown[key] = {key: metrics(rows) for key, rows in sorted(groups.items())}
    breakdown["coverage"] = {state: metrics([r for r in usable if coverage(r) == state]) for state in STATES[1:]}
    breakdown["stream"] = {
        stream: rate([stream in catches(r) for r in usable if r["kind"] != "ordinary"]) for stream in ("alerts", "advisory", "quick")
    }
    return {
        **metrics(usable),
        "total": len(records),
        "deadlines": [
            {"lane": lane, "deadline_seconds": deadline, "deadline_scale": factor, "applied_deadline_scale": applied, "count": count}
            for (lane, deadline, factor, applied), count in sorted(
                Counter(
                    (r.get("lane", "unknown"), r.get("deadline_seconds"), r.get("deadline_scale"), r.get("applied_deadline_scale"))
                    for r in records
                ).items(),
                key=lambda pair: str(pair[0]),
            )
        ],
        "coverage": {state: counts[state] for state in STATES},
        "breakdowns": breakdown,
        "confirmed": metrics([r for r in usable if r.get("label_check", r.get("confirmed")) in ("confirmed", True)]),
    }


def agreement(cluster, native):
    """Missing, failed or wrong-lane records are unknown, never matching quiet pushes."""
    cc = {r["id"]: r for r in cluster}
    if len(cc) != len(cluster) or len({r["id"] for r in native}) != len(native):
        raise ValueError("duplicate agreement identities")
    pairs, unknown, disagreements = [], [], []
    for n in sorted(native, key=lambda r: r["id"]):
        c = cc.get(n["id"])
        if (
            c is None
            or c.get("lane") not in {"ax", "kind"}
            or n.get("lane") != "docker"
            or c.get("image") != n.get("image")
            or c.get("base_deadline_seconds") != n.get("base_deadline_seconds")
            or coverage(c) == "instrument_failure"
            or coverage(n) == "instrument_failure"
        ):
            unknown.append(n["id"])
            continue
        cluster_flag, native_flag = false_alarm(c), false_alarm(n)
        same = cluster_flag == native_flag
        pairs.append({"change_id": n["id"], "cluster_flagged": cluster_flag, "native_flagged": native_flag, "same": same})
        if not same:
            disagreements.append(n["id"])
    report = rate([p["same"] for p in pairs])
    eligible = bool(pairs) and not unknown and report["wilson95"][0] >= 0.95
    return {
        **report,
        "requested": len(native),
        "pairs": pairs,
        "unknown": unknown,
        "disagreements": disagreements,
        "baseline_eligible": eligible,
        "flagged": not eligible,
    }


def budgets(rows, *, thresholds=None, binary=False):
    ordinary = [r for r in rows if r["kind"] == "ordinary"]
    vulnerable = [r for r in rows if r["kind"] != "ordinary"]
    if binary:
        fa = rate([r["prediction"] for r in ordinary])
        return {
            "catch": rate([r["prediction"] for r in vulnerable]),
            "false_alarm": fa,
            "budgets_met": [f"{budget}%" for budget in (1, 5, 10) if fa["rate"] is not None and fa["rate"] <= budget / 100],
        }
    output = {}
    for budget in (1, 5, 10):
        key = f"{budget}%"
        if thresholds is not None and key not in thresholds:
            continue
        if not ordinary:
            output[key] = {"label": "not_run"}
            continue
        if thresholds is not None:
            threshold = thresholds[key]
        else:
            candidates = sorted({r["score"] for r in rows})
            candidates.append(math.nextafter(candidates[-1], math.inf))
            threshold = next(t for t in candidates if sum(r["score"] >= t for r in ordinary) / len(ordinary) <= budget / 100)
        output[key] = {
            "threshold": threshold,
            "label": "fixed" if thresholds is not None else "exploratory",
            "catch": rate([r["score"] >= threshold for r in vulnerable]),
            "false_alarm": rate([r["score"] >= threshold for r in ordinary]),
        }
    return output


def gate(a, b, *, slice_id=None, informed=False, binary=True, threshold=None, threshold_fixed=False, seed=0):
    not_run = {"gate": "not_run"}
    if not slice_id or informed or not a or not b or (not binary and (not threshold_fixed or threshold is None)):
        return not_run
    try:
        score(a, seed=seed)
        score(b, seed=seed)
    except ValueError:
        return not_run
    aa, bb = {r["id"]: r for r in a}, {r["id"]: r for r in b}
    if len(aa) != len(a) or len(bb) != len(b) or aa.keys() != bb.keys():
        return not_run
    pairs = [
        (aa[key], bb[key]) for key in sorted(aa) if coverage(aa[key]) != "instrument_failure" and coverage(bb[key]) != "instrument_failure"
    ]
    if any(x["kind"] != y["kind"] or x["repo"] != y["repo"] for x, y in pairs):
        return not_run
    vulnerable = [(x, y) for x, y in pairs if x["kind"] != "ordinary"]
    ordinary = [(x, y) for x, y in pairs if x["kind"] == "ordinary"]
    if not vulnerable or not ordinary:
        return not_run
    ca = [bool(catches(x)) for x, _ in vulnerable]
    cb = [bool(catches(y)) if binary else y["score"] >= threshold for _, y in vulnerable]
    fa = [false_alarm(x) for x, _ in ordinary]
    fb = [false_alarm(y) if binary else y["score"] >= threshold for _, y in ordinary]
    catch_p, fa_p = mcnemar(ca, cb), mcnemar(fa, fb)
    regression = (sum(cb) < sum(ca) and catch_p < 0.05) or (binary and sum(fb) > sum(fa) and fa_p < 0.05)
    return {
        "gate": "regression" if regression else "pass",
        "slice": slice_id,
        "catch": {"difference": sum(cb) / len(cb) - sum(ca) / len(ca), "mcnemar_p": catch_p},
        "false_alarm": {
            "difference": sum(fb) / len(fb) - sum(fa) / len(fa),
            "mcnemar_p": fa_p,
            "cluster95": cluster_interval([(x["repo"], int(v) - int(u)) for (x, _), u, v in zip(ordinary, fa, fb, strict=True)], seed=seed),
        },
    }


def load_records(path):
    if path.is_file():
        return json.loads(path.read_text())
    rows = []
    for entry in json.loads((path / "inputs.json").read_text()):
        result = path / (hashlib.sha256(entry["item_id"].encode()).hexdigest() + ".json")
        record = json.loads(result.read_text()) if result.exists() else {}
        if record.get("input_digest") != entry["input_digest"]:
            record = {}
        rows.append({**entry["change"], **record, "id": entry["change"]["id"]})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path, help="JSON array of joined change/instrument/push records")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--against", type=Path, help="production-arm records for a paired adoption gate")
    parser.add_argument("--native", type=Path, help="native sample root; auto-detected under replay root")
    parser.add_argument("--slice-id")
    parser.add_argument("--informed", action="store_true")
    args = parser.parse_args()
    current = load_records(args.records)
    result = score(current)
    native = args.native or (args.records / "native" if args.records.is_dir() and (args.records / "native").exists() else None)
    if native:
        result["native_agreement"] = agreement(current, load_records(native))
        result["baseline_eligible"] = result["native_agreement"]["baseline_eligible"]
        result["flagged"] = result["native_agreement"]["flagged"]
    result["unseen"] = gate(load_records(args.against) if args.against else [], current, slice_id=args.slice_id, informed=args.informed)
    if native and result["flagged"]:
        result["unseen"] = {"gate": "not_run", "reason": "native_agreement"}
    args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
