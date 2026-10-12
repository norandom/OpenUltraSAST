"""Present valid-benchmark metrics on top of the shipped unseen scorer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.unseen import score


def demonstrated(proof: dict) -> bool:
    """Read search.verify.VerificationRecord, with affected then safe sides."""
    verification = proof.get("verification", proof)
    sides = verification.get("sides", [])
    if verification.get("outcome") != "demonstrated" or len(sides) != 2:
        return False
    if any(side.get("outcome") != "observed" or len(side.get("runs", [])) != 3 for side in sides):
        return False
    return all(run.get("observed") is True for run in sides[0]["runs"]) and all(run.get("observed") is False for run in sides[1]["runs"])


def scoring_records(records: list[dict]) -> list[dict]:
    """Project a multi-function fix onto a caught target while keeping one push."""
    projected = []
    for record in records:
        targets = record.get("targets", [])
        if not targets:
            projected.append(record)
            continue
        views = [{**record, **target, "files": [{"path": target["path"], "head_lines": [target["function_lines"]]}]} for target in targets]
        projected.append(next((view for view in views if score.catches(view)), views[0]))
    return projected


def summarize(records: list[dict], *, scored: dict | None = None, proofs: list[dict] = (), seed: int = 0) -> dict:
    projected = scoring_records(records)
    # Legacy score output uses only the primary target. Re-score grouped fixes
    # through the same scorer so a catch at any verified site counts once.
    if scored is None or any(row.get("targets") for row in records):
        scored = score.score(projected, seed=seed)
    if scored.get("total") != len(records):
        raise ValueError("scored output and records have different counts")
    if len({row["id"] for row in records}) != len(records):
        raise ValueError("duplicate replay id")
    usable = [row for row in projected if score.coverage(row) != "instrument_failure"]
    positives = [row for row in usable if row["kind"] == "vulnerability"]
    flagged = [row for row in usable if score.false_alarm(row)]
    precision = score.rate([row["kind"] == "vulnerability" and bool(score.catches(row)) for row in flagged])
    recall = {
        **scored["catch"],
        "cluster95": score.cluster_interval([(row["repo"], int(bool(score.catches(row)))) for row in positives], seed=seed),
    }
    false_alarms = {**scored["false_alarm"]}
    false_alarms["rate"] = None if false_alarms["rate"] is None else false_alarms["rate"] * 100
    for key in ("wilson95", "cluster95"):
        false_alarms[key] = [None if value is None else value * 100 for value in false_alarms[key]]
    joined = {}
    for proof in proofs:
        key = proof.get("case_id") or proof["id"]
        if key in joined:
            raise ValueError("duplicate proof case id")
        joined[key] = proof
    flagged_positives = [row for row in flagged if row["kind"] == "vulnerability"]
    case_ids = [case_id for row in flagged_positives for case_id in (row.get("case_ids") or [row.get("case_id") or row["id"]])]
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("duplicate flagged case id")
    missing = sorted(key for key in case_ids if key not in joined)
    exploit = {
        **score.rate([demonstrated(joined[key]) for key in case_ids if key in joined]),
        "flagged_positives": len(case_ids),
        "flagged_positive_pushes": len(flagged_positives),
        "not_yet_proved": missing,
        "status": "not yet proved" if missing else "measured",
    }
    result = dict(recall=recall, precision=precision, false_alarms_per_100_pushes=false_alarms, exploit_verified=exploit)
    result["headline"] = headline(result)
    return result


def headline(result: dict) -> str:
    def number(value, scale=1):
        return "not measured" if value is None else f"{value * scale:.1f}"

    recall, precision = result["recall"], result["precision"]
    low, high = recall["wilson95"]
    exploit = result["exploit_verified"]
    pending = f" ({len(exploit['not_yet_proved'])} not yet proved)" if exploit["not_yet_proved"] else ""
    return (
        f"On unseen app repos: recall {number(recall['rate'], 100)}% "
        f"(Wilson {number(low, 100)}-{number(high, 100)}), "
        f"false alarms {number(result['false_alarms_per_100_pushes']['rate'])} per 100 pushes, "
        f"precision {number(precision['rate'], 100)}%; exploit-verified "
        f"{exploit['count']} of {exploit['flagged_positives']}{pending}."
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path, help="joined replay records or replay result directory")
    parser.add_argument("--scored", type=Path, help="score.py output for these records")
    parser.add_argument("--proofs", type=Path, help="JSON array of case_id plus search verification records")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    result = summarize(
        score.load_records(args.records),
        scored=json.loads(args.scored.read_text()) if args.scored else None,
        proofs=json.loads(args.proofs.read_text()) if args.proofs else [],
    )
    args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(result["headline"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
