"""Gate 2: a zero-shot judge pass over the prover's findings.

The prover flags an entry when it cannot show a guard dominating a protected
operation. Some flagged entries are meant to be public -- a health endpoint, a
login form, a public API -- and the trace cannot tell. The judge is asked
exactly that question, zero-shot, and this module measures how often the
answer is right against the pool's labels.

Pool measures, never trains: no example in the prompt, no threshold tuned on
these answers. Every judgment is written to disk before anything is summed,
and the summary refuses to report from an empty or mostly-failed instrument.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

JUDGE_QUESTION = (
    "A static analyzer flagged this code path as a possible access-control "
    "vulnerability: an attacker-reachable entry point reaches a protected "
    "operation without a guard that dominates it.\n\n"
    "The analyzer cannot decide one thing: whether the entry point is MEANT TO "
    "BE PUBLIC -- intentionally callable by anyone, with no authorization "
    "expected -- in which case the missing guard is by design and the flag is a "
    "false alarm.\n\n"
    "You are given the repository name, the analyzer's finding, and the "
    "ordered trace it found (entry, call hops, operation, guards seen, missing "
    "obligations). Judge only from what is shown.\n\n"
    "Answer with strict JSON, nothing else:\n"
    '{"public": true|false, "confidence": "high"|"medium"|"low", "reason": "<one sentence>"}\n\n'
    '"public": true means the entry is meant to be callable by anyone and the '
    "flag is a false alarm. public false means the entry should be protected "
    "and the flag stands."
)


def _finding_key(record_id: str, finding_id: str) -> str:
    return hashlib.sha256(f"{record_id}\n{finding_id}".encode()).hexdigest()


def _judge_input(repo: str, finding: dict) -> str:
    payload = {
        "repository": repo,
        "entry": finding.get("entry", {}),
        "trace": finding.get("trace") or {},
        "evidence": finding.get("evidence", []),
        "operation": finding.get("operation", {}),
        "missing": finding.get("missing"),
    }
    return JUDGE_QUESTION + "\n\n" + json.dumps(payload, indent=2, default=str)


def _iter_findings(prover_out: Path):
    """Every finding of every completed prover record, with its push context."""
    for path in sorted(prover_out.glob("[0-9a-f]*.json")):
        record = json.loads(path.read_text())
        if not record.get("done"):
            continue
        for finding in record.get("findings") or []:
            yield record, finding


def _load_done(out: Path) -> dict:
    done = {}
    judged = out / "judgments.jsonl"
    if judged.is_file():
        for line in judged.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                done[row["key"]] = row
    return done


def run(args) -> int:
    import dspy

    from openultrasast.hunt.program import build_lm

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    lm = build_lm(cache_dir=out / "dspy-cache")
    dspy.configure(lm=lm, adapter=dspy.ChatAdapter())

    class Judge(dspy.Signature):
        """Answer the question with strict JSON only."""

        case: str = dspy.InputField()
        answer: str = dspy.OutputField()

    judge = dspy.Predict(Judge)
    done = _load_done(out)
    judgments_path = out / "judgments.jsonl"

    todo = 0
    failures = []
    started = time.monotonic()
    for record, finding in _iter_findings(Path(args.prover_out)):
        key = _finding_key(record["id"], finding.get("id") or "")
        if key in done:
            continue
        todo += 1
        payload = {
            "key": key,
            "record_id": record["id"],
            "repo": record["repo"],
            "kind": record.get("kind"),
            "finding_id": finding.get("id"),
            "path": finding.get("path"),
            "line": finding.get("line"),
            "model": lm.model,
        }
        try:
            result = judge(case=_judge_input(record["repo"], finding))
            text = (result.answer or "").strip()
            # Tolerate a fenced JSON block, then parse strictly.
            body = text.strip("`")
            if body.lower().startswith("json"):
                body = body[4:]
            parsed = json.loads(body[body.index("{") : body.rindex("}") + 1])
            if not isinstance(parsed.get("public"), bool):
                raise ValueError("public is not a boolean")
            payload["public"] = parsed["public"]
            payload["confidence"] = parsed.get("confidence")
            payload["reason"] = parsed.get("reason")
            payload["status"] = "ok"
        except Exception as error:  # noqa: BLE001  (recorded, never swallowed silently)
            payload["status"] = "judge_error"
            payload["error_type"] = type(error).__name__
            payload["error"] = str(error)[:500]
            failures.append(payload)
        with judgments_path.open("a") as handle:
            handle.write(json.dumps(payload, default=str) + "\n")
        if not todo % 25:
            print(f"{todo} judged, {len(failures)} failures", flush=True)

    seconds = time.monotonic() - started
    meta = {
        "model": lm.model,
        "temperature": 0.0,
        "dspy_version": dspy.__version__,
        "judged": todo,
        "failures": len(failures),
        "seconds": round(seconds, 1),
        "note": "zero-shot: no examples, no thresholds; question fixed before any answer was seen",
    }
    (out / "run.json").write_text(json.dumps(meta, indent=2, default=str) + "\n")
    print(json.dumps(meta))
    return 2 if failures and todo else 0


def summarize(args) -> int:
    out = Path(args.out)
    done = _load_done(out)
    rows = list(done.values())
    if not rows:
        raise SystemExit("no judgments: refuse to summarize an empty instrument")

    failures = [r for r in rows if r.get("status") != "ok"]
    if len(failures) > 0.1 * len(rows):
        raise SystemExit(f"refuse to summarize: {len(failures)}/{len(rows)} judgments failed")

    # Push-level rollup: a flagged push is dropped only when every one of its
    # findings was judged public.
    pushes = {}
    for row in rows:
        slot = pushes.setdefault(row["record_id"], {"repo": row["repo"], "kind": row["kind"], "kept": 0, "dropped": 0})
        if row["public"]:
            slot["dropped"] += 1
        else:
            slot["kept"] += 1

    def rate(n, d):
        return round(n / d, 4) if d else None

    vuln = [p for p in pushes.values() if p["kind"] == "vulnerability"]
    ordinary = [p for p in pushes.values() if p["kind"] == "ordinary"]
    tp_kept = sum(1 for p in vuln if p["kept"])
    fa_total, fa_dropped = len(ordinary), sum(1 for p in ordinary if not p["kept"])

    summary = {
        "model": rows[0].get("model"),
        "judgments": len(rows),
        "failed": len(failures),
        "pushes_flagged_by_prover": len(pushes),
        "true_pushes_kept": f"{tp_kept}/{len(vuln)}",
        "false_pushes_dropped": f"{fa_dropped}/{fa_total}",
        "recall_after_judge": rate(tp_kept, 23),
        "fa_per_100_after_judge": round((fa_total - fa_dropped) / 460 * 100, 1),
        "finding_verdicts": {
            "on_vulnerability_pushes": {
                "protected": sum(1 for r in rows if r["kind"] == "vulnerability" and not r["public"]),
                "public": sum(1 for r in rows if r["kind"] == "vulnerability" and r["public"]),
            },
            "on_ordinary_pushes": {
                "protected": sum(1 for r in rows if r["kind"] == "ordinary" and not r["public"]),
                "public": sum(1 for r in rows if r["kind"] == "ordinary" and r["public"]),
            },
        },
        "headline": (
            f"Judge over prover findings: keeps {tp_kept}/{len(vuln)} true flags, "
            f"drops {fa_dropped}/{fa_total} false flags "
            f"(recall {rate(tp_kept, 23)*100:.1f}%, FA {(fa_total - fa_dropped) / 460 * 100:.1f}/100)"
        ),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str) + "\n")
    print(json.dumps(summary, indent=2, default=str))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="judge every finding in a prover out-dir")
    p_run.add_argument("prover_out", type=Path)
    p_run.add_argument("--out", type=Path, required=True)
    p_run.set_defaults(fn=run)

    p_sum = sub.add_parser("summarize", help="roll judgments up to push-level metrics")
    p_sum.add_argument("--out", type=Path, required=True)
    p_sum.set_defaults(fn=summarize)

    args = parser.parse_args()
    raise SystemExit(args.fn(args))


if __name__ == "__main__":
    main()
