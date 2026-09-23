"""M3: replay a declared vulnerable/fixed/benign family in any supported language.

The NodeGoat instrument hard-codes its target and its three comparisons, which was right for M1
and is wrong for a transfer claim: a harness that only knows one language cannot say whether the
design transfers. This one takes the case family as an argument and reads its target, pins and
expectations from the committed inputs, so PHP and Python are asked exactly the way Node was.

What it records per revision is the same: the raw findings at the declared target, whether the
target question completed, the production comparison verdict, the recorded veto list, and the
census and source receipts. Expectations are written before the first scan.

Development evidence under a named budget. It is not independent qualification, it enables no
capability, and it makes no latency claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from measure import git, pin_snapshot  # noqa: E402

from openultrasast.model.scan import ScanBudget  # noqa: E402
from openultrasast.push.policy import CapabilityAdmission, CapabilityKey  # noqa: E402
from openultrasast.push.runner import _provenance  # noqa: E402
from openultrasast.push.vetoes import FLAG, LABEL  # noqa: E402
from openultrasast.push_inputs import validate_manifest  # noqa: E402
from openultrasast.repos import checkout_path, load_repo_recipe  # noqa: E402

# What each declared comparison is expected to show, stated before anything runs. `introduce`
# reintroduces the reviewed operation, `repair` removes it, `benign` changes something else.
EXPECTATIONS = {
    "introduce": "raw finding at the declared target lines; recorded novelty new",
    "repair": "fixed twin analyzed and quiet at the target; base-only findings retained",
    "benign": "backlog unchanged at the target; never new or worsened",
    # A regression snapshot has the same revision on both sides, so there is no change and no
    # novelty to claim. What it can show is whether the declared target is still detected and
    # whether its question completes. Anything reported as new here would be a defect in the
    # comparison, not a finding, so the verdict checks for exactly that.
    "regression": "declared target still detected and its question answered; never new, because nothing changed",
}


# The manifest labels a case by what it IS (vulnerable, fixed, benign, regression); the case id
# says what the comparison DOES (introduce, repair, benign). Selecting on one and keying
# expectations by the other silently ran a single case and called the rest missing.
ROLES = {"vulnerable": "introduce", "fixed": "repair", "benign": "benign", "regression": "regression"}


def role_of(case: dict[str, Any]) -> str | None:
    return ROLES.get(str(case.get("label", "")))


def write(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, allow_nan=False, default=str) + "\n")


def declaration_for(semantics: str, language: str, family: str, symbols: tuple[str, ...]) -> list[dict[str, Any]]:
    """An unreviewed declaration so the evaluation explanation renders. Never enabled, never PASS."""
    key = CapabilityKey(language, "unspecified", "unspecified", family, "taint", "unreviewed", semantics)
    declaration = CapabilityAdmission(
        key,
        "unreviewed-m3-transfer-v1",
        "experimental://m3-transfer",
        "experimental",
        "A request value reaches {operation}, which interpolates it into a statement the runtime executes ({context} capability).",
        "Bind the value at {operation} through the platform's parameterised form instead of interpolating it ({context} capability).",
        operation_symbols=symbols,
    )
    assert not declaration.enabled and declaration.verdict != "PASS", "the transfer declaration must stay unqualified"
    return [declaration.to_payload()]


def summarize(case: dict[str, Any], target: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    experimental = artifact.get("experimental") or {}
    head = [record["scan"] for record in artifact["scans"] if record["side"] == "head"]
    base = [record["scan"] for record in artifact["scans"] if record["side"] == "base"]
    at_target = [
        finding
        for scan in head
        for finding in scan["findings"]
        if finding["family"] == target["family"] and finding["site"].startswith(target["path"] + ":")
    ]
    questions = [
        outcome
        for scan in head
        for outcome in scan["question_outcomes"]
        if outcome["identity"]["path"] == target["path"] and outcome["identity"]["family"] == target["family"]
    ]
    answered = bool(questions) and all(q["raw_rows_json"] is not None for q in questions)
    findings = experimental.get("findings") if isinstance(experimental.get("findings"), list) else []
    recorded = [f for f in findings if f["family"] == target["family"] and f["site"].startswith(target["path"] + ":")]
    return {
        "expected": EXPECTATIONS[role_of(case) or "introduce"],
        "identical_revisions": case["base"] == case["tip"],
        "declared_target": target,
        "findings_at_target": len(at_target),
        "finding_sites": [f["site"] for f in at_target][:8],
        "target_lines_hit": sorted({int(f["site"].split(":")[1]) for f in at_target if f["site"].split(":")[1].isdigit()}),
        "target_questions": [{"function": q["identity"]["function"], "status": q["status"], "reason": q["reason"]} for q in questions],
        "target_questions_answered": answered,
        "questions_completed": sum(1 for s in head for q in s["question_outcomes"] if q["status"] == "completed"),
        "questions_total": sum(len(s["question_outcomes"]) for s in head),
        "base_questions_completed": sum(1 for s in base for q in s["question_outcomes"] if q["status"] == "completed"),
        "census": [{"language": p.get("language"), "files": len(p.get("paths", ()))} for s in head for p in s.get("partitions", ())],
        "production_result": [artifact["result"]["finding_status"], artifact["result"]["coverage_status"]],
        "recorded_status": experimental.get("status"),
        "recorded_at_target": [
            {
                "site": f["site"],
                "production": [f["production_novelty"], f["production_reason"]],
                "recorded": [f["recorded_novelty"], f["recorded_reason"]],
                "admission": f["production_admission"],
                "unlifted_vetoes": [[v["stage"], v["veto"]] for v in f["vetoes"] if not v["lifted"]],
            }
            for f in recorded
        ],
        "evaluation": experimental.get("evaluation", []),
        "base_only_findings": len(experimental.get("base_only_findings", []) or []),
        "coverage_reasons": artifact["admission"]["coverage_reasons"][:12],
        "admitted_defects": len(artifact["admission"]["defects"]),
        "timings": {k: v for k, v in artifact["timings"].items() if k.endswith("_seconds")},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--family", required=True, help="case id prefix, for example pmpro or nodegoat")
    parser.add_argument("--language", required=True)
    parser.add_argument("--symbols", default="", help="comma-separated operation symbols for the unreviewed declaration")
    parser.add_argument("--deadline", type=float, default=900.0)
    # The population a bounded run examines. 500 is the committed default and the shape every earlier
    # measurement used; a smaller budget is how a repository whose full question set cannot fit any ceiling
    # gets asked at all. It bounds the RUN, never the repository: the artifact's own census reports what was
    # left unexamined, and a bounded population establishes transfer rather than coverage.
    parser.add_argument("--max-regions", type=int, default=500)
    parser.add_argument("--only", default="", help="comma-separated case ids to run; the rest are recorded as skipped")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()

    manifest = json.loads(args.manifest.read_bytes())
    targets = json.loads((args.manifest.parent / "diagnostic-config-v1.json").read_text())["targets"]
    validation = validate_manifest(args.manifest, cache_root=args.cache, fetch=False)
    write(out / "input-validation.json", validation)
    ready = {s["id"] for s in validation["snapshots"] if s["status"] == "ready"}
    prefix = args.family if args.family.endswith("-") else args.family + "-"
    cases = [c for c in manifest["cases"] if c["id"].startswith(prefix) and role_of(c) is not None]
    if not cases:
        raise SystemExit(f"no vulnerable/fixed/benign cases for {args.family}")
    snapshots = {s["id"]: s for s in manifest["snapshots"]}
    missing = [c["id"] for c in cases if c["base"] not in ready or c["tip"] not in ready]
    if missing:
        raise SystemExit(f"inputs not ready: {missing}")

    recipe = load_repo_recipe(args.manifest.parent / snapshots[cases[0]["base"]]["recipe"])
    bare = out / "objects.git"
    bare.mkdir()
    git(bare, "init", "--bare")
    alternates = set()
    pins: dict[str, str] = {}
    for case in cases:
        for sid in (case["base"], case["tip"]):
            if sid in pins:
                continue
            snapshot = snapshots[sid]
            source = checkout_path(load_repo_recipe(args.manifest.parent / snapshot["recipe"]), args.cache)
            objects = git(source, "rev-parse", "--path-format=absolute", "--git-path", "objects").decode().strip()
            alternates.add(objects)
            (bare / "objects/info/alternates").write_text("\n".join(sorted(alternates)) + "\n")
            pins[sid] = pin_snapshot(bare, snapshot.get("commit", recipe.commit), snapshot)

    settings = ScanBudget(max_model_calls=0, max_regions=args.max_regions, order_by_evidence=True)
    installed = _provenance(bare, settings)
    family = next((targets[c["id"]]["family"] for c in cases if c["id"] in targets), "injection")
    symbols = tuple(s.strip() for s in args.symbols.split(",") if s.strip())
    declarations = out / "experimental-declarations.json"
    write(declarations, declaration_for(installed["semantics"], args.language, family, symbols))

    record: dict[str, Any] = {
        "schema_version": 1,
        "label": LABEL,
        "milestone": "M3",
        "family": args.family,
        "language": args.language,
        "flag": FLAG,
        "development_budget_seconds": args.deadline,
        "max_regions": args.max_regions,
        "budget_note": "Explicitly named development budget; this run cannot satisfy or measure the hook latency gate.",
        "expectations": EXPECTATIONS,
        "pins": pins,
        "targets": {c["id"]: targets.get(c["id"]) for c in cases},
        "source_receipts": {
            sid: {
                "path": targets[cases[0]["id"]]["path"],
                "bytes": len(git(bare, "cat-file", "blob", f"{oid}:{targets[cases[0]['id']]['path']}")),
                "sha256": hashlib.sha256(git(bare, "cat-file", "blob", f"{oid}:{targets[cases[0]['id']]['path']}")).hexdigest(),
            }
            for sid, oid in pins.items()
        },
        "provenance": installed,
        "hardware": {"platform": platform.platform(), "cpu_affinity": sorted(os.sched_getaffinity(0))},
        "instrument_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "cases": [],
    }
    write(out / "transfer-record.json", record)

    only = {c.strip() for c in args.only.split(",") if c.strip()}
    for case in cases:
        if only and case["id"] not in only:
            record["cases"].append({"case_id": case["id"], "status": "skipped_by_only"})
            continue
        target = targets.get(case["id"])
        if target is None:
            record["cases"].append({"case_id": case["id"], "status": "no_declared_target"})
            write(out / "transfer-record.json", record)
            continue
        artifact = out / (case["id"] + ".json")
        command = [
            sys.executable,
            "-m",
            "openultrasast.cli",
            "pre-push",
            str(bare),
            "--base",
            pins[case["base"]],
            "--head",
            pins[case["tip"]],
            "--artifact",
            str(artifact),
            "--deadline",
            str(args.deadline),
            "--cancellation-allowance",
            "2",
            "--max-regions",
            str(args.max_regions),
            "--cache-dir",
            str(out / "cache"),
            FLAG,
            "--experimental-declarations",
            str(declarations),
        ]
        # Streamed to files as it runs, with the engine's own timing logs on. Captured in memory, a case that
        # overran its deadline took its output with it: the 2026-09-23 replay crashed on case 1 and left no
        # record of where 95 minutes went. An overrun is recorded as what it is -- the product failing its
        # cancellation contract -- and the next case still runs.
        stdout_path, stderr_path = out / (case["id"] + ".stdout"), out / (case["id"] + ".stderr")
        started = time.monotonic()
        overrun = None
        with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
            process = subprocess.Popen(  # noqa: S603
                command,
                stdout=stdout,
                stderr=stderr,
                text=True,
                env={**os.environ, "OUSAST_LOG_LEVEL": "INFO", "OUSAST_SAMPLE_PROFILE": str(out / (case["id"] + ".profile.txt"))},
                start_new_session=True,
            )
            try:
                returncode: int | None = process.wait(timeout=args.deadline + 60)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                returncode = None
                overrun = round(time.monotonic() - started - args.deadline, 1)
        elapsed = time.monotonic() - started
        terminal = stdout_path.read_text(errors="replace")
        entry: dict[str, Any] = {
            "case_id": case["id"],
            "label": case["label"],
            "role": role_of(case),
            "base_oid": pins[case["base"]],
            "head_oid": pins[case["tip"]],
            "exit_code": returncode,
            "elapsed_seconds": elapsed,
            "terminal": terminal,
        }
        if overrun is not None:
            entry["outcome"] = {"instrument_error": "deadline_overrun", "overrun_seconds": overrun}
        elif artifact.is_file():
            data = json.loads(artifact.read_text())
            entry["provenance_matches"] = all(
                data["provenance"].get(k) == installed[k] for k in ("engine", "facts", "queries", "policy", "core", "semantics")
            )
            entry["outcome"] = summarize(case, target, data)
        else:
            entry["outcome"] = {"instrument_error": "missing_artifact"}
        record["cases"].append(entry)
        write(out / "transfer-record.json", record)
        print(json.dumps({"case": case["id"], "elapsed": round(elapsed, 1), "exit": returncode}), flush=True)

    outcomes = {c["case_id"]: c.get("outcome", {}) for c in record["cases"]}
    regressions = [(c["case_id"], c.get("outcome", {})) for c in record["cases"] if c.get("role") == "regression"]
    if regressions:
        record["verdict"] = {
            "targets_detected": {cid: o.get("findings_at_target", 0) for cid, o in regressions},
            "all_targets_detected": all(o.get("findings_at_target") for _, o in regressions),
            "all_target_questions_answered": all(o.get("target_questions_answered") for _, o in regressions),
            "nothing_reported_new": not any(
                f["recorded"][0] in ("new", "worsened") for _, o in regressions for f in o.get("recorded_at_target", [])
            ),
            "all_recorded": all(o.get("recorded_status") == "evaluated" for _, o in regressions),
            "no_admitted_defects": all(o.get("admitted_defects") == 0 for _, o in regressions),
            "note": (
                "Identical revisions on both sides: this establishes detection and completion, not novelty. "
                "A target reported new here would be a comparison defect."
            ),
        }
        write(out / "transfer-record.json", record)
        print(json.dumps(record["verdict"]), flush=True)
        return 0 if all(v for k, v in record["verdict"].items() if k not in ("note", "targets_detected")) else 1
    by_role = {c.get("role"): c.get("outcome", {}) for c in record["cases"]}
    introduce, repair, benign = by_role.get("introduce", {}), by_role.get("repair", {}), by_role.get("benign", {})
    record["verdict"] = {
        "raw_witness_present": bool(introduce.get("findings_at_target")),
        "fixed_twin_quiet": bool(repair.get("target_questions_answered")) and repair.get("findings_at_target") == 0,
        "unchanged_not_new_regression": bool(benign.get("target_questions_answered"))
        and not any(f["recorded"][0] in ("new", "worsened") for f in benign.get("recorded_at_target", [])),
        "all_recorded": all(o.get("recorded_status") == "evaluated" for o in outcomes.values() if o),
        "no_admitted_defects": all(o.get("admitted_defects") == 0 for o in outcomes.values() if o),
        "note": "Development transfer evidence. Silence from a failure is not a pass; an unanalyzed fixed twin fails.",
    }
    write(out / "transfer-record.json", record)
    print(json.dumps(record["verdict"]), flush=True)
    return 0 if all(v for k, v in record["verdict"].items() if k != "note") else 1


if __name__ == "__main__":
    raise SystemExit(main())
