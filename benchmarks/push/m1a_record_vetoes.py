"""M1a: replay the pinned NodeGoat vulnerable/fixed/unchanged revisions with vetoes recorded.

Prepares the same private bare repository and authored pins as `measure.py`, records the
expected operation and outcome for each comparison BEFORE any scanner run, then invokes the
production `ousast pre-push --base/--head` replay under `--experimental-record-vetoes` with an
explicitly named development budget. The output is a replayable three-revision record with
exact revision/question/operation provenance, the per-finding veto list, and readable source
and census receipts. It is development evidence for release milestone M1a only: nothing here
is an alert, an admission, a capability or a hook-latency measurement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
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

TARGET = {"path": "app/routes/contributions.js", "function": "handleContributionsUpdate", "family": "injection"}
WITNESS_LINES = (32, 33, 34)
# Declared before running. "quiet" means no raw injection finding at the target path in the head;
# "unchanged" means the raw findings remain but the recorded novelty is not new/worsened.
PLAN: tuple[dict[str, Any], ...] = (
    {
        "id": "nodegoat-introduce",
        "base": "nodegoat-fixed",
        "head": "nodegoat-vulnerable",
        "expected": "raw injection finding at the three eval lines with recorded novelty new; every applied veto listed",
        "expected_head_findings_at_target": len(WITNESS_LINES),
    },
    {
        "id": "nodegoat-repair",
        "base": "nodegoat-vulnerable",
        "head": "nodegoat-fixed",
        "expected": "fixed twin analyzed and quiet: target questions answered with no injection finding; three base-only findings",
        "expected_head_findings_at_target": 0,
    },
    {
        "id": "nodegoat-benign",
        "base": "nodegoat-vulnerable",
        "head": "nodegoat-benign",
        "expected": "unchanged backlog: raw findings remain with recorded novelty unchanged, never new or worsened",
        "expected_head_findings_at_target": len(WITNESS_LINES),
    },
)


# Unreviewed evaluation input for the M1b explanation rendering. It is bound to the run's own
# analysis semantics, marked experimental and never enabled, so it cannot qualify a capability or
# emit an alert: the runner keeps it out of admission entirely. The wording describes exactly the
# mechanism the graph established, evaluation of a request field as JavaScript, and the repair the
# pinned source documents immediately below the eval calls.
DECLARATION = {
    "evaluation_id": "unreviewed-m1b-demonstration-v1",
    "evaluation_artifact": "experimental://m1b-recorded-vetoes",
    "verdict": "experimental",
    "consequence_template": (
        "A request field reaches {operation}, where it is evaluated as JavaScript, so an attacker "
        "controlling that field can execute arbitrary code in the server process ({context} capability)."
    ),
    "repair_template": (
        "Replace the evaluation at {operation} with a numeric conversion such as Number(...) or "
        "parseInt(...), then validate the result before use ({context} capability)."
    ),
    "operation_symbols": ("eval", "const preTax = eval", "const afterTax = eval", "const roth = eval"),
}


def declarations_for(semantics: str) -> list[dict[str, Any]]:
    key = CapabilityKey("javascript", "unspecified", "unspecified", "injection", "taint", "unreviewed", semantics)
    declaration = CapabilityAdmission(
        key,
        DECLARATION["evaluation_id"],
        DECLARATION["evaluation_artifact"],
        "experimental",
        DECLARATION["consequence_template"],
        DECLARATION["repair_template"],
        operation_symbols=tuple(DECLARATION["operation_symbols"]),
    )
    assert not declaration.enabled and declaration.verdict != "PASS", "the demonstration declaration must stay unqualified"
    return [declaration.to_payload()]


def write(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")


def receipts(bare: Path, oid: str, path: str) -> dict[str, object]:
    blob = git(bare, "cat-file", "blob", f"{oid}:{path}")
    if not blob:
        raise ValueError("empty source blob")
    return {"path": path, "bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest(), "lines": blob.count(b"\n")}


def summarize(case: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    experimental = artifact.get("experimental") or {}
    head_scans = [s["scan"] for s in artifact["scans"] if s["side"] == "head"]
    base_scans = [s["scan"] for s in artifact["scans"] if s["side"] == "base"]
    target_head = [
        f for s in head_scans for f in s["findings"] if f["family"] == TARGET["family"] and f["site"].startswith(TARGET["path"] + ":")
    ]
    target_questions = [
        q
        for s in head_scans
        for q in s["question_outcomes"]
        if q["identity"]["path"] == TARGET["path"] and q["identity"]["family"] == TARGET["family"]
    ]
    census = [
        {"language": p.get("language"), "frontend": p.get("frontend"), "files": len(p.get("paths", ())), "complete": p.get("complete")}
        for s in head_scans
        for p in s.get("partitions", ())
    ]
    raw_findings = experimental.get("findings")
    findings: list[dict[str, Any]] = raw_findings if isinstance(raw_findings, list) else []
    target_recorded = [f for f in findings if f["family"] == TARGET["family"] and f["site"].startswith(TARGET["path"] + ":")]
    observed = len(target_head)
    analyzed = bool(target_questions) and all(q["raw_rows_json"] is not None for q in target_questions)
    outcome = {
        "expected": case["expected"],
        "expected_head_findings_at_target": case["expected_head_findings_at_target"],
        "observed_head_findings_at_target": observed,
        "target_questions_answered": analyzed,
        "target_question_outcomes": [
            {"function": q["identity"]["function"], "status": q["status"], "reason": q["reason"]} for q in target_questions
        ],
        "head_scan_completed": bool(head_scans) and all(s.get("scope") is not None for s in head_scans),
        "base_scan_present": bool(base_scans),
        "production_finding_status": artifact["result"]["finding_status"],
        "production_coverage_status": artifact["result"]["coverage_status"],
        "recorded_status": experimental.get("status"),
        "evaluation": experimental.get("evaluation", []),
        "recorded_target_findings": [
            {
                "site": f["site"],
                "witness": f["witness"],
                "question_function": (f.get("question") or {}).get("function"),
                "operation_method": f.get("operation_method"),
                "base_location": f.get("base_location"),
                "production": [f["production_novelty"], f["production_reason"], f["production_admission"]],
                "recorded": [f["recorded_novelty"], f["recorded_reason"], f["recorded_admission"]],
                "vetoes": f["vetoes"],
            }
            for f in target_recorded
        ],
        "base_only_findings": experimental.get("base_only_findings", []),
        "census": census,
        "coverage_reasons": artifact["admission"]["coverage_reasons"],
        "timings": artifact["timings"],
    }
    if case["id"] == "nodegoat-repair":
        # Silence from failure is not a pass: the fixed twin must have been analyzed.
        outcome["fixed_twin_quiet"] = (
            analyzed and observed == 0 and not any("deadline" in r for r in artifact["admission"]["coverage_reasons"])
        )
    elif case["id"] == "nodegoat-benign":
        # Silence from a timeout must not read as "no regression reported".
        outcome["analyzed"] = analyzed and experimental.get("status") == "evaluated"
        outcome["reported_as_new_regression"] = any(f["recorded"][0] in ("new", "worsened") for f in outcome["recorded_target_findings"])
    else:
        outcome["raw_witness_present"] = observed == case["expected_head_findings_at_target"] and all(
            any(f["site"].startswith(f"{TARGET['path']}:{line}:") for f in target_head) for line in WITNESS_LINES
        )
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--deadline", type=float, default=900.0, help="explicitly named development budget; never the hook gate")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    manifest = json.loads(args.manifest.read_bytes())
    validation = validate_manifest(args.manifest, cache_root=args.cache, fetch=False)
    write(out / "input-validation.json", validation)
    snapshots = {s["id"]: s for s in manifest["snapshots"]}
    needed = ("nodegoat-vulnerable", "nodegoat-fixed", "nodegoat-benign")
    ready = {s["id"]: s["status"] for s in validation["snapshots"] if s["id"] in needed}
    if any(ready.get(sid) != "ready" for sid in needed):
        raise SystemExit(f"NodeGoat snapshots not ready: {ready}")
    recipe = load_repo_recipe(args.manifest.parent / snapshots[needed[0]]["recipe"])
    source = checkout_path(recipe, args.cache)
    bare = out / "objects.git"
    bare.mkdir()
    git(bare, "init", "--bare")
    objects = git(source, "rev-parse", "--path-format=absolute", "--git-path", "objects").decode().strip()
    (bare / "objects/info/alternates").write_text(objects + "\n")
    pins = {sid: pin_snapshot(bare, recipe.commit, snapshots[sid]) for sid in needed}
    settings = ScanBudget(max_model_calls=0, max_regions=500, order_by_evidence=True)
    installed = _provenance(bare, settings)
    declarations_path = out / "experimental-declarations.json"
    write(declarations_path, declarations_for(installed["semantics"]))
    record: dict[str, Any] = {
        "schema_version": 1,
        "label": LABEL,
        "declarations": declarations_path.name,
        "declaration_note": (
            "Unreviewed experimental declaration, bound to this run's semantics, used only to render the "
            "evaluation explanation. It is not enabled and not PASS, and the runner keeps it out of admission."
        ),
        "milestone": "M1a",
        "flag": FLAG,
        "development_budget_seconds": args.deadline,
        "budget_note": "Explicitly named development budget; this run cannot satisfy or measure the 30s hook latency gate.",
        "source_commit": recipe.commit,
        "pins": pins,
        "target": TARGET,
        "witness_lines": list(WITNESS_LINES),
        "plan": [dict(case, base_oid=pins[case["base"]], head_oid=pins[case["head"]]) for case in PLAN],
        "source_receipts": {sid: receipts(bare, oid, TARGET["path"]) for sid, oid in pins.items()},
        "provenance": installed,
        "hardware": {"platform": platform.platform(), "cpu_affinity": sorted(os.sched_getaffinity(0))},
        "instrument_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "cases": [],
    }
    write(out / "m1a-record.json", record)  # Expectations and pins are on disk before any scan.
    cases: list[dict[str, Any]] = []
    for case in PLAN:
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
            pins[case["head"]],
            "--artifact",
            str(artifact),
            "--deadline",
            str(args.deadline),
            "--cancellation-allowance",
            "2",
            "--max-regions",
            "500",
            "--cache-dir",
            str(out / "cache"),
            FLAG,
            "--experimental-declarations",
            str(declarations_path),
        ]
        started = time.monotonic()
        process = subprocess.run(command, capture_output=True, text=True, timeout=args.deadline + 30)
        elapsed = time.monotonic() - started
        (out / (case["id"] + ".stdout")).write_text(process.stdout)
        (out / (case["id"] + ".stderr")).write_text(process.stderr)
        entry: dict[str, Any] = {
            "case_id": case["id"],
            "command": command,
            "base_oid": pins[case["base"]],
            "head_oid": pins[case["head"]],
            "exit_code": process.returncode,
            "elapsed_seconds": elapsed,
            "terminal": process.stdout,
            "artifact": artifact.name if artifact.is_file() else None,
        }
        if artifact.is_file():
            data = json.loads(artifact.read_text())
            entry["provenance_matches_installed"] = all(
                data["provenance"].get(k) == installed[k] for k in ("engine", "facts", "queries", "policy", "core", "semantics")
            )
            entry["outcome"] = summarize(case, data)
        else:
            entry["outcome"] = {"instrument_error": "missing_artifact"}
        cases.append(entry)
        record["cases"] = cases
        write(out / "m1a-record.json", record)
        print(json.dumps({"case": case["id"], "elapsed_seconds": round(elapsed, 3), "exit": process.returncode}), flush=True)
    outcomes: dict[str, dict[str, Any]] = {str(c["case_id"]): c["outcome"] for c in cases}
    introduce, repair, benign = (outcomes.get(k, {}) for k in ("nodegoat-introduce", "nodegoat-repair", "nodegoat-benign"))
    verdict: dict[str, Any] = {
        "raw_witness_present": bool(introduce.get("raw_witness_present")),
        "fixed_twin_quiet": bool(repair.get("fixed_twin_quiet")),
        "unchanged_not_new_regression": bool(benign.get("analyzed")) and not benign.get("reported_as_new_regression", True),
        "all_recorded": all(o.get("recorded_status") == "evaluated" for o in outcomes.values()),
        "kill_criterion_triggered": bool(repair) and not repair.get("fixed_twin_quiet"),
        "note": "M1a exit evidence only when every entry is true; a fixed twin that timed out or was not analyzed fails M1a.",
    }
    record["verdict"] = verdict
    write(out / "m1a-record.json", record)
    print(json.dumps(verdict), flush=True)
    return 0 if all(v for k, v in verdict.items() if k not in ("note", "kill_criterion_triggered")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
