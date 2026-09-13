"""First frozen-core PMPro/Node diagnostic experiment, using local Git objects only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from openultrasast.model.contracts import QuestionIdentity
from openultrasast.model.scan import ScanBudget
from openultrasast.push.runner import _provenance
from openultrasast.push_inputs import validate_manifest
from openultrasast.push_scoring import freeze_profile, score
from openultrasast.repos import checkout_path, load_repo_recipe


def git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_NO_LAZY_FETCH="1",
        GIT_ALLOW_PROTOCOL="",
        GIT_GRAFT_FILE=os.devnull,
        GIT_AUTHOR_NAME="Authored evaluation",
        GIT_AUTHOR_EMAIL="evaluation@example.invalid",
        GIT_COMMITTER_NAME="Authored evaluation",
        GIT_COMMITTER_EMAIL="evaluation@example.invalid",
        GIT_AUTHOR_DATE="2026-09-12T00:00:00+00:00",
        GIT_COMMITTER_DATE="2026-09-12T00:00:00+00:00",
    )
    return subprocess.run(
        ["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(root), *args],
        input=data,
        capture_output=True,
        check=True,
        timeout=30,
        env=env,
    ).stdout


def pin_snapshot(bare: Path, commit: str, snapshot: dict) -> str:
    """Apply declared edits to a private Git index; retain every other tracked blob."""
    git(bare, "read-tree", commit)
    edited = False
    for entry in snapshot["files"]:
        content = git(bare, "cat-file", "blob", commit + ":" + entry["path"])
        if not content:
            raise ValueError("empty input bytes")
        if edit := entry.get("edit"):
            before, after = edit["before"].encode(), edit["after"].encode()
            if not edit["provenance"].startswith("authored") or not before or content.count(before) != 1:
                raise ValueError("authored edit must match exactly once")
            if hashlib.sha256(content).hexdigest() != entry["original_sha256"]:
                raise ValueError("original hash mismatch")
            content = content.replace(before, after, 1)
            edited = True
        if len(content) != entry["size"] or hashlib.sha256(content).hexdigest() != entry["sha256"]:
            raise ValueError("resulting input identity mismatch")
        if entry.get("edit"):
            blob = git(bare, "hash-object", "-w", "--stdin", data=content).decode().strip()
            mode = git(bare, "ls-tree", commit, "--", entry["path"]).split(b" ", 1)[0].decode()
            git(bare, "update-index", "--add", "--cacheinfo", mode, blob, entry["path"])
    if not edited:
        return commit
    tree = git(bare, "write-tree").decode().strip()
    return (
        git(bare, "commit-tree", tree, "-p", commit, data=("Authored evaluation snapshot: " + snapshot["id"] + "\n").encode())
        .decode()
        .strip()
    )


def execution_record(case_id: str, artifact: dict, *, elapsed: float, target: dict | None = None) -> dict:
    """Associate existing answers; empty rows cannot manufacture a witnessed negative."""
    selected, deferred, queries = [], [], []
    rank = None
    modes = set()
    for record in artifact["scans"]:
        if record["side"] != "head":
            continue
        scan = record["scan"]
        if scope := scan.get("scope"):
            modes.add(scope["ranking_mode"])
            if target is not None:
                rank = next(
                    (
                        index
                        for index, q in enumerate(scope["selected"], 1)
                        if all(q["identity"][key] == target[key] for key in ("path", "function", "family"))
                    ),
                    None,
                )
            selected.extend(QuestionIdentity.from_payload(q["identity"]).question_id for q in scope["selected"])
            deferred.extend(QuestionIdentity.from_payload(q["identity"]).question_id for q in scope["deferred"])
        for outcome in scan["question_outcomes"]:
            identity = QuestionIdentity.from_payload(outcome["identity"])
            query = {
                "id": identity.question_id,
                "status": "answered" if outcome["status"] == "completed" else "unanswered",
                "outcome": "unknown",
            }
            # Keep the exact question/answer association. A raw finding reached from
            # another function is not a proved transitive path for this scorer.
            findings = [
                f
                for f in scan["findings"]
                if f["family"] == identity.family
                and f["site"].startswith(identity.path + ":")
                and f["site"].rsplit(":", 1)[-1] == identity.function
            ]
            if outcome["status"] == "completed" and findings:
                target_sites = {f"{target['path']}:{line}:{target['function']}" for line in target["lines"]} if target else set()
                finding = next((f for f in findings if f["site"] in target_sites), findings[0])
                query.update(outcome="positive", finding={**finding, "site": finding["site"].rsplit(":", 1)[0]})
            queries.append(query)
    if modes and modes != {"evidence"}:
        raise ValueError("runtime ranker differs from frozen evidence mode")
    deltas = [d["candidate"]["delta"]["novelty"] for d in artifact["admission"]["dispositions"]]
    novelty = next((d for d in ("new", "worsened", "unknown", "unchanged") if d in deltas), "unknown")
    reasons = artifact["admission"]["coverage_reasons"]
    coverage = (
        "timeout"
        if any("deadline" in reason for reason in reasons)
        else ("complete" if artifact["result"]["coverage_status"] == "complete_within_scope" else "incomplete")
    )
    if artifact["admission"]["defects"]:
        raise ValueError("unqualified experiment unexpectedly emitted an admitted alert")
    return {
        "case_id": case_id,
        "ranking_mode": "evidence",
        "rank": rank,
        "rank_kind": "selected_question_position",
        "selected": selected,
        "deferred": deferred,
        "queries": queries,
        "alerts": [],
        "delta": novelty,
        "coverage": coverage,
        "cache_state": "cold",
        "timings": {
            "total": elapsed,
            "build": sum(r["scan"].get("build_seconds", 0) for r in artifact["scans"]),
            "query": sum(r["scan"].get("query_seconds", 0) for r in artifact["scans"]),
        },
    }


def write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--selection", choices=("development", "regression", "envelope"), default="development")
    parser.add_argument("--deadline", type=float, default=30)
    parser.add_argument("--cache-dir", type=Path)
    args = parser.parse_args()
    if args.deadline <= 0:
        parser.error("deadline must be positive")
    args.out.mkdir(parents=True, exist_ok=False)
    manifest = json.loads(args.manifest.read_bytes())
    validation = validate_manifest(args.manifest, cache_root=args.cache, fetch=False)
    write(args.out / "input-validation.json", validation)
    settings = ScanBudget(max_model_calls=0, max_regions=500, order_by_evidence=True)
    initial = _provenance(args.manifest.parent, settings)
    keys = ("ranking_mode", "engine", "engine_runtime", "facts", "queries", "policy", "core", "semantics")
    config = {key: initial[key] for key in keys}
    config.update(
        version="qualification-replay-v1-" + args.selection,
        scope="full tracked tree; declared first-party graph/target exclusions; evidence ranker",
        hardware=platform.platform(),
        budget_seconds=args.deadline,
        targets=json.loads((args.manifest.parent / "diagnostic-config-v1.json").read_text())["targets"],
    )
    profile = freeze_profile(args.manifest.read_bytes(), config)
    write(args.out / "profile.json", profile)  # Freeze on disk BEFORE any measurement.
    run = {"profile_sha256": profile["profile_sha256"], "context": dict(config), "records": []}
    evidence = {"cases": [], "core_changes": [], "adapter_changes": [], "freeze_after_pmpro": None}
    valid_snapshots = {s["id"] for s in validation["snapshots"] if s["status"] == "ready"}
    ready = {
        c["id"]: c["status"] == "ready" or (c["label"] == "regression" and c["base"] in valid_snapshots and c["tip"] in valid_snapshots)
        for c in validation["cases"]
    }
    snapshots = {s["id"]: s for s in manifest["snapshots"]}
    # Fixed declared order; reserved, regression and unsupported populations stay
    # in the joint scorer without scanning or tuning on the holdout.
    cases = [c for prefix in ("pmpro-", "nodegoat-") for c in manifest["cases"] if c["id"].startswith(prefix)]
    if args.selection == "regression":
        cases = [c for c in manifest["cases"] if c["label"] == "regression"]
    elif args.selection == "envelope":
        cases = [c for c in manifest["cases"] if c["label"] == "unsupported"]
    with tempfile.TemporaryDirectory(prefix="ousast-experiment-") as temporary:
        bare = Path(temporary) / "objects.git"
        bare.mkdir()
        git(bare, "init", "--bare")
        sources = {}
        for case in cases:
            for sid in (case["base"], case["tip"]):
                if sid in sources or not ready[case["id"]]:
                    continue
                snapshot = snapshots[sid]
                recipe = load_repo_recipe(args.manifest.parent / snapshot["recipe"])
                recipe = replace(recipe, commit=snapshot.get("commit", recipe.commit))
                source = checkout_path(recipe, args.cache)
                objects = git(source, "rev-parse", "--path-format=absolute", "--git-path", "objects").decode().strip()
                sources[sid] = (recipe.commit, objects)
        (bare / "objects/info/alternates").write_text("\n".join(sorted({value[1] for value in sources.values()})) + "\n")
        pins = {sid: pin_snapshot(bare, commit, snapshots[sid]) for sid, (commit, _) in sources.items()}
        write(
            args.out / "replay-pins.json",
            {"snapshots": pins, "provenance": "Full upstream trees; declared authored edits in a private bare Git repository."},
        )
        seen_comparisons = set()
        for case in cases:
            if not ready[case["id"]]:
                evidence["cases"].append({"case_id": case["id"], "status": "missing_input_prerequisite"})
                continue
            current = _provenance(args.manifest.parent, settings)
            if any(current[key] != initial[key] for key in keys):
                raise ValueError("core/facts/query/policy changed after freezing")
            if case["id"].startswith("nodegoat-") and evidence["freeze_after_pmpro"] is None:
                evidence["freeze_after_pmpro"] = {key: current[key] for key in keys}
                write(args.out / "freeze-after-pmpro.json", evidence["freeze_after_pmpro"])
            artifact_path = args.out / (case["id"] + ".json")
            command = [
                "ousast",
                "pre-push",
                str(bare),
                "--base",
                pins[case["base"]],
                "--head",
                pins[case["tip"]],
                "--artifact",
                str(artifact_path),
                "--deadline",
                str(args.deadline),
                "--cancellation-allowance",
                "2",
                "--max-regions",
                "500",
            ]
            if args.cache_dir is not None:
                command += ["--cache-dir", str(args.cache_dir)]
            start = time.monotonic()
            process = subprocess.run(command, capture_output=True, text=True, timeout=args.deadline + 5)
            elapsed = time.monotonic() - start
            (args.out / (case["id"] + ".stdout")).write_text(process.stdout)
            (args.out / (case["id"] + ".stderr")).write_text(process.stderr)
            entry = {
                "case_id": case["id"],
                "command": command,
                "process_exit_code": process.returncode,
                "elapsed_seconds": elapsed,
                "artifact": artifact_path.name if artifact_path.exists() else None,
                "terminal": process.stdout,
                "core_unchanged": True,
                "input_pins": {"base": pins[case["base"]], "head": pins[case["tip"]]},
            }
            if artifact_path.exists():
                artifact = json.loads(artifact_path.read_text())
                # Unmeasured provenance caused by preparation timeout is explicit;
                # never replace it with a fictitious runtime measurement.
                entry["runtime_provenance_available"] = all(artifact["provenance"].get(key) == initial[key] for key in keys)
                record = execution_record(case["id"], artifact, elapsed=elapsed, target=config["targets"].get(case["id"]))
                comparison = (pins[case["base"]], pins[case["tip"]])
                if args.cache_dir is not None and comparison in seen_comparisons and artifact["timings"].get("graph_hits", 0) >= 2:
                    record["cache_state"] = "identical_tip"
                seen_comparisons.add(comparison)
                entry["coverage_reasons"] = artifact["admission"]["coverage_reasons"]
                entry["stage_timings"] = artifact["timings"]
                entry["snapshot_bytes_read"] = sum(s["bytes_read"] for s in artifact["snapshots"])
                entry["classification"] = "scope/deadline" if record["coverage"] == "timeout" else "recorded context/capability limits"
            else:
                record = {
                    "case_id": case["id"],
                    "ranking_mode": "evidence",
                    "rank": None,
                    "selected": [],
                    "deferred": [],
                    "queries": [],
                    "alerts": [],
                    "delta": "unknown",
                    "coverage": "error",
                    "cache_state": "cold",
                    "timings": {"total": elapsed, "build": 0, "query": 0},
                }
                entry["classification"] = "instrument/artifact unavailable; zero stage costs mean unmeasured"
            if process.returncode != 0:
                entry["classification"] = "instrument/CLI failure"
                record["coverage"] = "error"
            run["records"].append(record)
            evidence["cases"].append(entry)
            write(args.out / "run.json", run)
            write(args.out / "execution-evidence.json", evidence)
            print(json.dumps({"case": case["id"], "coverage": record["coverage"], "elapsed_seconds": elapsed}), flush=True)
    scored = score(profile, validation, run)
    write(args.out / "scorecard.json", scored)
    decision = {
        "decision": "NO-GO",
        "capabilities_enabled": False,
        "scorecard": "scorecard.json",
        "reason": "Qualification evidence run; independent eligibility and joint quality/warm-latency gates remain unmet.",
        "selection": args.selection,
        "analysis_deadline_seconds": args.deadline,
        "recorded_cases": len(run["records"]),
        "declared_population": len(manifest["cases"]),
        "core_unchanged": True,
        "adapter_changes": [],
        "limits": [
            "No representative warm changed-code measurements; identical-comparison reuse is reported separately",
            "Untouched Ghost population not scanned",
            "PHP/Python admission populations missing",
            "libpng retained as unsupported envelope; no C/C++ detection claim",
            "Zero normal alerts from an empty registry cannot establish precision or useful recall",
        ],
    }
    write(args.out / "decision.json", decision)
    print(json.dumps(decision), flush=True)
    return 1  # Measurement completed; the feasibility/admission decision is explicitly NO-GO.


if __name__ == "__main__":
    raise SystemExit(main())
