"""Frozen repeated NodeGoat runtime experiment; never a capability qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import signal
import subprocess
import sys
import time
from pathlib import Path


def summarize(plan, runs):
    if not plan:
        raise ValueError("empty measurement population")
    ids = {row["id"] for row in plan}
    observed = {row["id"]: row for row in runs}
    if len(ids) != len(plan) or len(observed) != len(runs) or not observed.keys() <= ids:
        raise ValueError("duplicate or unplanned measurement")
    for row in runs:
        elapsed = row.get("elapsed_seconds")
        if elapsed is not None and (type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0):
            raise ValueError("invalid elapsed measurement")
    result = {
        "workloads": {},
        "runtime_verdict": "PASS",
        "rollout": "NO-GO",
        "qualification_limit": "Development NodeGoat, n=3 per workload; independent quality and multi-project performance not established.",
    }
    for name in dict.fromkeys(row["workload"] for row in plan):
        population = [p for p in plan if p["workload"] == name]
        records = [observed[p["id"]] for p in population if p["id"] in observed]
        samples = sorted(r["elapsed_seconds"] for r in records if r.get("elapsed_seconds") is not None)
        complete = sum(bool(r.get("target_completed")) for r in records)
        target_count = sum(r.get("completed_targets", int(bool(r.get("target_completed")))) for r in records)
        expected_count = sum(p.get("expected_targets", 1) for p in population)
        covered = sum(r.get("coverage") == "complete_within_scope" and not r.get("deferred") for r in records)
        row = dict(
            population=len(population),
            observed=len(records),
            missing=len(population) - len(records),
            latency_samples=len(samples),
            p50_seconds=samples[math.ceil(0.5 * len(samples)) - 1] if samples else None,
            p95_seconds=samples[math.ceil(0.95 * len(samples)) - 1] if samples else None,
            timeouts=sum(bool(r.get("timed_out")) for r in records),
            completed_targets=target_count,
            expected_targets=expected_count,
            complete_target_cases=complete,
            completion=complete / len(population),
            complete_coverage_cases=covered,
            cancellation_overrun_seconds=max(
                [max(0, r["elapsed_seconds"] - 30) for r in records if r.get("timed_out") and r.get("elapsed_seconds") is not None] or [0]
            ),
        )
        row["pass"] = (
            not row["missing"]
            and len(samples) == len(population)
            and complete / len(population) >= 0.95
            and covered / len(population) >= 0.95
            and max(samples, default=33) <= 32
            and (name == "cold" or row["p95_seconds"] <= 30)
            and row["cancellation_overrun_seconds"] <= 2
            and not any(r.get("instrument_error") for r in records)
        )
        if not row["pass"]:
            result["runtime_verdict"] = "NO-GO"
        result["workloads"][name] = row
    required = {"identical-tip", "function-edit", "dependency-edit", "configuration-edit", "cold", "growth", "multi-ref"}
    result["missing_workloads"] = sorted(required - result["workloads"].keys())
    if result["missing_workloads"]:
        result["runtime_verdict"] = "NO-GO"
    return result


def write(path, data):
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")


def main():
    from measure import git, pin_snapshot

    from openultrasast.model.scan import ScanBudget
    from openultrasast.push.runner import _provenance
    from openultrasast.repos import checkout_path, load_repo_recipe

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    manifest = json.loads(args.manifest.read_bytes())
    snapshots = {s["id"]: s for s in manifest["snapshots"]}
    selected = [s for s in snapshots if s in ("nodegoat-vulnerable", "nodegoat-fixed")]
    if len(selected) != 2:
        raise ValueError("declared NodeGoat pair unavailable")
    recipe = load_repo_recipe(args.manifest.parent / snapshots[selected[0]]["recipe"])
    source = checkout_path(recipe, args.cache)
    bare = out / "objects.git"
    bare.mkdir()
    git(bare, "init", "--bare")
    objects = git(source, "rev-parse", "--path-format=absolute", "--git-path", "objects").decode().strip()
    (bare / "objects/info/alternates").write_text(objects + "\n")
    pins = {sid: pin_snapshot(bare, recipe.commit, snapshots[sid]) for sid in selected}
    head, base = pins["nodegoat-vulnerable"], pins["nodegoat-fixed"]
    target_path = "app/routes/contributions.js"
    original = git(bare, "cat-file", "blob", head + ":" + target_path)
    assert len(original) > 0

    def mutate(changes, title):
        git(bare, "read-tree", head)
        for path, data in changes.items():
            blob = git(bare, "hash-object", "-w", "--stdin", data=data).decode().strip()
            git(bare, "update-index", "--add", "--cacheinfo", "100644", blob, path)
        tree = git(bare, "write-tree").decode().strip()
        return git(bare, "commit-tree", tree, "-p", head, data=(title + "\n").encode()).decode().strip()

    package = json.loads(git(bare, "cat-file", "blob", head + ":package.json"))
    configuration = git(bare, "cat-file", "blob", head + ":config/env/all.js")
    assert b"4000" in configuration and original.count(b"eval(req.body.preTax)") == 1
    plan = []
    for repeat in range(1, 4):
        edited = mutate(
            {target_path: original.replace(b"eval(req.body.preTax)", f"Number(req.body.preTax) + {repeat}".encode(), 1)},
            f"function edit {repeat}",
        )
        dependency = dict(package)
        dependency["dependencies"] = dict(package["dependencies"])
        dependency["dependencies"]["express"] = f"4.22.{repeat}"
        dep = mutate({"package.json": (json.dumps(dependency, indent=2) + "\n").encode()}, f"dependency edit {repeat}")
        config = mutate({"config/env/all.js": configuration.replace(b"4000", str(4100 + repeat).encode(), 1)}, f"config edit {repeat}")
        growth = mutate(
            {
                f"app/routes/runtime-growth-{i}.js": (
                    f"module.exports = function route{i}(req, res) {{ return res.json({{value: req.body.value, revision: {repeat}}}); }};\n"
                ).encode()
                for i in range(100)
            },
            f"growth {repeat}",
        )
        for workload, comparisons in [
            ("identical-tip", [(base, head)]),
            ("function-edit", [(head, edited)]),
            ("dependency-edit", [(head, dep)]),
            ("configuration-edit", [(head, config)]),
            ("cold", [(base, head)]),
            ("growth", [(head, growth)]),
            ("multi-ref", [(head, edited), (head, config)]),
        ]:
            plan.append(dict(id=f"{workload}-{repeat}", workload=workload, comparisons=comparisons, expected_targets=len(comparisons)))
    installed = _provenance(bare, ScanBudget(max_model_calls=0, max_regions=500, order_by_evidence=True))
    profile = dict(
        schema_version=1,
        plan=plan,
        source_commit=recipe.commit,
        pins=pins,
        input_probe=dict(path=target_path, bytes=len(original), sha256=hashlib.sha256(original).hexdigest()),
        provenance=installed,
        hardware=dict(
            platform=platform.platform(),
            cpu_affinity=sorted(os.sched_getaffinity(0)),
            cpuinfo=Path("/proc/cpuinfo").read_text(),
            memory_limit=Path("/sys/fs/cgroup/memory.max").read_text().strip(),
        ),
        gates=dict(deadline_seconds=30, cancellation_seconds=2, warm_p95_seconds=30, completion=0.95),
        lab_priming_deadline=600,
        quantile="nearest-rank; includes timeout elapsed values; missing samples explicit",
        target=dict(path=target_path, function="handleContributionsUpdate", family="injection"),
        harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        instrumentation_sha256=hashlib.sha256(Path(__file__).with_name("trace_cli.py").read_bytes()).hexdigest(),
    )
    write(out / "profile.json", profile)
    runs = []

    def run(case, deadline, cache=True):
        identity = case["id"]
        artifact = out / (identity + ".json")
        trace = out / (identity + ".trace.jsonl")
        lines = "".join(f"refs/heads/local{i} {tip} refs/heads/result{i} {old}\n" for i, (old, tip) in enumerate(case["comparisons"]))
        command = [
            sys.executable,
            str(Path(__file__).with_name("trace_cli.py")),
            "pre-push",
            str(bare),
            "--remote",
            "evaluation",
            "/local-only",
            "--artifact",
            str(artifact),
            "--deadline",
            str(deadline),
        ]
        if cache:
            command += ["--cache-dir", str(out / "artifacts")]
        start = time.monotonic()
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            env={**os.environ, "OUSAST_EVALUATION_TRACE": str(trace)},
        )
        error = None
        try:
            stdout, stderr = process.communicate(lines, timeout=deadline + 5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=2)
            error = "outer_deadline_exceeded"
        elapsed = time.monotonic() - start
        (out / (identity + ".stdout")).write_text(stdout)
        (out / (identity + ".stderr")).write_text(stderr)
        data = json.loads(artifact.read_bytes()) if artifact.is_file() else None
        if data is None:
            error = error or "missing_artifact"
        if process.returncode != 0:
            error = error or "unexpected_cli_exit"
        completed = 0
        if data:
            for scan in data["scans"]:
                if scan["side"] == "head" and any(
                    q["status"] == "completed" and all(q["identity"][key] == value for key, value in profile["target"].items())
                    for q in scan["scan"]["question_outcomes"]
                ):
                    completed += 1
        record = dict(
            id=identity,
            elapsed_seconds=elapsed,
            exit_code=process.returncode,
            instrument_error=error,
            timed_out=bool(data and any("deadline" in reason for reason in data["admission"]["coverage_reasons"]))
            or error == "outer_deadline_exceeded",
            target_completed=completed == case["expected_targets"],
            completed_targets=completed,
            expected_targets=case["expected_targets"],
            coverage=data["result"]["coverage_status"] if data else "unavailable",
            timings=data["timings"] if data else {},
            selected=sum(len(s["scan"]["scope"]["selected"]) for s in data["scans"] if s["side"] == "head" and s["scan"]["scope"])
            if data
            else 0,
            deferred=sum(len(s["scan"]["scope"]["deferred"]) for s in data["scans"] if s["side"] == "head" and s["scan"]["scope"])
            if data
            else 0,
            stages=[json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else [],
        )
        write(out / (identity + ".measurement.json"), record)
        print(json.dumps({k: record[k] for k in ("id", "elapsed_seconds", "target_completed", "coverage", "instrument_error")}), flush=True)
        return record

    prime = run(dict(id="lab-prime", comparisons=[(base, head)], expected_targets=1), 600)
    write(out / "priming.json", prime)
    for case in plan:
        runs.append(run(case, 30, cache=case["workload"] != "cold"))
        write(out / "runs.json", runs)
        write(out / "scorecard.json", summarize(plan, runs))
    final = summarize(plan, runs)
    final["profile_sha256"] = hashlib.sha256((out / "profile.json").read_bytes()).hexdigest()
    final["priming_completed"] = prime["target_completed"]
    write(out / "scorecard.json", final)
    return 0 if final["runtime_verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
