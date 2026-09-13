"""Packaged JavaScript reuse correctness control, not capability qualification.

Run with --out pointing to an empty directory outside any analyzed repository.
Authored development code is never an independent precision/recall population.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
if any(out.iterdir()):
    parser.error("output directory must be empty")
repo = out / "repo"
repo.mkdir()


def git(*args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


git("init")
git("config", "user.name", "Replay control")
git("config", "user.email", "control@example.invalid")
git("config", "core.hooksPath", "/dev/null")
source = repo / "api.js"
source.write_text('function handler(req, res) {\n const value = "fixed";\n eval(value);\n}\napp.post("/run", handler);\n')
assert len(source.read_bytes()) > 0
git("add", "api.js")
git("commit", "-m", "fixed")
base = git("rev-parse", "HEAD")
source.write_text(source.read_text().replace('"fixed"', "req.body.value"))
git("add", "api.js")
git("commit", "-m", "introduce")
head = git("rev-parse", "HEAD")
runs = []


def run(name, deadline, cache=True, tip=head):
    artifact = out / (name + ".json")
    cmd = [
        "python",
        "-m",
        "openultrasast.cli",
        "pre-push",
        str(repo),
        "--base",
        base,
        "--head",
        tip,
        "--artifact",
        str(artifact),
        "--deadline",
        str(deadline),
        "--max-regions",
        "20",
    ]
    if cache:
        cmd += ["--cache-dir", str(out / "cache")]
    start = time.monotonic()
    process = subprocess.run(cmd, capture_output=True, text=True, timeout=deadline + 10)
    elapsed = time.monotonic() - start
    (out / (name + ".stdout")).write_text(process.stdout)
    (out / (name + ".stderr")).write_text(process.stderr)
    assert artifact.is_file(), (process.returncode, process.stdout, process.stderr)
    data = json.loads(artifact.read_text())
    run = {
        "name": name,
        "elapsed_seconds": elapsed,
        "exit_code": process.returncode,
        "timings": data["timings"],
        "result": data["result"],
        "artifact": str(artifact),
    }
    runs.append(run)
    (out / "runs.json").write_text(json.dumps(runs, indent=2))
    print(json.dumps(run), flush=True)
    return data


populated = run("populate", 600)
warm = run("warm-identical", 30)
cold = run("uncached", 600, False)
(repo / "package.json").write_text('{"dependencies":{"express":"5.0.0"}}\n')
git("add", "package.json")
git("commit", "-m", "dependency change")
changed = git("rev-parse", "HEAD")
run("dependency-edit", 30, tip=changed)
git("rm", "package.json")
source.write_text(source.read_text().replace("req.body.value", 'req.body.value + "!"'))
git("add", "api.js")
git("commit", "-m", "one function edit")
edited = git("rev-parse", "HEAD")
run("one-function-edit", 30, tip=edited)


def evidence(data):
    return [
        {
            "side": s["side"],
            "scope": s["scan"]["scope"],
            "questions": s["scan"]["question_outcomes"],
            "findings": s["scan"]["findings"],
            "degradations": s["scan"]["degradations"],
        }
        for s in data["scans"]
    ]


summary = {
    "cold_populated_evidence_equal": evidence(cold) == evidence(populated),
    "cold_warm_evidence_equal": evidence(cold) == evidence(warm),
    "admission_equal": cold["admission"] == warm["admission"],
    "runs": runs,
    "source_bytes": len(source.read_bytes()),
    "rollout": "not qualified; authored development control only",
}
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary), flush=True)
assert summary["cold_populated_evidence_equal"] and summary["cold_warm_evidence_equal"] and summary["admission_equal"]
assert warm["timings"]["graph_hits"] == 2 and warm["timings"]["query_hits"] > 0
assert any(item["candidate"]["delta"]["novelty"] == "new" for item in warm["admission"]["dispositions"])
assert not any(data["admission"]["defects"] for data in (populated, warm, cold))
assert runs[1]["elapsed_seconds"] <= 32
assert all(
    r["timings"]["graph_hits"] <= 1 and r["elapsed_seconds"] <= 32 for r in runs if r["name"] in ("dependency-edit", "one-function-edit")
)
