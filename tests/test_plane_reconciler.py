"""ai-service-plane Req 3.1-3.5, 2.2, 7.3: a fake ``ax`` drives a Run through the reconciler.

The fake is a Python script the tests write into ``tmp_path``: it logs every argv line, parses what ``apply``
receives, answers ``get task`` with Running until a scripted poll count and then a terminal phase, and on reaching
it POSTs a scripted tar to the ``OUSAST_ARTIFACT_URL`` it found in the applied Task's env. Nothing here runs a
task; every outcome comes from a scripted ``summary.json`` delivery.
"""

from __future__ import annotations

import io
import json
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest
import yaml

from openultrasast.plane import reconciler
from openultrasast.plane.workspaces import workspaces

RECONCILER = Path("src/openultrasast/plane/reconciler.py")

FAKE_AX = '''#!{python}
"""Fake ax CLI for the reconciler tests: argv log, scripted phases, scripted deliveries."""
import io, json, sys, tarfile, time, urllib.error, urllib.request
from pathlib import Path
import yaml

HERE = Path(__file__).resolve().parent
SCRIPT = json.loads((HERE / "script.json").read_text())
argv = sys.argv[1:]
(HERE / "ax.log").open("a").write(f"{{time.monotonic():.4f}} " + " ".join(argv) + "\\n")
(HERE / "applied").mkdir(exist_ok=True)
if argv[:2] == ["apply", "-f"]:
    docs = list(yaml.safe_load_all(Path(argv[2]).read_text()))
    for doc in docs:
        if doc["kind"] == "Task":
            env = {{e["name"]: e["value"] for e in doc["spec"].get("env", [])}}
            (HERE / "applied" / (doc["metadata"]["name"] + ".json")).write_text(json.dumps({{"docs": docs, "env": env, "polls": 0}}))
    print("task created")
elif argv[:2] == ["get", "task"]:
    record = HERE / "applied" / (argv[2] + ".json")
    if not record.exists():
        print("Error: not found", file=sys.stderr)
        sys.exit(1)
    rec = json.loads(record.read_text())
    rec["polls"] += 1
    env, task = rec["env"], rec["env"]["OUSAST_TASK"]
    script = SCRIPT.get(task, {{}})
    needed = script.get("polls", 1)
    phase = "Running" if rec["polls"] < needed else script.get("phase", "Completed")
    if rec["polls"] == needed and script.get("deliver", True):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for path, content in script.get("files", {{}}).items():
                data = (content if isinstance(content, str) else json.dumps(content)).encode()
                info = tarfile.TarInfo(path)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        headers = {{"Content-Type": "application/x-tar", "X-Ousast-Task": script.get("as_task", task), "X-Ousast-Run": env["OUSAST_RUN"]}}
        req = urllib.request.Request(env["OUSAST_ARTIFACT_URL"], data=buf.getvalue(), method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                (HERE / "ax.log").open("a").write(f"{{time.monotonic():.4f}} delivered {{task}} {{resp.status}}\\n")
        except urllib.error.HTTPError as exc:
            (HERE / "ax.log").open("a").write(f"{{time.monotonic():.4f}} rejected {{task}} {{exc.code}}\\n")
    record.write_text(json.dumps(rec))
    print(yaml.safe_dump({{"apiVersion": "ax.io/v1alpha1", "kind": "Task", "metadata": {{"name": argv[2]}}, "status": {{"phase": phase}}}}))
elif argv[:2] == ["delete", "task"]:
    print("deleted")
'''

MANIFESTS = """
apiVersion: ax.io/v1alpha1
kind: Model
metadata:
  name: deepseek-flash
  annotations: {openultrasast.io/provider-extension: "true"}
spec:
  provider: deepseek
  model: deepseek-chat
  parameters: {cache_hit_per_m: 0.07, input_per_m: 0.27, output_per_m: 1.1}
---
apiVersion: ax.io/v1alpha1
kind: Workspace
metadata:
  name: case-pin
spec:
  git: [{name: repo, repo: https://example.invalid/repo.git, commit: abc123}]
---
apiVersion: ax.io/v1alpha1
kind: Task
metadata:
  name: repo-facts
spec:
  image: ousast-runner:dev
  command: [repo_facts]
  workspaces: [{name: case-pin, path: /workspace}]
---
apiVersion: ax.io/v1alpha1
kind: Task
metadata:
  name: verify
  annotations: {openultrasast.io/model: deepseek-flash}
spec:
  image: ousast-runner:dev
  command: [verify]
  env: [{name: OUSAST_PASS, value: a}]
  workspaces: [{name: case-pin, path: /workspace}]
---
apiVersion: ax.io/v1alpha1
kind: Task
metadata:
  name: agree
spec:
  command: [agree]
---
apiVersion: openultrasast.io/v1alpha1
kind: Run
metadata:
  name: {run}
spec:
  tasks:
{tasks}
"""

CHAIN = """
    - name: repo-facts
      task: repo-facts
      outputs: [facts.json]
      serialize: engine
    - name: verify
      task: verify
      inputs: {facts: repo-facts/facts.json}
      outputs: [agreed.json]
      budget: {usd: 2.5, calls: 40}
    - name: agree
      task: agree
      dependsOn: [verify]
      inputs: {pass: verify/agreed.json}
"""

FACTS_SUMMARY = {"status": "done", "units_done": 3, "units_total": 3, "usd": None, "calls": 0, "usage": {}}
VERIFY_SUMMARY = {
    "status": "done",
    "units_done": 2,
    "units_total": 2,
    "usd": 0.5,
    "calls": 4,
    "model": "deepseek-flash",
    "usage": {"prompt_tokens": 1000, "prompt_cache_hit_tokens": 300, "completion_tokens": 200},
}
AGREE_SUMMARY = {"status": "done", "units_done": 1, "units_total": 1, "usd": None, "calls": 0}
SCRIPT = {
    "repo-facts": {"polls": 2, "files": {"summary.json": FACTS_SUMMARY, "facts.json": {"a.py": {"functions": ["f"]}}}},
    "verify": {"polls": 2, "files": {"summary.json": VERIFY_SUMMARY, "agreed.json": {"agreed": ["a.py:f"]}}},
    "agree": {"polls": 1, "files": {"summary.json": AGREE_SUMMARY}},
}


class Fake:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.ax = root / "ax"
        self.ax.write_text(FAKE_AX.format(python=sys.executable), encoding="utf-8")
        self.ax.chmod(self.ax.stat().st_mode | stat.S_IXUSR)

    def script(self, script: dict) -> None:
        (self.root / "script.json").write_text(json.dumps(script), encoding="utf-8")

    def log(self) -> list[tuple[float, list[str]]]:
        lines = (self.root / "ax.log").read_text(encoding="utf-8").splitlines() if (self.root / "ax.log").exists() else []
        return [(float(line.split()[0]), line.split()[1:]) for line in lines]

    def applied(self, run: str, task: str) -> dict:
        return json.loads((self.root / "applied" / f"{run}-{task}.json").read_text(encoding="utf-8"))

    def events(self, verb: str) -> list[tuple[float, str]]:
        """(time, name) of every ``apply``/``delete``/``delivered``/``rejected`` line, name = run task or ax name."""
        out = []
        for stamp, words in self.log():
            if verb == "apply" and words[:2] == ["apply", "-f"]:
                out.append((stamp, Path(words[2]).parent.name))
            elif verb == "delete" and words[:2] == ["delete", "task"]:
                out.append((stamp, words[2]))
            elif verb in ("delivered", "rejected") and words[0] == verb:
                out.append((stamp, words[1]))
        return out


@pytest.fixture
def fake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fake:
    monkeypatch.setenv("OUSAST_RESULTS", str(tmp_path / "results"))
    monkeypatch.setenv("OUSAST_ARTIFACT_HOST", "127.0.0.1")
    monkeypatch.setenv("OUSAST_POLL_SECONDS", "0.02")
    fake = Fake(tmp_path)
    fake.script(SCRIPT)
    return fake


def write_run(tmp_path: Path, name: str, tasks: str = CHAIN) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(MANIFESTS.replace("{run}", name).replace("{tasks}", tasks.rstrip("\n")), encoding="utf-8")
    return path


def state_of(name: str) -> dict:
    return json.loads((reconciler.run_dir(name) / "state.json").read_text(encoding="utf-8"))


def statuses(name: str) -> dict[str, str]:
    return {task: info["status"] for task, info in state_of(name)["tasks"].items()}


# --- the DAG through ax -------------------------------------------------------------------------------------------


def test_chain_runs_in_order_with_inputs_env_and_model(fake: Fake, tmp_path: Path) -> None:
    result = reconciler.run(write_run(tmp_path, "chain"), ax=str(fake.ax))
    assert result == "done"
    assert statuses("chain") == {"repo-facts": "done", "verify": "done", "agree": "done"}
    applies = [name for _, name in fake.events("apply")]
    assert applies == ["repo-facts", "verify", "agree"]
    assert [n for _, n in fake.events("delete")] == ["chain-repo-facts", "chain-verify", "chain-agree"]
    verify = fake.applied("chain", "verify")
    env = verify["env"]
    assert env["OUSAST_PASS"] == "a" and env["OUSAST_RUN"] == "chain" and env["OUSAST_TASK"] == "verify"
    assert env["OUSAST_OUTPUT_DIR"] == "/workspace/.ousast-out/verify"
    assert env["OUSAST_BUDGET_USD"] == "2.5" and env["OUSAST_BUDGET_CALLS"] == "40"
    assert env["OUSAST_INPUT_FACTS"] == "/workspace/.ousast-in/verify/repo-facts/facts.json"
    assert env["OUSAST_ARTIFACT_URL"].startswith("http://127.0.0.1:")
    assert env["OUSAST_MODEL"] == "deepseek-flash"
    assert json.loads(env["OUSAST_MODEL_PARAMS"]) == {"cache_hit_per_m": 0.07, "input_per_m": 0.27, "output_per_m": 1.1}
    kinds = [(d["kind"], d["metadata"]["name"]) for d in verify["docs"]]
    assert kinds == [("Task", "chain-verify"), ("Model", "deepseek-flash"), ("Workspace", "case-pin"), ("Workspace", "chain-verify-inputs")]
    inputs_ws = verify["docs"][3]
    assert inputs_ws["spec"]["files"] == [{"path": "repo-facts/facts.json", "content": json.dumps({"a.py": {"functions": ["f"]}})}]
    assert verify["docs"][0]["spec"]["workspaces"][-1] == {"name": "chain-verify-inputs", "path": "/workspace/.ousast-in/verify"}
    assert "annotations" not in verify["docs"][0]["metadata"], "ax's ObjectMeta has no annotations"
    facts = fake.applied("chain", "repo-facts")
    assert "OUSAST_MODEL" not in facts["env"] and "OUSAST_BUDGET_USD" not in facts["env"]
    assert facts["docs"][0]["spec"]["image"] == "ousast-runner:dev"
    delivered = reconciler.run_dir("chain") / "verify" / "agreed.json"
    assert json.loads(delivered.read_text()) == {"agreed": ["a.py:f"]}
    assert state_of("chain")["tasks"]["verify"]["usd"] == 0.5 and state_of("chain")["tasks"]["verify"]["model"] == "deepseek-flash"
    assert not (reconciler.run_dir("chain") / "lock").exists()


PAIR = """
    - name: x
      task: repo-facts
      {serialize}
    - name: y
      task: repo-facts
      {serialize}
"""


def overlap(fake: Fake) -> bool:
    applies = dict((name, stamp) for stamp, name in fake.events("apply"))
    deletes = dict((name.split("-", 1)[1], stamp) for stamp, name in fake.events("delete"))
    return max(applies.values()) < min(deletes.values())


def test_serialize_label_never_overlaps_but_others_do(fake: Fake, tmp_path: Path) -> None:
    fake.script({"x": {"polls": 4, "files": {"summary.json": FACTS_SUMMARY}}, "y": {"polls": 4, "files": {"summary.json": FACTS_SUMMARY}}})
    assert reconciler.run(write_run(tmp_path, "par", PAIR.replace("{serialize}", "")), ax=str(fake.ax), workers=2) == "done"
    assert overlap(fake), "two unlabeled tasks with --workers 2 run at once"
    (fake.root / "ax.log").unlink()
    serialized = write_run(tmp_path, "ser", PAIR.replace("{serialize}", "serialize: engine"))
    assert reconciler.run(serialized, ax=str(fake.ax), workers=2) == "done"
    assert not overlap(fake), "tasks sharing a serialize label never overlap"


def test_unfinished_stops_dependants_and_rerun_skips_done(fake: Fake, tmp_path: Path) -> None:
    script = json.loads(json.dumps(SCRIPT))
    script["verify"]["files"]["summary.json"] = {**VERIFY_SUMMARY, "status": "unfinished", "units_done": 1, "reason": "budget"}
    fake.script(script)
    manifest = write_run(tmp_path, "resume")
    assert reconciler.run(manifest, ax=str(fake.ax)) == "unfinished"
    assert statuses("resume") == {"repo-facts": "done", "verify": "unfinished", "agree": "pending"}
    assert state_of("resume")["tasks"]["verify"]["reason"] == "budget"
    fake.script(SCRIPT)
    (fake.root / "ax.log").unlink()
    assert reconciler.run(manifest, ax=str(fake.ax)) == "done"
    assert [name for _, name in fake.events("apply")] == ["verify", "agree"], "done tasks are skipped on rerun (Req 2.2, 3.3)"
    assert statuses("resume") == {"repo-facts": "done", "verify": "done", "agree": "done"}


def test_failed_task_halts_the_run(fake: Fake, tmp_path: Path) -> None:
    script = json.loads(json.dumps(SCRIPT))
    failed = {"status": "failed", "units_done": 0, "units_total": 3, "reason": "402 insufficient balance"}
    script["repo-facts"]["files"]["summary.json"] = failed
    fake.script(script)
    assert reconciler.run(write_run(tmp_path, "halt"), ax=str(fake.ax)) == "failed"
    assert statuses("halt") == {"repo-facts": "failed", "verify": "pending", "agree": "pending"}
    assert state_of("halt")["tasks"]["repo-facts"]["reason"] == "402 insufficient balance"
    assert [name for _, name in fake.events("apply")] == ["repo-facts"]


def test_ax_failure_phase_and_missing_delivery_are_failed(fake: Fake, tmp_path: Path) -> None:
    script = json.loads(json.dumps(SCRIPT))
    script["repo-facts"]["phase"] = "Failed"
    fake.script(script)
    assert reconciler.run(write_run(tmp_path, "phase"), ax=str(fake.ax)) == "failed"
    assert state_of("phase")["tasks"]["repo-facts"]["reason"] == "ax phase Failed"
    script = json.loads(json.dumps(SCRIPT))
    script["repo-facts"]["deliver"] = False
    fake.script(script)
    assert reconciler.run(write_run(tmp_path, "silent"), ax=str(fake.ax)) == "failed"
    assert state_of("silent")["tasks"]["repo-facts"]["reason"] == "no summary.json delivered"
    assert [n for _, n in fake.events("delete")] == ["phase-repo-facts", "silent-repo-facts"], "ax delete follows every terminal task"


def test_summary_done_requires_every_unit(fake: Fake, tmp_path: Path) -> None:
    script = json.loads(json.dumps(SCRIPT))
    script["repo-facts"]["files"]["summary.json"] = {**FACTS_SUMMARY, "units_done": 2}
    fake.script(script)
    assert reconciler.run(write_run(tmp_path, "short"), ax=str(fake.ax)) == "failed"
    assert statuses("short")["repo-facts"] == "failed"


# --- receiver and lock ---------------------------------------------------------------------------------------------


def tar_of(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_receiver_rejects_traversal_unknown_tasks_and_wrong_types(tmp_path: Path) -> None:
    receiver = reconciler.Receiver("r", tmp_path / "r", 0)
    receiver.running.add("t")
    headers = {"X-Ousast-Run": "r", "X-Ousast-Task": "t", "Content-Type": "application/x-tar"}
    code, text = receiver.accept(headers, tar_of({"../escape.json": b"{}"}))
    assert code == 400 and "escape" in text and not (tmp_path / "escape.json").exists()
    assert receiver.accept({**headers, "X-Ousast-Task": "other"}, tar_of({"summary.json": b"{}"}))[0] == 403
    assert receiver.accept({**headers, "X-Ousast-Run": "someone"}, tar_of({"summary.json": b"{}"}))[0] == 403
    assert receiver.accept({**headers, "Content-Type": "application/json"}, b"{}")[0] == 415
    assert receiver.accept(headers, b"not a tar")[0] == 400
    assert receiver.accept(headers, tar_of({"summary.json": b"{}", "sub/x.json": b"1"}))[0] == 200
    assert (tmp_path / "r" / "t" / "sub" / "x.json").read_text() == "1" and "t" in receiver.delivered
    receiver.server_close()


def test_delivery_for_a_task_that_is_not_running_is_rejected(fake: Fake, tmp_path: Path) -> None:
    script = json.loads(json.dumps(SCRIPT))
    script["repo-facts"]["as_task"] = "agree"  # the runner claims to be a task that has not started
    fake.script(script)
    assert reconciler.run(write_run(tmp_path, "spoof"), ax=str(fake.ax)) == "failed"
    assert [n for _, n in fake.events("rejected")] == ["repo-facts"]
    assert not (reconciler.run_dir("spoof") / "agree" / "summary.json").exists()


def test_lock_refuses_a_second_runner_and_ignores_a_dead_one(fake: Fake, tmp_path: Path) -> None:
    manifest = write_run(tmp_path, "locked")
    base = reconciler.run_dir("locked")
    base.mkdir(parents=True)
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        (base / "lock").write_text(str(holder.pid))
        with pytest.raises(RuntimeError, match=f"held by pid {holder.pid}"):
            reconciler.run(manifest, ax=str(fake.ax))
        assert not fake.events("apply")
    finally:
        holder.kill()
        holder.wait()
    (base / "lock").write_text(str(holder.pid))  # the process is gone: a stale lock
    assert reconciler.run(manifest, ax=str(fake.ax)) == "done"


# --- status and attribution (Req 7.3) ------------------------------------------------------------------------------


def usage(prompt: int, cache_hit: int, output: int) -> dict[str, int]:
    return {"prompt_tokens": prompt, "prompt_cache_hit_tokens": cache_hit, "completion_tokens": output}


def test_status_prints_attribution_from_usage_fields_only(fake: Fake, tmp_path: Path) -> None:
    script = json.loads(json.dumps(SCRIPT))
    script["agree"]["files"]["summary.json"] = {**AGREE_SUMMARY, "model": "deepseek-flash", "usd": 0.1, "calls": 1}  # no usage
    script["verify"]["files"]["units.jsonl"] = "\n".join(
        json.dumps(u)
        for u in (
            {"path": "a.py", "turns": 3, "usd": 0.3, "usage": usage(700, 300, 150)},
            {"path": "b.py", "turns": 1, "usd": 0.2, "usage": usage(300, 0, 50)},
        )
    )
    fake.script(script)
    assert reconciler.run(write_run(tmp_path, "attr"), ax=str(fake.ax)) == "done"
    text = reconciler.status("attr", units=True)
    lines = {line.split()[0]: line.split() for line in text.splitlines() if line.strip() and not line.startswith("run ")}
    assert lines["verify"][1:7] == ["deepseek-flash", "4", "1000", "300", "200", "0.5000"]
    assert lines["agree"][1:7] == ["deepseek-flash", "1", "n/a", "n/a", "n/a", "0.1000"], "missing usage is n/a, never estimated"
    assert lines["repo-facts"][1:7] == ["-", "0", "n/a", "n/a", "n/a", "n/a"]
    assert lines["a.py"][1:7] == ["deepseek-flash", "3", "700", "300", "150", "0.3000"]
    assert lines["b.py"][1:7] == ["deepseek-flash", "1", "300", "0", "50", "0.2000"]
    assert lines["subtotal"][1:8] == ["deepseek-flash", "deepseek-flash", "5", "n/a", "n/a", "n/a", "0.6000"]
    assert lines["total"][1:7] == ["-", "5", "n/a", "n/a", "n/a", "0.6000"]
    report = json.loads((reconciler.run_dir("attr") / "attribution.json").read_text())
    assert report["total"] == {"task": "total", "model": None, "calls": 5, "prompt": None, "cache_hit": None, "output": None, "usd": 0.6}
    assert [u["task"] for u in report["units"]["verify"]] == ["a.py", "b.py"]
    assert [row["status"] for row in report["tasks"]] == ["done", "done", "done"]
    fake.script(SCRIPT)
    reconciler.run(write_run(tmp_path, "attr2"), ax=str(fake.ax))
    report = reconciler.attribution("attr2")
    assert report["total"]["prompt"] == 1000 and report["total"]["cache_hit"] == 300 and report["total"]["output"] == 200
    assert report["models"][0]["task"] == "subtotal deepseek-flash" and report["models"][0]["usd"] == 0.5


def test_status_of_an_unknown_run_says_so(fake: Fake) -> None:
    assert "not started" in reconciler.status("nothing")


# --- doctor, workspaces, size ---------------------------------------------------------------------------------------


def test_doctor_names_the_bring_up_script_when_nothing_is_reachable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))  # no kubectl, no curl
    checks = reconciler.doctor()
    assert [name for name, _, _ in checks] == [
        "kind cluster",
        "agent substrate (ate-system)",
        "ax controller (ax-system)",
        "runner image in kind registry",
    ]
    assert all(not ok and "ops/ax/up.sh" in text for _, ok, text in checks)


def test_workspaces_one_manifest_per_case_pin(tmp_path: Path) -> None:
    population = tmp_path / "population.toml"
    population.write_text(
        '[[case]]\nid = "demo-sqli"\nrepo = "https://github.com/x/y"\nvulnerable = "aaa"\nfixed = "bbb"\n'
        'benign = { base = "ccc", tip = "ddd" }\n',
        encoding="utf-8",
    )
    written = workspaces(population, tmp_path / "out")
    labels = ("vulnerable", "fixed", "benign-base", "benign-tip")
    assert [p.name for p in written] == [f"demo-sqli-{label}.yaml" for label in labels]
    doc = yaml.safe_load(written[0].read_text(encoding="utf-8"))
    assert doc == {
        "apiVersion": "ax.io/v1alpha1",
        "kind": "Workspace",
        "metadata": {"name": "demo-sqli-vulnerable"},
        "spec": {"git": [{"name": "repo", "repo": "https://github.com/x/y", "commit": "aaa"}]},
    }
    from openultrasast.plane.manifests import load_manifests

    assert set(load_manifests(written).workspaces) == {p.stem for p in written}


def test_reconciler_is_under_500_lines_and_holds_no_pipeline_logic() -> None:
    text = RECONCILER.read_text(encoding="utf-8")
    assert len(text.splitlines()) < 500, "Req 3.4: the reconciler stays under 500 lines"
    for word in ("prompt(", "openai", "ChatClient", "score(", "system_prompt"):
        assert word not in text, f"Req 3.4: no pipeline logic in the reconciler ({word})"
    assert "Popen" not in text and "openultrasast.plane.tasks" not in text, "ax is the only executor"


def test_cli_wires_plane_subcommands() -> None:
    from openultrasast.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["plane", "--help"])
    assert exc.value.code == 0
    with pytest.raises(SystemExit):
        main(["plane"])


def test_elapsed_polling_is_paced(fake: Fake, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUSAST_POLL_SECONDS", "0.1")
    fake.script({"x": {"polls": 3, "files": {"summary.json": FACTS_SUMMARY}}, "y": {"polls": 1, "files": {"summary.json": FACTS_SUMMARY}}})
    started = time.monotonic()
    assert reconciler.run(write_run(tmp_path, "paced", PAIR.replace("{serialize}", "")), ax=str(fake.ax)) == "done"
    assert time.monotonic() - started >= 0.4, "three polls of x plus one of y at 0.1s each"


def test_doctor_treats_an_empty_namespace_as_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    """kubectl's "No resources found" must not read as one ready pod (a plausible-zero instrument failure)."""
    from openultrasast.plane import reconciler

    monkeypatch.setattr(reconciler, "_sh", lambda *a: (True, "No resources found in ax-system namespace."))
    ok, text = reconciler._pods_ready("ax-system", "kind-ousast")
    assert not ok and "no pods" in text
    monkeypatch.setattr(reconciler, "_sh", lambda *a: (True, "a-1 1/1 Running 0 1m\nb-2 0/1 Completed 0 1m"))
    assert reconciler._pods_ready("ns", "ctx") == (True, "2 pods ready")
    monkeypatch.setattr(reconciler, "_sh", lambda *a: (True, "a-1 0/1 Running 0 1m"))
    assert reconciler._pods_ready("ns", "ctx")[0] is False
