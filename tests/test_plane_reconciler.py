"""ai-service-plane Req 3.1-3.5, 2.2, 7.3: a fake ``ax`` drives a Run through the reconciler.

The fake is a Python script the tests write into ``tmp_path`` that follows ax's real task lifecycle (ax source:
internal/controller/reconciler.go, internal/server/server.go): ``apply`` creates the task ``Suspended``; ``resume``
fails with DeadlineExceeded the first time (ax then reports ``Failed``, as while Agent Substrate builds a new
image's golden snapshot) and succeeds after; ``get task`` answers ``Running`` forever -- ax has no Completed phase
-- and on the scripted poll it POSTs a scripted tar to the ``OUSAST_ARTIFACT_URL`` in the applied Task's env, or
turns ``Failed`` with a condition message, or vanishes. Every outcome comes from a scripted delivery, and a
delivery happens only after the reconciler's start request reached the fake router (Req 4.5).
"""

from __future__ import annotations

import io
import json
import stat
import subprocess
import sys
import tarfile
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from openultrasast.plane import reconciler
from openultrasast.plane.workspaces import workspaces

RECONCILER = Path("src/openultrasast/plane/reconciler.py")
PIN = "0123456789abcdef0123456789abcdef01234567"
SECRET = "sk-reconciler-test-7a2b-only-in-the-start-request"

# The fields ax's API server decodes (pkg/apis/v1alpha1/ax.proto, protojson: an unknown field is an error at
# ``ax apply``). ``None`` marks a value ax types as free-form (a Struct) or that this test does not descend into.
_RESOURCES = {"cpu": None, "memory": None}
AX_FIELDS: dict[str, dict] = {
    "Task": {
        "image": None,
        "command": None,
        "env": {"name": None, "value": None},
        "resources": {"requests": _RESOURCES, "limits": _RESOURCES},
        "workspaces": {"name": None, "path": None, "goal": None},
        "debug": None,
    },
    "Workspace": {
        "git": {"name": None, "repo": None, "branch": None, "dir": None, "depth": None},
        "files": {"path": None, "content": None},
        "mcp": {"registries": None, "servers": None},
        "skills": {"registries": None, "path": None},
    },
    "Model": {"provider": None, "model": None, "secretKey": {"name": None, "key": None}, "parameters": None},
}


def non_ax_fields(value: object, schema: dict | None, path: str) -> list[str]:
    """Every key under ``value`` that ``schema`` does not name, as dotted paths."""
    if schema is None:
        return []
    if isinstance(value, list):
        return [bad for i, item in enumerate(value) for bad in non_ax_fields(item, schema, f"{path}[{i}]")]
    assert isinstance(value, dict), f"{path} must be a mapping"
    bad = [f"{path}.{k}" for k in value if k not in schema]
    return bad + [b for k, v in value.items() if k in schema for b in non_ax_fields(v, schema[k], f"{path}.{k}")]


FAKE_AX = '''#!{python}
"""Fake ax CLI with ax's real task lifecycle: apply -> Suspended; resume (the first ones fail DeadlineExceeded and
leave the task Failed, as ax's server does) -> Running; never Completed; the scripted delivery after N polls."""
import io, json, sys, tarfile, time, urllib.error, urllib.request
from pathlib import Path
import yaml

HERE = Path(__file__).resolve().parent
SCRIPT = json.loads((HERE / "script.json").read_text())
argv = sys.argv[1:]
(HERE / "ax.log").open("a").write(f"{{time.monotonic():.4f}} " + " ".join(argv) + "\\n")
(HERE / "applied").mkdir(exist_ok=True)
record = HERE / "applied" / ((argv[2] if len(argv) > 2 else "-") + ".json")
rec = json.loads(record.read_text()) if record.exists() else None
script = SCRIPT.get(rec["env"]["OUSAST_TASK"], {{}}) if rec else {{}}


def gone():
    print(f'Error: getting task "{{argv[2]}}": rpc error: code = NotFound desc = task not found', file=sys.stderr)
    sys.exit(1)


if argv[:2] == ["apply", "-f"]:
    docs = list(yaml.safe_load_all(Path(argv[2]).read_text()))
    for doc in docs:
        if doc["kind"] == "Task":
            env = {{e["name"]: e["value"] for e in doc["spec"].get("env", [])}}
            state = {{"docs": docs, "env": env, "polls": 0, "resumes": 0, "phase": "Suspended", "message": "Task is suspended"}}
            (HERE / "applied" / (doc["metadata"]["name"] + ".json")).write_text(json.dumps(state))
    print("task created")
elif argv[:2] == ["resume", "task"]:
    if rec is None or rec.get("gone"):
        gone()
    rec["resumes"] += 1
    if rec["resumes"] <= script.get("resume_failures", 1):
        rec.update(phase="Failed", message="resuming actor: context deadline exceeded")
        record.write_text(json.dumps(rec))
        print("Error: resuming task: rpc error: code = DeadlineExceeded desc = context deadline exceeded", file=sys.stderr)
        sys.exit(1)
    rec.update(phase="Running", message="Task is running and its workspace is ready")
    record.write_text(json.dumps(rec))
    print(f"task.ax.io/{{argv[2]}} resumed")
elif argv[:2] == ["get", "task"]:
    if rec is None or rec.get("gone"):
        gone()
    if rec["phase"] == "Running":
        rec["polls"] += 1
    env, task = rec["env"], rec["env"]["OUSAST_TASK"]
    if rec["phase"] == "Running" and rec["polls"] == script.get("polls", 1):
        if "phase" in script:
            rec.update(phase=script["phase"], message=script.get("message", ""))
        if script.get("vanish"):
            rec["gone"] = True
    started = (HERE / "started" / argv[2]).exists()  # the runner runs its command only after the start request
    if rec["phase"] == "Running" and rec["polls"] >= script.get("polls", 1) and started and not rec.get("sent"):
        rec["sent"] = True
        if script.get("deliver", True) and "phase" not in script and not script.get("vanish"):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tar:
                for path, content in script.get("files", {{}}).items():
                    data = (content if isinstance(content, str) else json.dumps(content)).encode()
                    info = tarfile.TarInfo(path)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            headers = {{"Content-Type": "application/x-tar", "X-Ousast-Run": env["OUSAST_RUN"]}}
            headers["X-Ousast-Task"] = script.get("as_task", task)
            req = urllib.request.Request(env["OUSAST_ARTIFACT_URL"], data=buf.getvalue(), method="POST", headers=headers)
            try:
                with urllib.request.urlopen(req) as resp:
                    (HERE / "ax.log").open("a").write(f"{{time.monotonic():.4f}} delivered {{task}} {{resp.status}}\\n")
            except urllib.error.HTTPError as exc:
                (HERE / "ax.log").open("a").write(f"{{time.monotonic():.4f}} rejected {{task}} {{exc.code}}\\n")
    record.write_text(json.dumps(rec))
    if rec.get("gone"):
        gone()
    condition = {{"type": "Ready", "status": "True" if rec["phase"] == "Running" else "False", "message": rec["message"]}}
    status = {{"phase": rec["phase"], "conditions": [condition]}}
    print(yaml.safe_dump({{"apiVersion": "ax.io/v1alpha1", "kind": "Task", "metadata": {{"name": argv[2]}}, "status": status}}))
elif argv[:2] == ["delete", "task"]:
    if rec is not None:
        rec["gone"] = True
        record.write_text(json.dumps(rec))
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
  secretKey: {name: deepseek, key: DEEPSEEK_API_KEY}
  parameters: {cache_hit_per_m: 0.07, input_per_m: 0.27, output_per_m: 1.1}
---
apiVersion: ax.io/v1alpha1
kind: Workspace
metadata:
  name: case-pin
  atespace: default
  annotations: {openultrasast.io/git-commits: "repo=0123456789abcdef0123456789abcdef01234567"}
spec:
  git: [{name: repo, repo: https://example.invalid/repo.git, dir: src, depth: 1}]
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
    router: FakeRouter

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
            elif verb in ("delete", "resume") and words[:2] == [verb, "task"]:
                out.append((stamp, words[2]))
            elif verb in ("delivered", "rejected") and words[0] == verb:
                out.append((stamp, words[1]))
        return out


class FakeRouter(ThreadingHTTPServer):
    """Agent Substrate's router as the reconciler sees it: records each start request and answers from ``codes``
    (by ax task name, default 202); an accepted start marks the task started for the fake ax, whose runner only
    then runs its command and delivers."""

    daemon_threads = True

    def __init__(self, root: Path) -> None:
        super().__init__(("127.0.0.1", 0), _RouterHandler)
        self.root = root
        self.codes: dict[str, tuple[int, str]] = {}
        self.starts: list[dict] = []
        threading.Thread(target=self.serve_forever, daemon=True).start()


class _RouterHandler(BaseHTTPRequestHandler):
    server: FakeRouter

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        target = self.headers.get("ate-target-actor", "")
        name = target.partition("/")[2]
        code, text = self.server.codes.get(name, (202, "started"))
        self.server.starts.append({"at": time.monotonic(), "path": self.path, "target": target, "body": body, "code": code})
        if code == 202:
            (self.server.root / "started").mkdir(exist_ok=True)
            (self.server.root / "started" / name).touch()
        with (self.server.root / "ax.log").open("a") as log:
            log.write(f"{time.monotonic():.4f} started {name} {code}\n")
        self.send_response(code)
        self.send_header("Content-Length", str(len(text.encode())))
        self.end_headers()
        self.wfile.write(text.encode())

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture
def fake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Fake]:
    monkeypatch.setenv("OUSAST_RESULTS", str(tmp_path / "results"))
    monkeypatch.setenv("OUSAST_ARTIFACT_HOST", "127.0.0.1")
    monkeypatch.setenv("OUSAST_POLL_SECONDS", "0.02")
    monkeypatch.setenv("OUSAST_TASK_TIMEOUT", "20")  # a test that never delivers fails in seconds, not in 2 hours
    monkeypatch.setenv("OUSAST_START_TIMEOUT", "2")
    monkeypatch.setenv("DEEPSEEK_API_KEY", SECRET)  # the Model's secretKey variable, as ``.env`` would set it
    fake = Fake(tmp_path)
    fake.script(SCRIPT)
    fake.router = FakeRouter(tmp_path)
    monkeypatch.setenv("OUSAST_ROUTER_URL", f"http://127.0.0.1:{fake.router.server_address[1]}")
    try:
        yield fake
    finally:
        fake.router.shutdown()
        fake.router.server_close()


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
    assert json.loads(env["OUSAST_GIT_PINS"]) == {"case-pin/repo": PIN}, "the Workspace annotation reaches the task as env"
    assert verify["docs"][2]["spec"]["git"] == [{"name": "repo", "repo": "https://example.invalid/repo.git", "dir": "src", "depth": 1}]
    assert verify["docs"][2]["metadata"] == {"name": "case-pin", "atespace": "default"}
    assert "OUSAST_GIT_PINS" not in fake.applied("chain", "agree")["env"], "no bound workspace, no pins"
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


def test_resume_retries_deadline_exceeded_and_completion_is_the_delivery(fake: Fake, tmp_path: Path) -> None:
    """ax creates a Task Suspended; the first resume of a new image times out; a later one runs it (live evidence)."""
    assert reconciler.run(write_run(tmp_path, "life", "    - name: repo-facts\n      task: repo-facts\n"), ax=str(fake.ax)) == "done"
    verbs = [w[0] for _, w in fake.log() if w[0] in ("apply", "resume", "delivered", "delete")]
    assert verbs == ["apply", "resume", "resume", "delivered", "delete"], "resumed twice, delivered, then deleted"
    resumes = [stamp for stamp, _ in fake.events("resume")]
    (delivered, _), (deleted, _) = fake.events("delivered")[0], fake.events("delete")[0]
    assert resumes[1] < delivered < deleted, "the fake delivers only once a resume went through"
    assert state_of("life")["tasks"]["repo-facts"]["status"] == "done", "done without any Completed phase from ax"


def test_resume_gives_up_after_the_resume_timeout_with_the_last_error(fake: Fake, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUSAST_RESUME_TIMEOUT", "0.3")
    fake.script({**SCRIPT, "repo-facts": {**SCRIPT["repo-facts"], "resume_failures": 1000}})
    assert reconciler.run(write_run(tmp_path, "stuck"), ax=str(fake.ax)) == "failed"
    reason = state_of("stuck")["tasks"]["repo-facts"]["reason"]
    assert "OUSAST_RESUME_TIMEOUT" in reason and "DeadlineExceeded" in reason
    assert len(fake.events("resume")) >= 2, "retried with backoff before giving up"
    assert [n for _, n in fake.events("delete")] == ["stuck-repo-facts"]


def test_ax_failed_phase_before_delivery_fails_with_the_condition_message(fake: Fake, tmp_path: Path) -> None:
    script = json.loads(json.dumps(SCRIPT))
    script["repo-facts"].update(phase="Failed", message="ActorResumeFailed: worker lost")
    fake.script(script)
    assert reconciler.run(write_run(tmp_path, "phase"), ax=str(fake.ax)) == "failed"
    assert state_of("phase")["tasks"]["repo-facts"]["reason"] == "ax phase Failed: ActorResumeFailed: worker lost"
    assert statuses("phase") == {"repo-facts": "failed", "verify": "pending", "agree": "pending"}
    assert [n for _, n in fake.events("delete")] == ["phase-repo-facts"], "ax delete follows a failed task"


def test_a_task_that_vanishes_before_delivery_is_failed(fake: Fake, tmp_path: Path) -> None:
    fake.script({**SCRIPT, "repo-facts": {**SCRIPT["repo-facts"], "vanish": True}})
    assert reconciler.run(write_run(tmp_path, "vanish"), ax=str(fake.ax)) == "failed"
    assert "disappeared from ax" in state_of("vanish")["tasks"]["repo-facts"]["reason"]


def test_no_delivery_within_the_task_timeout_is_failed(fake: Fake, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUSAST_TASK_TIMEOUT", "0.5")
    fake.script({**SCRIPT, "repo-facts": {**SCRIPT["repo-facts"], "deliver": False}})
    started = time.monotonic()
    assert reconciler.run(write_run(tmp_path, "silent"), ax=str(fake.ax)) == "failed"
    assert time.monotonic() - started >= 0.5
    reason = state_of("silent")["tasks"]["repo-facts"]["reason"]
    assert "OUSAST_TASK_TIMEOUT" in reason and "Running" in reason, "Running forever is not completion"
    assert [n for _, n in fake.events("delete")] == ["silent-repo-facts"], "ax delete follows every task"


def files_containing(root: Path, needle: str) -> list[str]:
    return sorted(str(p) for p in root.rglob("*") if p.is_file() and needle.encode() in p.read_bytes())


def test_start_is_sent_once_after_resume_with_the_models_credential(fake: Fake, tmp_path: Path) -> None:
    """Req 4.5/4.6: one start per task through the router, after ax accepted a resume; the bound Model's credential
    travels only in that request, never in the rendered Task, the run dir or any file the run leaves behind."""
    assert reconciler.run(write_run(tmp_path, "sig"), ax=str(fake.ax)) == "done"
    starts = fake.router.starts
    assert [s["target"] for s in starts] == ["default/sig-repo-facts", "default/sig-verify", "default/sig-agree"], "once each"
    assert all(s["path"] == "/ousast/v1/start" and s["code"] == 202 for s in starts)
    by_task = {s["body"]["task"]: s for s in starts}
    assert by_task["sig-verify"]["body"] == {"run": "sig", "task": "sig-verify", "credentials": {"DEEPSEEK_API_KEY": SECRET}}
    assert by_task["sig-repo-facts"]["body"]["credentials"] == {} and by_task["sig-agree"]["body"]["credentials"] == {}, "no Model"
    accepted = {}
    for stamp, words in fake.log():  # the last resume of each task is the one ax accepted
        if words[:2] == ["resume", "task"]:
            accepted[words[2]] = stamp
    delivered = {name: stamp for stamp, name in fake.events("delivered")}
    for s in starts:
        name = s["body"]["task"]
        assert accepted[name] < s["at"] < delivered[name.removeprefix("sig-")], f"{name}: resume, then start, then delivery"
    verify_model = fake.applied("sig", "verify")["docs"][1]
    assert verify_model["spec"]["secretKey"] == {"name": "deepseek", "key": "DEEPSEEK_API_KEY"}, "the manifest names the key"
    assert "DEEPSEEK_API_KEY" not in fake.applied("sig", "verify")["env"], "the rendered Task carries no credential"
    rendered = str(reconciler.run_dir("sig") / "verify" / "task.yaml")
    assert rendered in files_containing(tmp_path, "OUSAST_ARTIFACT_URL"), "the scan reads the rendered files it vouches for"
    assert files_containing(tmp_path, SECRET) == [], "no rendered task.yaml, state, log or applied record holds the value"


def test_a_model_bound_task_without_its_secret_fails_before_ax_sees_it(fake: Fake, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY")
    assert reconciler.run(write_run(tmp_path, "nokey"), ax=str(fake.ax)) == "failed"
    assert statuses("nokey") == {"repo-facts": "done", "verify": "failed", "agree": "pending"}
    reason = state_of("nokey")["tasks"]["verify"]["reason"]
    assert "DEEPSEEK_API_KEY" in reason and "deepseek-flash" in reason
    assert [name for _, name in fake.events("apply")] == ["repo-facts"], "verify is never applied without its credential"


def test_a_refused_start_fails_the_task_with_the_runners_answer(fake: Fake, tmp_path: Path) -> None:
    fake.router.codes["ref-repo-facts"] = (409, "task ref-repo-facts already ran and was delivered (done)")
    assert reconciler.run(write_run(tmp_path, "ref"), ax=str(fake.ax)) == "failed"
    reason = state_of("ref")["tasks"]["repo-facts"]["reason"]
    assert "HTTP 409" in reason and "already ran and was delivered" in reason
    assert len(fake.router.starts) == 1, "a refusal is final, not retried"
    assert [n for _, n in fake.events("delete")] == ["ref-repo-facts"], "ax delete follows a refused start"


def test_outcome_of_needs_a_delivered_summary() -> None:
    assert reconciler.outcome_of(None) == ("failed", "no summary.json delivered")
    assert reconciler.outcome_of({"status": "done", "units_done": 1, "units_total": 1}) == ("done", "")


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


def test_delivery_for_a_task_that_is_not_running_is_rejected(fake: Fake, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUSAST_TASK_TIMEOUT", "1")  # the rejected delivery is no delivery: the task times out
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
        '[[case]]\nid = "demo-sqli"\nrepo = "https://github.com/x/y"\nvulnerable = "' + "a" * 40 + '"\nfixed = "' + "b" * 40 + '"\n'
        'benign = { base = "' + "c" * 40 + '", tip = "' + "d" * 40 + '" }\n',
        encoding="utf-8",
    )
    written = workspaces(population, tmp_path / "out")
    labels = ("vulnerable", "fixed", "benign-base", "benign-tip")
    assert [p.name for p in written] == [f"demo-sqli-{label}.yaml" for label in labels]
    doc = yaml.safe_load(written[0].read_text(encoding="utf-8"))
    assert doc == {
        "apiVersion": "ax.io/v1alpha1",
        "kind": "Workspace",
        "metadata": {"name": "demo-sqli-vulnerable", "annotations": {"openultrasast.io/git-commits": "repo=" + "a" * 40}},
        "spec": {"git": [{"name": "repo", "repo": "https://github.com/x/y", "dir": "repo", "depth": 1}]},
    }
    from openultrasast.plane.manifests import load_manifests

    loaded = load_manifests(written).workspaces
    assert set(loaded) == {p.stem for p in written}
    assert loaded["demo-sqli-benign-tip"].pins == {"repo": "d" * 40}


def test_rendered_documents_carry_only_ax_fields(tmp_path: Path) -> None:
    """Req 1.1/1.4: whatever ``ax apply`` receives names only fields ax documents; annotations never leave."""
    (tmp_path / "repo-facts").mkdir()
    (tmp_path / "repo-facts" / "facts.json").write_text("{}", encoding="utf-8")
    run, manifests = reconciler.load_run(write_run(tmp_path, "fields"))
    docs = [d for entry in run.tasks for d in reconciler.render_task(run, entry, manifests, tmp_path, "http://h:1/")]
    assert {d["kind"] for d in docs} == {"Task", "Workspace", "Model"}
    for rendered in docs:
        where = f"{rendered['kind']}/{rendered['metadata']['name']}"
        assert set(rendered) == {"apiVersion", "kind", "metadata", "spec"}, where
        assert set(rendered["metadata"]) <= {"name", "atespace"}, where
        assert non_ax_fields(rendered["spec"], AX_FIELDS[rendered["kind"]], f"{where} spec") == []
        assert "openultrasast.io/" not in yaml.safe_dump(rendered["metadata"]), where


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
    from openultrasast.plane import doctor

    monkeypatch.setattr(doctor, "_sh", lambda *a: (True, "No resources found in ax-system namespace."))
    ok, text = doctor._pods_ready("ax-system", "kind-ousast")
    assert not ok and "no pods" in text
    monkeypatch.setattr(doctor, "_sh", lambda *a: (True, "a-1 1/1 Running 0 1m\nb-2 0/1 Completed 0 1m"))
    assert doctor._pods_ready("ns", "ctx") == (True, "2 pods ready")
    monkeypatch.setattr(doctor, "_sh", lambda *a: (True, "a-1 0/1 Running 0 1m"))
    assert doctor._pods_ready("ns", "ctx")[0] is False
