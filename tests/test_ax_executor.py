"""AX transport controls using an executable shim and an in-memory object store."""

import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

with pytest.MonkeyPatch.context() as patch:
    patch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "benchmarks/learn"))
    import engine_trace_ax as ax


IMAGE = "ghcr.io/norandom/ousast-engine-task@sha256:" + "a" * 64
PIN = {"repo": "owner/repo", "pin": "123", "units": [{"unit": "a", "supported": True}], "questions": {"a": {}}}


def archive(record):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        data = json.dumps(record).encode()
        info = tarfile.TarInfo("result.json")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class Store:
    def __init__(self, result=None):
        self.result = result
        self.objects = {}
        self.deleted = []
        self.expiries = []

    def _put(self, key, data):
        self.objects[key] = data

    def _get(self, key):
        return (self.result, None) if self.result else None

    def _delete(self, key):
        self.deleted.append(key)
        self.objects.pop(key, None)

    def presign_get(self, key, expiry):
        self.expiries.append(expiry.total_seconds())
        return "https://files.because-security.com/bucket/" + key + "?signature=secret"

    presign_put = presign_get


@pytest.fixture
def setup(tmp_path, monkeypatch):
    log = tmp_path / "calls.jsonl"
    shim = tmp_path / "fake-ax"
    shim.write_text("#!/bin/sh\nexec " + sys.executable + " " + str(tmp_path / "shim.py") + ' "$@"\n')
    shim.chmod(0o755)
    (tmp_path / "shim.py").write_text("""import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ["AX_LOG"]).open("a") as log:
    log.write(json.dumps({"args": args, "input": sys.stdin.read() if args[0] == "apply" else "",
        "kubeconfig": os.environ.get("KUBECONFIG")}) + "\\n")
if args[0] == "get" and os.environ.get("AX_GET_FAIL"):
    sys.exit(1)
if args[0] == "get":
    applies = [json.loads(line) for line in Path(os.environ["AX_LOG"]).read_text().splitlines()
        if json.loads(line)["args"][0] == "apply"]
    manifest = json.loads(applies[-1]["input"])
    phases = os.environ.get("AX_PHASE", "Running").split(",")
    phase = phases[min(len(applies) - 1, len(phases) - 1)]
    print(json.dumps({"items": [{"metadata": manifest["metadata"], "status": {
        "phase": phase, "workerIP": "10.0.0.2"}}] if phase != "Missing" else []}))
if args[0] == "delete" and os.environ.get("AX_DELETE_FAIL"):
    sys.exit(1)
""")
    monkeypatch.setenv("AX_LOG", str(log))
    monkeypatch.setenv("S3_ENDPOINT", "https://files.because-security.com")
    args = SimpleNamespace(
        ax_bin=str(shim), kubeconfig="/operator/kubeconfig", atespace="default", image=IMAGE, deadline=4, question_deadline=2
    )
    source = tmp_path / "case"
    source.mkdir()
    (source / "app.py").write_text("print(42)\n")
    output = tmp_path / "out"
    output.mkdir()
    now = [0]

    def pause(seconds):
        now[0] += seconds

    return args, source, output, log, pause, lambda: now[0]


def test_ax_executor_success_while_running_and_cleanup(setup):
    args, source, output, log, pause, clock = setup
    store = Store(archive({**PIN, "done": True}))
    executor = ax.AX(args, store, pause=pause, clock=clock)
    done, ip = executor.execute(source, output, PIN, "owner/repo/123")
    assert done.returncode == 0
    assert ip == "10.0.0.2"
    assert json.loads((output / "result.json").read_text())["done"]
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert calls[0]["args"] == ["apply", "-f", "-"]
    assert calls[-1]["args"][:2] == ["delete", "task"]
    assert calls[-1]["args"][-2:] == ["--atespace", args.atespace]
    assert all(c["kubeconfig"] == args.kubeconfig for c in calls)
    manifest = json.loads(calls[0]["input"])
    assert manifest["apiVersion"] == "ax.io/v1alpha1"
    assert manifest["kind"] == "Task"
    assert len(manifest["metadata"]["name"]) <= 49
    assert manifest["spec"]["image"] == IMAGE
    env = {e["name"]: e["value"] for e in manifest["spec"]["env"]}
    assert set(env) == {"SOURCE_URL", "QUESTIONS_URL", "RESULT_URL", "DEADLINE", "QUESTION_DEADLINE"}
    assert len(json.dumps(manifest["spec"]["env"]).encode()) < 32768
    assert "AWS" not in calls[0]["input"]
    assert env["SOURCE_URL"].split("?")[0].endswith("/source.dat")
    assert env["RESULT_URL"].split("?")[0].endswith("/result.dat")
    assert env["QUESTIONS_URL"].split("?")[0].endswith("/questions.json")
    assert {key.rsplit("/", 1)[-1] for key in store.deleted} == {"source.dat", "questions.json", "result.dat"}
    assert store.expiries == [604] * 3
    assert len(store.deleted) == 3 and not store.objects


def test_ax_executor_timeout_deletes_task(setup):
    args, source, output, log, pause, clock = setup
    store = Store()
    done, _ = ax.AX(args, store, pause=pause, clock=clock).execute(source, output, PIN, "pin")
    assert done is None
    assert json.loads(log.read_text().splitlines()[-1])["args"][:2] == ["delete", "task"]
    assert len(store.deleted) == 3


def test_ax_executor_failed_phase_deletes_task(setup, monkeypatch):
    args, source, output, log, pause, clock = setup
    monkeypatch.setenv("AX_PHASE", "Failed")
    done, _ = ax.AX(args, Store(), pause=pause, clock=clock).execute(source, output, PIN, "pin")
    assert done.returncode == 1 and done.stderr == "AX sandbox failed twice"
    attempts = json.loads((output / "ax_attempts.json").read_text())
    assert [a["phase"] for a in attempts] == ["Failed", "Failed"]
    assert json.loads(log.read_text().splitlines()[-1])["args"][:2] == ["delete", "task"]


@pytest.mark.parametrize("phase", ["Failed", "Missing"])
def test_ax_executor_retries_with_new_name_links_and_backoff(setup, monkeypatch, phase):
    args, source, output, log, pause, clock = setup
    monkeypatch.setenv("AX_PHASE", phase + ",Succeeded")
    store = Store()
    store._get = lambda key: (archive({**PIN, "done": True}), None) if "/attempt-1/" in key else None
    pauses = []

    def backoff(seconds):
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        assert calls[-1]["args"][:2] == ["delete", "task"]
        pauses.append(seconds)
        pause(seconds)

    done, _ = ax.AX(args, store, pause=backoff, clock=clock).execute(source, output, PIN, "x" * 100)
    assert done.returncode == 0
    record = json.loads((output / "result.json").read_text())
    attempts = record["ax_attempts"]
    assert record["done"] and [a["phase"] for a in attempts] == [phase, "Succeeded"]
    assert len({a["name"] for a in attempts}) == 2
    assert all(a["name"].startswith("ousast-engine-") and len(a["name"]) <= 49 and a["seconds"] >= 0 for a in attempts)
    assert pauses == [10]
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    manifests = [json.loads(c["input"]) for c in calls if c["args"][0] == "apply"]
    links = [{e["name"]: e["value"] for e in m["spec"]["env"]} for m in manifests]
    assert all(links[0][key] != links[1][key] for key in ("SOURCE_URL", "QUESTIONS_URL", "RESULT_URL"))
    assert len(store.expiries) == 6 and len(store.deleted) == 6


@pytest.mark.parametrize("late", [False, True])
def test_ax_executor_failed_result_is_never_retried(setup, monkeypatch, late):
    args, source, output, log, pause, clock = setup
    monkeypatch.setenv("AX_PHASE", "Failed")
    store = Store(archive({**PIN, "done": True, "status": "failed"}))
    original_get = store._get
    reads = []

    def get(key):
        reads.append(key)
        return None if late and len(reads) == 1 else original_get(key)

    store._get = get
    done, _ = ax.AX(args, store, pause=pause, clock=clock).execute(source, output, PIN, "pin")
    record = json.loads((output / "result.json").read_text())
    assert done.returncode == 0 and record["status"] == "failed"
    assert len(record["ax_attempts"]) == 1
    assert sum(json.loads(line)["args"][0] == "apply" for line in log.read_text().splitlines()) == 1


@pytest.mark.parametrize("mode", ["ax", "mixed-ax"])
def test_ax_sandbox_failed_twice_scheduler(setup, monkeypatch, mode):
    with monkeypatch.context() as patch:
        patch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "benchmarks/learn"))
        import engine_trace as trace

    args, source, output, log, pause, clock = setup
    monkeypatch.setenv("AX_PHASE", "Failed")
    args.executor, args.parallel, args.out, args.docker_image = mode, 1, output, "vm-image"
    args.ax_dispatcher = ax.AX(args, Store(), pause=pause, clock=clock)
    monkeypatch.setattr(trace, "prepare_questions", lambda *_: PIN["questions"])

    class Inputs:
        def materialize(self, pin, target):
            target.mkdir()
            data = (source / "app.py").read_bytes()
            (target / "app.py").write_bytes(data)
            return {"files": 1, "bytes": len(data)}

    original_run = subprocess.run
    docker_calls = []

    def run(command, **kwargs):
        if command[0] == args.ax_bin:
            return original_run(command, **kwargs)
        assert command[:2] in (["docker", "run"], ["docker", "rm"])
        docker_calls.append(command)
        if command[1] == "run":
            assert command[command.index("--heap-profile") + 1] == "vm"
            assert "vm-image" in command
            target = Path(next(arg.removesuffix(":/out") for arg in command if arg.endswith(":/out")))
            prepared = json.loads((target / "pin.json").read_text())
            trace.write_json(
                target / "result.json",
                {**prepared, "done": True, "units": [trace.unit_record(u, "asked-nothing") for u in prepared["units"]]},
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    assert trace.run_plan([PIN], source, {}, Inputs(), args) is (mode == "ax")
    record = json.loads((output / trace.pin_name(PIN)).read_text())
    assert [a["phase"] for a in record["ax_attempts"]] == ["Failed", "Failed"]
    assert sum(json.loads(line)["args"][0] == "apply" for line in log.read_text().splitlines()) == 2
    if mode == "mixed-ax":
        assert [command[1] for command in docker_calls] == ["run", "rm"]
        assert record["executor"] == "docker" and record["fallback"] == "vm-sandbox"
        assert record["units"][0]["status"] == "asked-nothing"
        assert record["ax_attempt"]["ax_attempts"] == record["ax_attempts"]
    else:
        assert not docker_calls
        assert record["units"][0]["status"] == "failed"
        assert record["units"][0]["reason"] == "AX sandbox failed twice"


def test_ax_executor_delete_failure_is_fatal_and_still_cleans_objects(setup, monkeypatch):
    args, source, output, _, pause, clock = setup
    monkeypatch.setenv("AX_DELETE_FAIL", "1")
    store = Store(archive({**PIN, "done": True}))
    with pytest.raises(RuntimeError, match="cleanup"):
        ax.AX(args, store, pause=pause, clock=clock).execute(source, output, PIN, "pin")
    assert len(store.deleted) == 3


@pytest.mark.parametrize("endpoint", ["http://files.because-security.com", "https://127.0.0.1", "https://[::1]", "https://localhost"])
def test_ax_executor_endpoint_rejected_before_store_open(setup, monkeypatch, endpoint):
    args = setup[0]
    monkeypatch.setenv("S3_ENDPOINT", endpoint)
    monkeypatch.setattr(ax, "open_store", lambda: pytest.fail("store opened before validation"))
    with pytest.raises(ValueError, match="egress policy"):
        ax.AX(args)


def test_ax_executor_rejects_tag_and_large_env(setup):
    args = setup[0]
    urls = {key: "https://files.because-security.com/" for key in ("SOURCE_URL", "QUESTIONS_URL", "RESULT_URL")}
    args.image = "image:latest"
    with pytest.raises(ValueError, match="digest"):
        ax.task_manifest("name", args, urls)
    args.image = IMAGE
    urls["SOURCE_URL"] += "x" * 32768
    with pytest.raises(ValueError, match="32 KB"):
        ax.task_manifest("name", args, urls)


def test_ax_executor_rejects_mismatched_result(setup):
    args, source, output, _, pause, clock = setup
    store = Store(archive({"done": True, "units": []}))
    done, _ = ax.AX(args, store, pause=pause, clock=clock).execute(source, output, PIN, "pin")
    assert done.returncode == 1
    assert not (output / "result.json").exists()


def test_ax_executor_table_worker_ip():
    assert ax.task_state("NAME ATESPACE PHASE WORKER-IP\nours default Running 10.2.3.4\n", "ours") == ("Running", "10.2.3.4")


def test_ax_executor_missing_requires_readable_task_list():
    assert ax.task_state('{"items": []}', "ours") == ("Missing", None)
    assert ax.task_state("NAME ATESPACE PHASE WORKER-IP\n", "ours") == ("Missing", None)
    assert ax.task_state("", "ours") == ("", None)
    assert ax.task_state("temporarily unavailable", "ours") == ("", None)


def test_ax_executor_status_query_failure_is_not_disappearance(setup, monkeypatch):
    args, source, output, log, pause, clock = setup
    monkeypatch.setenv("AX_GET_FAIL", "1")
    done, _ = ax.AX(args, Store(), pause=pause, clock=clock).execute(source, output, PIN, "pin")
    assert done is None
    assert sum(json.loads(line)["args"][0] == "apply" for line in log.read_text().splitlines()) == 1


def test_ax_executor_entry_download_failure_restores_host_units(setup):
    args, source, output, _, pause, clock = setup
    store = Store(archive({"done": True, "status": "failed", "reason": "questions download failed", "units": []}))
    done, _ = ax.AX(args, store, pause=pause, clock=clock).execute(source, output, PIN, "pin")
    assert done.returncode == 0
    unit = json.loads((output / "result.json").read_text())["units"][0]
    assert unit["unit"] == "a" and unit["status"] == "failed"
    assert unit["reason"] == "questions download failed"


def test_ax_executor_presign_host_must_match_egress_policy(setup):
    args, source, output, log, pause, clock = setup
    store = Store()
    store.presign_put = lambda key, expiry: "https://another-store.example/result"
    done, _ = ax.AX(args, store, pause=pause, clock=clock).execute(source, output, PIN, "pin")
    assert done.returncode == 1 and "egress policy" in done.stderr
    assert not log.exists()
    assert len(store.deleted) == 3


def test_ax_executor_get_failure_does_not_lose_result(setup, monkeypatch):
    args, source, output, _, pause, clock = setup
    monkeypatch.setenv("AX_GET_FAIL", "1")
    done, _ = ax.AX(args, Store(archive({**PIN, "done": True})), pause=pause, clock=clock).execute(source, output, PIN, "pin")
    assert done.returncode == 0


def test_ax_executor_absent_worker_ip():
    assert ax.task_state("NAME ATESPACE PHASE ACTOR WORKER-IP AGE\nours other Pending actor <none> 1s\n", "ours") == ("Pending", None)


def test_ax_executor_late_store_result_times_out(setup):
    args, source, output, log, pause, clock = setup
    store = Store(archive({**PIN, "done": True}))
    original_get = store._get

    def late_get(key):
        pause(args.deadline)
        return original_get(key)

    store._get = late_get
    done, _ = ax.AX(args, store, pause=pause, clock=clock).execute(source, output, PIN, "pin")
    assert done is None
    assert not (output / "result.json").exists()
    assert json.loads(log.read_text().splitlines()[-1])["args"][:2] == ["delete", "task"]


def test_ax_executor_late_status_times_out(setup):
    args, source, output, _, pause, clock = setup
    executor = ax.AX(args, Store(archive({**PIN, "done": True})), pause=pause, clock=clock)
    original_ax = executor.ax

    def late_ax(*command, **kwargs):
        result = original_ax(*command, **kwargs)
        if command[0] == "get":
            pause(args.deadline)
        return result

    executor.ax = late_ax
    done, _ = executor.execute(source, output, PIN, "pin")
    assert done is None
    assert not (output / "result.json").exists()


def test_ax_executor_blocking_store_read_cannot_delay_task_deletion(setup):
    import threading
    import time

    args, source, output, log, _, _ = setup
    args.deadline = 0.15
    release = threading.Event()
    store = Store()
    store._get = lambda key: release.wait(5)
    started = time.monotonic()
    try:
        done, _ = ax.AX(args, store).execute(source, output, PIN, "pin")
        # A result deadline is a failed attempt that names its reason; the lane treats it like None.
        assert done is None or (done.returncode and "deadline" in done.stderr)
        assert time.monotonic() - started < 2
        assert json.loads(log.read_text().splitlines()[-1])["args"][:2] == ["delete", "task"]
    finally:
        release.set()


def test_ax_task_names_reserve_watcher_prefix_and_fit_actor_limit(setup):
    args, source, output, log, pause, clock = setup
    executor = ax.AX(args, Store(archive({**PIN, "done": True})), pause=pause, clock=clock)
    # Sanitization and truncation must not collapse distinct pins.
    for pin_id in ["A/B", "a-b", "x" * 100 + "1", "x" * 100 + "2", "☃"]:
        done, _ = executor.execute(source, output, PIN, pin_id)
        assert done.returncode == 0
    manifests = [json.loads(call["input"]) for line in log.read_text().splitlines() if (call := json.loads(line))["args"][0] == "apply"]
    names = [manifest["metadata"]["name"] for manifest in manifests]
    assert len(set(names)) == 5
    for manifest, name in zip(manifests, names, strict=True):
        assert manifest["kind"] == "Task"
        assert manifest["metadata"]["atespace"] == "default"
        assert name.startswith("ousast-engine-")
        assert len(name.encode()) <= 49
        assert len((name + "-tmpl-12345678").encode()) <= 63
