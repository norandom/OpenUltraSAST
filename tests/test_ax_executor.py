"""AX transport controls using an executable shim and an in-memory object store."""

import io
import json
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
    manifest = json.loads(json.loads(Path(os.environ["AX_LOG"]).read_text().splitlines()[0])["input"])
    print(json.dumps({"items": [{"metadata": manifest["metadata"], "status": {
        "phase": os.environ.get("AX_PHASE", "Running"), "workerIP": "10.0.0.2"}}]}))
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
    assert done.returncode == 1 and "Failed" in done.stderr
    assert json.loads(log.read_text().splitlines()[-1])["args"][:2] == ["delete", "task"]


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
        assert done is None
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
