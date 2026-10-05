"""Offline shared dispatcher contracts."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.ax.batch import Item, Workload, dispatch, manifest

IMAGE = "registry/task@sha256:" + "a" * 64


def item(identity="one"):
    return Item(identity, {"SPEC_URL": b"{}"}, "result.dat", ("python3", "/entry.py"), {}, identity)


def workload():
    return Workload(IMAGE, frozenset({"SPEC_URL", "RESULT_URL"}), 900, lambda data, output: {})


def test_manifest_contract():
    doc = manifest(
        "ousast-engine-replay-abc",
        workload(),
        item(),
        {"SPEC_URL": "https://files.example/spec.dat", "RESULT_URL": "https://files.example/result.dat"},
    )
    assert {v["name"] for v in doc["spec"]["env"]} == {"SPEC_URL", "RESULT_URL"}
    with pytest.raises(ValueError):
        manifest("bad", workload(), item(), {})
    bad = item()
    bad.extra_env["AWS_SECRET_ACCESS_KEY"] = "secret"
    with pytest.raises(ValueError):
        manifest(
            "ousast-engine-test",
            workload(),
            bad,
            {"SPEC_URL": "https://files.example/spec.dat", "RESULT_URL": "https://files.example/result.dat"},
        )


def test_dispatch_retry_fallback_resume_stop(tmp_path):
    calls = []

    def lane(it, output, attempt):
        calls.append(("ax", attempt))
        return {"status": "sandbox_failure"}

    def vm(it, output, attempt):
        calls.append(("docker", attempt))
        return {"status": "ok"}

    assert not dispatch([item()], workload(), tmp_path, {"ax": lane, "docker": vm}, lanes=("ax", "ax", "docker"), overflow=False)
    assert [c[0] for c in calls] == ["ax", "ax", "docker"]
    assert not dispatch([item()], workload(), tmp_path, {"ax": lane, "docker": vm})
    assert len(calls) == 3
    (tmp_path / "STOP").touch()
    dispatch([item("two")], workload(), tmp_path, {"ax": lane, "docker": vm})
    assert len(calls) == 3
    assert json.loads((tmp_path / "progress.json").read_text())["pins_in_flight"] == 0


def test_cleanup_failure_halts(tmp_path):
    calls = []

    def broken(it, output, attempt):
        calls.append(it.id)
        raise RuntimeError("cleanup failed")

    with pytest.raises(RuntimeError, match="cleanup"):
        dispatch([item("one"), item("two")], workload(), tmp_path, {"ax": broken}, lanes=("ax",))
    assert calls == ["one"]


def test_ax_lane_fake_cli_and_store(tmp_path, monkeypatch):
    import subprocess
    from types import SimpleNamespace

    from benchmarks.ax.batch import AXLane

    calls = []

    class Store:
        objects = {}

        def _put(self, key, data):
            self.objects[key] = data

        def _get(self, key):
            return (b"completed", None)

        def _delete(self, key):
            self.objects.pop(key, None)

        def presign_get(self, key, expiry):
            assert key.endswith(".dat")
            return "https://files.example/" + key + "?signature=secret"

        presign_put = presign_get

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[1] == "get":
            name = json.loads(calls[0][1]["input"])["metadata"]["name"]
            return subprocess.CompletedProcess(command, 0, json.dumps({"metadata": {"name": name}, "status": {"phase": "Running"}}), "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setenv("S3_ENDPOINT", "https://files.example")

    def validate(data, output):
        assert data == b"completed"
        (output / "result.json").write_text('{"status":"ok"}')

    work = Workload(IMAGE, frozenset({"SPEC_URL", "RESULT_URL"}), 10, validate)
    lane = AXLane(SimpleNamespace(ax_bin="fake-ax", kubeconfig=None, atespace="default"), work, Store())
    assert lane(item(), tmp_path, 0)["status"] == "ok"
    doc = json.loads(calls[0][1]["input"])
    assert doc["metadata"]["name"].startswith("ousast-engine-") and len(doc["metadata"]["name"]) <= 49
    assert {e["name"] for e in doc["spec"]["env"]} == {"SPEC_URL", "RESULT_URL"}
    assert calls[-1][0][1:3] == ["delete", "task"]
    assert not lane.store.objects


def test_bounded_lanes_oom_and_instrument_retry(tmp_path):
    import threading
    import time
    from collections import Counter

    active, peak, calls = Counter(), Counter(), []
    lock = threading.Lock()

    def execute(lane):
        def run(it, output, attempt):
            with lock:
                calls.append((it.id, lane, attempt))
                active[lane] += 1
                peak[lane] = max(peak[lane], active[lane])
            time.sleep(0.01)
            with lock:
                active[lane] -= 1
            return {"status": "oom" if lane == "ax" else "ok"}

        return run

    assert not dispatch([item(str(i)) for i in range(9)], workload(), tmp_path, {"ax": execute("ax"), "docker": execute("docker")})
    assert peak["ax"] == 2 and peak["docker"] == 1
    assert all(attempt == 0 for _, _, attempt in calls)
    attempts = []

    def failed(it, output, attempt):
        attempts.append(attempt)
        return {"status": "instrument_failure"}

    assert dispatch([item("fail")], workload(), tmp_path, {"ax": failed}, lanes=("ax",))
    assert attempts == [0, 1]


@pytest.mark.parametrize("step", ["reason", "explore", "verify"])
def test_search_environment(step):
    it = item()
    it.extra_env = {"SEARCH_STEP": step, "SEARCH_ID": "search-1", "SEARCH_TASK_ID": "task-2"}
    urls = {"SPEC_URL": "https://files.example/spec.dat", "RESULT_URL": "https://files.example/result.dat"}
    doc = manifest("ousast-engine-search-1", workload(), it, urls)
    assert {"name": "SEARCH_STEP", "value": step} in doc["spec"]["env"]
    for key, value in [
        ("SEARCH_STEP", "shell"),
        ("SEARCH_ID", "https://secret"),
        ("SEARCH_TASK_ID", "x\nTOKEN=y"),
        ("MODEL_API_KEY", "secret"),
    ]:
        it.extra_env = {key: value}
        with pytest.raises(ValueError):
            manifest("ousast-engine-search-1", workload(), it, urls)
