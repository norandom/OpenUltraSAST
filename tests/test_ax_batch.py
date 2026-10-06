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


@pytest.mark.parametrize("failure", [None, TimeoutError, KeyboardInterrupt])
def test_search_executor_task_links_and_cleanup(monkeypatch, failure):
    from types import SimpleNamespace

    from benchmarks.ax.batch import SearchExecutorTask

    class Store:
        def __init__(self):
            self.deleted = []
            self.uploads = []

        def _put(self, key, data):
            self.uploads.append((key, data))

        def presign_get(self, key, expires):
            return "https://files.example/" + key + "?get"

        def presign_put(self, key, expires):
            return "https://files.example/" + key + "?put"

        def _delete(self, key):
            self.deleted.append(key)

    calls = []
    lane = SimpleNamespace(
        store=Store(),
        host="files.example",
        args=SimpleNamespace(atespace="default"),
        workload=workload(),
        ax=lambda *a, **kw: calls.append((a, kw)),
        clock=__import__("time").monotonic,
        pause=lambda _: None,
    )
    from contextlib import nullcontext

    with pytest.raises(failure) if failure else nullcontext(), SearchExecutorTask(lane, b"archive", deadline=60) as session:
        assert session.name.startswith("ousast-engine-search-exec-")
        assert session.client.command_url.endswith("?put")
        doc = calls[0][1]["manifest"]
        assert doc["spec"]["command"][2] == "openultrasast.search.executor"
        assert {r["name"] for r in doc["spec"]["env"]} == {
            "COMMAND_GET_URL",
            "EXECUTOR_RESULT_PUT_URL",
            "REPO_URL",
            "PREPARED_PUT_URL",
            "PREPARED_PART_URLS",
        }
        assert "API_KEY" not in json.dumps(doc)
        if failure:

            def submit(*args, **kwargs):
                raise failure("transport interrupted")

            monkeypatch.setattr(session.client, "submit", submit)
            session.client.submit("list_files", {})
    assert calls[-1][0][:2] == ("delete", "task")
    from openultrasast.search.verify_task import MAX_PARTS

    assert len(lane.store.deleted) == 4 + MAX_PARTS


def test_capacity_backpressure_retries_same_manifest_until_deadline(tmp_path, monkeypatch):
    import subprocess
    from types import SimpleNamespace

    from benchmarks.ax.batch import AXLane

    now, applies, deletes = [0.0], [], []

    class Store:
        def _put(self, *args):
            pass

        def _get(self, *args):
            return (b"{}", None)

        def _delete(self, *args):
            pass

        def presign_get(self, key, expiry):
            return "https://files.example/" + key

        presign_put = presign_get

    busy = [True]

    def run(argv, **kwargs):
        if argv[0] == "kubectl":
            return subprocess.CompletedProcess(argv, 0, json.dumps({"items": [{"status": {"phase": "Running"}}]}), "")
        if argv[1] == "apply":
            applies.append(kwargs["input"])
            return subprocess.CompletedProcess(argv, 1 if busy[0] else 0, "", "no free workers available secret-url")
        if argv[1] == "delete":
            deletes.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setenv("S3_ENDPOINT", "https://files.example")
    monkeypatch.setattr(subprocess, "run", run)

    def pause(seconds):
        assert 0 < seconds <= 30
        now[0] += seconds
        if now[0] > 30:
            busy[0] = False

    def validate(data, output):
        (output / "result.json").write_text('{"status":"ok"}')

    lane = AXLane(
        SimpleNamespace(ax_bin="ax", kubeconfig=None, atespace="default"),
        Workload(IMAGE, workload().url_env, 100, validate),
        Store(),
        pause=pause,
        clock=lambda: now[0],
    )
    assert lane(item(), tmp_path, 0)["status"] == "ok"
    assert len(applies) >= 3 and len(set(applies)) == 1
    assert len(deletes) == len(applies)
    busy[0] = True
    lane.pause = lambda seconds: now.__setitem__(0, now[0] + seconds)
    deletes.clear()
    result = lane(item(), tmp_path, 1)
    assert result["status"] == "capacity_timeout"
    assert deletes
    calls = []

    def no_vm(*args):
        pytest.fail("capacity must not fall back")

    def capacity(*args):
        calls.append(1)
        return result

    assert dispatch([item()], workload(), tmp_path / "dispatch", {"ax": capacity, "docker": no_vm}, lanes=("ax", "docker"), overflow=False)
    assert len(calls) == 1


def test_shared_capacity_across_workloads(tmp_path, monkeypatch):
    import subprocess
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace

    from benchmarks.ax.batch import AXLane

    monkeypatch.setenv("S3_ENDPOINT", "https://files.example")
    active, peak = [0], [0]
    lock = threading.Lock()

    def execute(item, output, attempt, attempts):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.02)
        with lock:
            active[0] -= 1
        (output / "result.json").write_text('{"status":"ok"}')
        return subprocess.CompletedProcess([], 0), None

    lanes = [AXLane(SimpleNamespace(), workload(), object()) for _ in range(6)]
    paths = [tmp_path / str(i) for i in range(6)]
    for lane, path in zip(lanes, paths, strict=True):
        path.mkdir()
        lane._execute_attempt = execute
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda pair: pair[0](item(), pair[1], 0), zip(lanes, paths, strict=True)))
    assert all(r["status"] == "ok" for r in results)
    assert peak[0] == 2


@pytest.mark.parametrize("phases", [[], ["Pending", "Pending"], ["Running", "Running"]])
def test_capacity_health_uses_lane_runner_and_throttles(monkeypatch, phases):
    import subprocess
    from types import SimpleNamespace

    from benchmarks.ax import batch

    now, checks, applies = [0.0], [], []
    monkeypatch.setenv("S3_ENDPOINT", "https://files.example")

    def jitter(low, high):
        assert (low, high) == ((2, 5) if now[0] < 60 else (15, 30))
        return 5 if high == 5 else 20

    monkeypatch.setattr(batch.random, "uniform", jitter)

    def runner(argv, **kwargs):
        if argv[0] == "kubectl":
            checks.append(now[0])
            assert argv == ["kubectl", "-n", "ax-workers", "get", "pods", "-o", "json"]
            assert kwargs["env"]["KUBECONFIG"] == "/tmp/test-kubeconfig"
            assert kwargs["timeout"] <= 10
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({"items": [{"metadata": {"name": "private-name"}, "status": {"phase": phase}} for phase in phases]}), ""
            )
        if argv[1] == "apply":
            applies.append(kwargs["input"])
            return subprocess.CompletedProcess(argv, 1, "", "no free workers available")
        return subprocess.CompletedProcess(argv, 0, "", "")

    lane = batch.AXLane(
        SimpleNamespace(ax_bin="ax", kubeconfig="/tmp/test-kubeconfig", atespace="default"),
        workload(),
        store=object(),
        runner=runner,
        clock=lambda: now[0],
        pause=lambda seconds: now.__setitem__(0, now[0] + seconds),
    )
    expected = batch.CapacityDeadline if "Running" in phases else batch.ClusterUnavailable
    with pytest.raises(expected) as caught:
        batch.apply_when_available(lane, {"metadata": {"name": "same-task"}}, 190)
    assert checks == ([60, 120, 180] if "Running" in phases else [60])
    assert len(set(applies)) == 1
    assert "private-name" not in str(caught.value)
    assert str(caught.value)


def test_executor_slot_deadline_has_reason(monkeypatch):
    from types import SimpleNamespace

    from benchmarks.ax import batch

    monkeypatch.setattr(batch, "AX_SLOTS", SimpleNamespace(acquire=lambda **kw: False))
    with pytest.raises(batch.CapacityDeadline, match="no free workers available before deadline"):
        batch.SearchExecutorTask(object(), b"archive").__enter__()


def test_search_preparation_failure_retains_command_record():
    import time
    from types import SimpleNamespace

    from benchmarks.ax.batch import SearchExecutorTask
    from openultrasast.search.task_storage import CommandFailure

    task = object.__new__(SearchExecutorTask)
    task.end = time.monotonic() + 60
    task.client = SimpleNamespace(
        submit=lambda *args, **kwargs: {
            "status": "could_not_build",
            "phase": "build",
            "exit_code": 8,
            "reason": "CommandFailure: exit code 8",
            "stderr": "dependency missing token=hidden",
        }
    )
    with pytest.raises(CommandFailure) as caught:
        task.prepare({})
    assert caught.value.phase == "build" and caught.value.exit_code == 8
    assert "dependency missing" in caught.value.stderr and "hidden" not in caught.value.stderr


def test_verifier_lane_uploads_parts_and_task_reassembles(tmp_path, monkeypatch):
    import io
    import subprocess
    from types import SimpleNamespace

    from benchmarks.ax.batch import AXLane
    from openultrasast.search import executor, verify_task

    monkeypatch.setattr(verify_task, "MAX_PART_BYTES", 100)
    monkeypatch.setenv("S3_ENDPOINT", "https://files.example")
    source = tmp_path / "source"
    source.mkdir()
    (source / "input").write_bytes(bytes(range(256)) * 4)
    blob = verify_task.pack_checkout(source)
    objects, puts = {}, []

    class Store:
        def _put(self, key, data):
            objects["https://files.example/" + key] = data

        def _get(self, key):
            return b"completed", None

        def _delete(self, key):
            objects.pop("https://files.example/" + key, None)

        def presign_get(self, key, expiry):
            return "https://files.example/" + key

        presign_put = presign_get

    def put(self, url, block, timeout):
        assert len(block) <= 100
        puts.append(url)
        objects[url] = block

    monkeypatch.setattr(executor.URLTransport, "put", put)
    work = Workload(IMAGE, frozenset({"VERIFY_INPUT_URL", "RESULT_URL"}), 10, lambda *args: None, kind="search-verify")
    lane = AXLane(SimpleNamespace(ax_bin="fake", kubeconfig=None, atespace="default"), work, Store())

    def ax(*args, **kwargs):
        if args[0] == "apply":
            env = {value["name"]: value["value"] for value in kwargs["manifest"]["spec"]["env"]}
            assert set(env) == {"VERIFY_INPUT_URL", "RESULT_URL"}
            restored = io.BytesIO()
            verify_task.assemble_parts(objects[env["VERIFY_INPUT_URL"]], restored, lambda part: objects[part["url"]])
            assert restored.getvalue() == blob
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(lane, "ax", ax)
    request = Item("verify", {"VERIFY_INPUT_URL": blob}, "result.json", ("python3",), {}, "digest")
    output, _ = lane._execute_attempt(request, tmp_path, 0, [])
    assert output.returncode == 0, output
    assert len(puts) > 1
    assert not objects  # fragment cleanup is part of the task lifecycle


@pytest.mark.parametrize("corrupt", [False, True])
def test_executor_prepare_checks_part_digest(monkeypatch, corrupt):
    import hashlib
    import io
    import time
    from types import SimpleNamespace

    from benchmarks.ax.batch import SearchExecutorTask
    from openultrasast.search import verify_task

    monkeypatch.setattr(verify_task, "MAX_PART_BYTES", 100)
    blob = b"compressed bytes" * 30
    objects = {}
    lane = SimpleNamespace(store=SimpleNamespace(_get=lambda key: (objects[key], None)))
    task = SearchExecutorTask(lane, b"checkout")
    metadata = verify_task.upload_parts(io.BytesIO(blob), objects.__setitem__, task.keys[4:])
    objects[task.keys[3]] = metadata
    if corrupt:
        objects[task.keys[4]] = b"corrupt"
    task.end = time.monotonic() + 60
    task.client = SimpleNamespace(submit=lambda *args, **kwargs: {"status": "ok", "sha256": hashlib.sha256(metadata).hexdigest()})
    if corrupt:
        with pytest.raises(ValueError, match="part digest mismatch"):
            task.prepare({})
    else:
        assert task.prepare({}) == blob
