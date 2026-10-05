"""No-network end-to-end executor smoke, through the real mailbox client."""

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.ax import batch
from benchmarks.search import executor_smoke as smoke
from openultrasast.search.executor import Command, InProcessExecutor


class Store:
    def __init__(self, executor):
        self.executor, self.objects = executor, {}

    def _put(self, key, data):
        self.objects[key] = data

    def _delete(self, key):
        self.objects.pop(key, None)

    def presign_get(self, key, expires):
        return "https://files.example/" + key

    presign_put = presign_get

    def put(self, url, data, timeout):
        self.result = json.dumps(self.executor.execute(Command(**json.loads(data)))).encode()

    def get(self, url, timeout):
        return self.result


class Executor(InProcessExecutor):
    empty = False
    empty_install = False

    def _task_run(self, argv, timeout, limits):
        if argv[:2] == ["sh", "-ec"]:
            if not self.empty:
                (self.repo / "README.md").write_text("test input")
                (self.repo / "requirements.txt").write_text("")
            return dict(exit_code=0, stdout="cloned", stderr="", scratch_peak_bytes=4096, stdout_bytes=6, stderr_bytes=0)
        if "pip" in argv:
            return dict(
                exit_code=0,
                stdout="" if self.empty_install else "installed",
                stderr="",
                scratch_peak_bytes=8192,
                stdout_bytes=0 if self.empty_install else 9,
                stderr_bytes=0,
            )
        return super()._task_run(argv, timeout, limits)


def setup(tmp_path, monkeypatch):
    executor = Executor(tmp_path, task_boundary=True)
    store = Store(executor)
    monkeypatch.setattr("openultrasast.search.executor.URLTransport", lambda: store)
    events = []
    lane = SimpleNamespace(
        store=store,
        host="files.example",
        args=SimpleNamespace(atespace="default"),
        workload=batch.Workload("image@sha256:" + "a" * 64, frozenset(), 900, None),
        clock=time.monotonic,
    )

    def ax(*args, **kwargs):
        events.append(args[0])
        if args[0] == "apply":
            doc = kwargs["manifest"]
            assert doc["metadata"]["name"].startswith("ousast-engine-search-exec-")
            assert {x["name"] for x in doc["spec"]["env"]} == {"REPO_URL", "COMMAND_GET_URL", "EXECUTOR_RESULT_PUT_URL", "PREPARED_PUT_URL"}

    lane.ax = ax
    return executor, lane, events


def test_smoke_mailbox_end_to_end(tmp_path, monkeypatch):
    executor, lane, events = setup(tmp_path, monkeypatch)
    record = smoke.run_smoke(lane, "https://github.com/example/project", "a" * 40)
    assert record["status"] == "ok"
    assert executor.stopped
    assert events == ["apply", "delete"]
    assert not lane.store.objects
    assert [r["step"] for r in record["commands"]] == ["clone", "list_files", "read_file", "grep", "install", "trivial", "stop"]
    assert record["scratch_peak_bytes"] >= 8192
    read = next(r for r in record["commands"] if r["step"] == "read_file")
    assert read["input_bytes"] == 10
    assert all(r["wall_seconds"] >= 0 and r["output_bytes"] >= 0 for r in record["commands"])


@pytest.mark.parametrize("kind,reason", [("empty", "clone yielded zero files"), ("empty_install", "empty fast install")])
def test_instrument_failure_and_cleanup(tmp_path, monkeypatch, kind, reason):
    executor, lane, events = setup(tmp_path, monkeypatch)
    setattr(executor, kind, True)
    record = smoke.run_smoke(lane, "https://github.com/example/project", "a" * 40)
    assert record["status"] == "instrument_failure"
    assert reason in record["reason"]
    assert events[-1] == "delete"
    assert not lane.store.objects


@pytest.mark.parametrize(
    "files,recipe", [(["package.json"], "npm"), (["composer.json"], "composer"), (["pom.xml"], "maven"), (["pyproject.toml"], "pip")]
)
def test_recipes(files, recipe):
    assert smoke.install_recipe(files)[0] == recipe


def test_real_executor_measurements(tmp_path):
    (tmp_path / "input").write_bytes(b"12345")
    result = InProcessExecutor(tmp_path, task_boundary=True).submit("run", {"command": ["python3", "-c", "print(1)"]})
    assert result["exit_code"] == 0
    assert result["stdout_bytes"] == 2
    assert result["scratch_peak_bytes"] >= 5
    assert result["wall_seconds"] > 0


def test_docker_managed_task_uses_docker_and_no_heap_flag(tmp_path, monkeypatch):
    import subprocess

    executor = Executor(tmp_path, task_boundary=True)
    store = Store(executor)
    monkeypatch.setattr("openultrasast.search.executor.URLTransport", lambda: store)
    monkeypatch.setenv("S3_ENDPOINT", "https://files.example")
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    lane = batch.DockerLane(
        SimpleNamespace(atespace="default"), batch.Workload("image@sha256:" + "a" * 64, frozenset(), 900, None), store=store, runner=runner
    )
    record = smoke.run_smoke(lane, "https://github.com/example/project", "a" * 40)
    assert record["status"] == "ok"
    assert [a[1] for a in calls] == ["image", "run", "rm"]
    assert "--heap-profile" not in calls[1]
    assert calls[2][2] == "-f"


def test_apply_exception_still_deletes(tmp_path, monkeypatch):
    executor, lane, events = setup(tmp_path, monkeypatch)

    def failing(*args, **kwargs):
        events.append(args[0])
        if args[0] == "apply":
            raise OSError("do not expose https://secret.example/token")

    lane.ax = failing
    result = smoke.run_smoke(lane, "https://github.com/example/project", "a" * 40)
    assert result["status"] == "instrument_failure"
    assert events == ["apply", "delete"]
    assert "secret.example" not in json.dumps(result)


def test_smoke_retains_sanitized_command_failure(tmp_path, monkeypatch):
    executor, lane, events = setup(tmp_path, monkeypatch)
    original = executor._task_run

    def fail(argv, timeout, limits):
        if "pip" in argv:
            return {
                "exit_code": 17,
                "stderr": "project failed: Bearer hidden https://host/project?q=secret",
                "stdout": "",
                "phase": "run",
                "reason": "CommandFailure: exit code 17",
            }
        return original(argv, timeout, limits)

    monkeypatch.setattr(executor, "_task_run", fail)
    record = smoke.run_smoke(lane, "https://github.com/example/project", "a" * 40)
    row = record["commands"][-1]
    assert row["exit_code"] == 17 and row["phase"] == "run"
    assert "CommandFailure" in row["reason"]
    assert all(word not in json.dumps(record) for word in ("hidden", "secret", "project", "example"))
    assert events == ["apply", "delete"]


def test_docker_missing_image_is_diagnosable_without_pull(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setenv("S3_ENDPOINT", "https://files.example")
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "No such image: pinned-image")

    lane = batch.DockerLane(
        SimpleNamespace(atespace="default"),
        batch.Workload("image@sha256:" + "a" * 64, frozenset(), 900, None),
        store=Store(Executor(tmp_path, task_boundary=True)),
        runner=runner,
    )
    record = smoke.run_smoke(lane, "https://github.com/example/project", "a" * 40)
    assert record["status"] == "instrument_failure"
    assert "ValueError:" in record["reason"] and "No such image" in record["reason"]
    assert [c[1] for c in calls] == ["image"]


@pytest.mark.parametrize("delete_fails", [False, True])
def test_capacity_partial_create_deleted_before_retry(tmp_path, monkeypatch, delete_fails):
    executor, lane, events = setup(tmp_path, monkeypatch)
    live, attempts = set(), []

    def ax(*args, **kwargs):
        events.append(args[0])
        if args[0] == "apply":
            assert not live
            live.add(kwargs["manifest"]["metadata"]["name"])
            attempts.append(1)
            if len(attempts) == 1:
                raise batch.NoFreeWorkers("partially provisioned")
        elif args[0] == "delete":
            if delete_fails:
                raise OSError("cannot delete")
            live.discard(args[2])

    lane.ax, lane.pause = ax, lambda seconds: None
    record = smoke.run_smoke(lane, "https://github.com/example/project", "a" * 40)
    assert len(attempts) == (1 if delete_fails else 2)
    assert record["status"] == ("instrument_failure" if delete_fails else "ok")
    if not delete_fails:
        assert events == ["apply", "delete", "apply", "delete"] and not live
    else:
        # Simulated leaked task deliberately retains its reservation; restore test global.
        batch.AX_SLOTS.release()


def test_apply_timeout_does_not_resubmit(tmp_path, monkeypatch):
    import subprocess

    executor, lane, events = setup(tmp_path, monkeypatch)

    def ax(*args, **kwargs):
        events.append(args[0])
        if args[0] == "apply":
            raise subprocess.TimeoutExpired("apply", 30)

    lane.ax = ax
    record = smoke.run_smoke(lane, "https://github.com/example/project", "a" * 40)
    assert events == ["apply", "delete"]
    assert "TimeoutExpired:" in record["reason"]


def test_dispatch_rejects_duplicate_items_before_launch(tmp_path):
    item = batch.Item("same", {}, "result.json", (), {}, "")

    def unexpected(*args):
        pytest.fail("duplicate inputs must be rejected before any dispatch")

    with pytest.raises(ValueError, match="duplicate dispatch item"):
        batch.dispatch([item, item], batch.Workload("image", frozenset(), 1, None), tmp_path, {"ax": unexpected}, lanes=("ax",))


@pytest.mark.parametrize("stage", ["enter", "body", "normal"])
def test_cleanup_preserves_original_and_logs(tmp_path, monkeypatch, caplog, stage):
    _, lane, _ = setup(tmp_path, monkeypatch)
    original = ValueError("original apply failure")

    def ax(*args, **kwargs):
        if args[0] == "apply" and stage == "enter":
            raise original
        if args[0] == "delete":
            raise ValueError("delete failed https://private.example/?token=secret")

    lane.ax = ax
    # Retained reservations must not leak into other tests.
    monkeypatch.setattr(batch, "AX_SLOTS", __import__("threading").BoundedSemaphore(2))
    with pytest.raises(RuntimeError if stage == "normal" else ValueError) as caught, batch.SearchExecutorTask(lane, b"archive"):
        if stage == "body":
            raise original
    if stage != "normal":
        assert caught.value is original
        assert str(caught.value).startswith("original apply failure; executor cleanup failed:")
    assert "delete failed" in str(caught.value)
    assert "executor cleanup failed" in caplog.text
    assert "private.example" not in caplog.text + str(caught.value)
