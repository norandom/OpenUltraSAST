"""Offline operator storage/egress contracts, using real local child processes."""

import json
import os
import sys
from pathlib import Path

import pytest

from openultrasast.search import executor, task_storage, verify_task
from openultrasast.search.verify import Side, verify_side_task


def spec():
    return {
        "demo": {
            "build": {"recipe": "none", "arguments": []},
            "start": {"runtime": "python", "path": "app.py", "arguments": [], "mode": "cli"},
            "steps": [{"type": "cli", "arguments": []}],
        },
        "family": "path",
        "timeout_seconds": 2,
    }


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setattr(task_storage, "WORKSPACE", root)
    # Keep global tempfile state and environment changes local to this test.
    monkeypatch.setattr(task_storage.tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(os, "environ", dict(os.environ))
    task_storage.configure()
    return root


def test_workspace_environment_and_cached_tempdir(workspace):
    env = executor.clean_environment()
    assert env["TMPDIR"] == str(workspace / "tmp")
    assert task_storage.tempfile.gettempdir() == env["TMPDIR"]
    for key, suffix in {
        "npm_config_cache": ".npm",
        "COMPOSER_HOME": ".composer",
        "PIP_CACHE_DIR": ".pip",
        "GRADLE_USER_HOME": ".gradle",
    }.items():
        assert env[key] == str(workspace / suffix)
    assert env["MAVEN_OPTS"] == "-Dmaven.repo.local=" + str(workspace / ".m2")


@pytest.mark.parametrize("wait", [False, True])
def test_executor_checks_caches_and_stops_at_scratch_limit(workspace, monkeypatch, wait):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "input").write_text("readable-input")
    monkeypatch.setenv("OUSAST_SCRATCH_BYTES", "20000")
    app = executor.InProcessExecutor(repo, task_boundary=True)
    code = (
        "from pathlib import Path; import os,time; print(Path('input').stat().st_size); "
        "p=Path(os.environ['PIP_CACHE_DIR']); p.mkdir(); (p/'large').write_bytes(b'x'*30000); " + ("time.sleep(10)" if wait else "")
    )
    result = app.submit("run", {"command": [sys.executable, "-c", code]}, timeout_seconds=3)
    assert result["status"] == "could_not_build" and result["reason"] == "ScratchLimit: scratch limit"
    assert result["stopped"] and app.stopped


def test_executor_exports_built_input_and_verifier_needs_no_build(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "app.py").write_text("print('safe')")
    blobs = []
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    monkeypatch.setattr(executor.URLTransport, "put", lambda self, url, data, timeout: blobs.append(data))
    result = app.submit("prepare_verification", spec())
    assert result["status"] == "ok", result
    destination = workspace / "unpacked"
    verify_task.extract_checkout(blobs[0], destination)
    assert (destination / "checkout/app.py").read_text() == "print('safe')"
    assert json.loads((destination / "spec.json").read_text()) == spec()
    assert (destination / "products").is_dir()
    demo = workspace / "demo"
    demo.mkdir()
    (demo / "demo.json").write_text(json.dumps(spec()["demo"]))
    observation = verify_side_task(Side(destination / "checkout", products=destination / "products"), demo, "path")
    assert observation.outcome == "observed", observation


def test_verifier_refuses_build_recipe():
    value = spec()
    value["demo"]["build"] = {"recipe": "npm", "arguments": ["project"]}
    with pytest.raises(ValueError, match="builds are forbidden"):
        verify_task.validate_spec(value)


def test_first_download_retries_for_60_seconds(monkeypatch):
    import urllib.error

    now, timeouts = [0.0], []

    class Opener:
        def open(self, url, timeout):
            timeouts.append(timeout)
            raise urllib.error.HTTPError(url, 403, "pending policy", {}, None)

    monkeypatch.setattr(verify_task.urllib.request, "build_opener", lambda *a: Opener())
    monkeypatch.setattr(verify_task.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(verify_task.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    with pytest.raises(OSError, match="egress not ready"):
        verify_task.download("https://files.because-security.com/input", 100)
    assert now[0] == 60 and len(timeouts) > 3


def test_verifier_reports_scratch_limit(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    # Writes happen after readiness, in a package cache outside the checkout.
    (repo / "app.py").write_text(
        "import sys,os\nfrom pathlib import Path\n"
        "if '--ready' not in sys.argv:\n"
        " p=Path(os.environ['npm_config_cache']); p.mkdir(exist_ok=True); (p/'large').write_bytes(b'x'*30000)\n"
    )
    demo = workspace / "demo"
    demo.mkdir()
    (demo / "demo.json").write_text(json.dumps(spec()["demo"]))
    monkeypatch.setenv("OUSAST_SCRATCH_BYTES", "25000")
    result = verify_side_task(Side(repo), demo, "path")
    assert result.outcome == "could_not_build" and result.reason == "ScratchLimit: scratch limit", result


def test_preparation_builds_before_export_and_exports_products(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "app.py").write_text("import dependency; print(dependency.VALUE)")
    (repo / "requirements.txt").write_text("dependency==1")
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    blobs, commands = [], []
    monkeypatch.setattr(executor.URLTransport, "put", lambda self, url, data, timeout: blobs.append(data))

    def build(argv, timeout, limits):
        commands.append(argv)
        products = Path(argv[argv.index("--target") + 1])
        assert products.is_relative_to(workspace)
        products.mkdir()
        (products / "dependency.py").write_text("VALUE = 42")
        return {"exit_code": 0, "timed_out": False, "stderr": ""}

    monkeypatch.setattr(app, "_task_run", build)
    request = spec()
    request["demo"]["build"] = {"recipe": "pip", "arguments": ["requirements.txt"]}
    result = app.submit("prepare_verification", request)
    assert result["status"] == "ok", result
    assert len(commands) == 1 and "--no-index" not in commands[0]
    unpacked = workspace / "unpacked"
    verify_task.extract_checkout(blobs[0], unpacked)
    assert (unpacked / "products/packages/dependency.py").read_text() == "VALUE = 42"
    assert json.loads((unpacked / "spec.json").read_text())["demo"]["build"] == {"recipe": "none", "arguments": []}


def test_open_logs_count_toward_scratch_guard(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    monkeypatch.setenv("OUSAST_SCRATCH_BYTES", "20000")
    app = executor.InProcessExecutor(repo, task_boundary=True)
    result = app.submit("run", {"command": [sys.executable, "-c", "print('x'*30000)"]})
    assert result["status"] == "could_not_build" and result["reason"] == "ScratchLimit: scratch limit"


def test_unreadable_scratch_is_not_reported_as_empty(tmp_path):
    with pytest.raises(OSError, match="scratch root unavailable"):
        task_storage.check(tmp_path / "missing")


def test_pip_removing_enumerated_directory_is_not_guard_failure(workspace, monkeypatch):
    original = task_storage.os.walk

    def disappearing(root, **kwargs):
        kwargs["onerror"](FileNotFoundError(2, "removed pip build directory", str(root / "pip-build")))
        yield from original(root, **kwargs)

    monkeypatch.setattr(task_storage.os, "walk", disappearing)
    (workspace / "input").write_bytes(b"input")
    assert task_storage.check(workspace) >= 5


def test_guard_still_refuses_permission_errors(workspace, monkeypatch):
    def unreadable(root, **kwargs):
        kwargs["onerror"](PermissionError("permission denied"))
        return iter(())

    monkeypatch.setattr(task_storage.os, "walk", unreadable)
    with pytest.raises(PermissionError):
        task_storage.check(workspace)


def test_child_environment_has_disk_home_and_owned_runtime_path(workspace):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "input").write_bytes(b"proof")
    code = (
        "import os; from pathlib import Path; print(Path('input').stat().st_size); "
        "print(os.environ['PATH']); p=Path.home()/'probe'; p.write_text('ok'); print(p)"
    )
    result = executor.InProcessExecutor(repo, task_boundary=True).submit("run", {"command": [sys.executable, "-c", code]})
    assert result["exit_code"] == 0
    assert result["stdout"].startswith("5\n/venv/bin:")
    assert (workspace / "home/probe").read_text() == "ok"


def test_scratch_failure_preserves_exit_and_stderr(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    monkeypatch.setenv("OUSAST_SCRATCH_BYTES", "20000")
    code = (
        "import sys,time; from pathlib import Path; print('pip build detail',file=sys.stderr,flush=True); "
        "Path('big').write_bytes(b'x'*30000); time.sleep(10)"
    )
    result = executor.InProcessExecutor(repo, task_boundary=True).submit("run", {"command": [sys.executable, "-c", code]})
    assert result["phase"] == "scratch guard"
    assert result["exit_code"] is not None
    assert result["stderr"] == "pip build detail"
    assert result["reason"].startswith("ScratchLimit:")


def test_capacity_deadline_plain_diagnostic_survives():
    from benchmarks.ax.batch import CapacityDeadline

    message = "no free workers available before deadline"
    assert task_storage.diagnostic(message) == message
    assert task_storage.exception_reason(CapacityDeadline(message)) == "CapacityDeadline: " + message


def test_cleanup_diagnostic_retains_both_causes():
    error = ValueError("original apply failed")
    error.executor_cleanup_reason = "executor cleanup failed: " + "details " * 100 + "delete failed"
    error.args = (str(error) + "; " + error.executor_cleanup_reason,)
    reason = task_storage.exception_reason(error)
    assert reason.startswith("ValueError: original apply failed;")
    assert reason.endswith("delete failed")
    assert len(reason) <= 300
