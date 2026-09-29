"""ax runner contract (ai-service-plane task 3, Requirements 4.1-4.6): env contract, readiness, delivery, exit codes,
the start request and credentials."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from openultrasast.plane import runner
from openultrasast.plane.manifests import GitSource
from openultrasast.plane.router import Router, StartError
from openultrasast.plane.runner import (
    EXIT_BY_STATUS,
    START_PATH,
    DeliveryError,
    Start,
    StartGate,
    clone_destination,
    deliver,
    find_cached_checkout,
    start_health_server,
)

STUB = Path(__file__).parent / "plane_stub_task.py"
STUB_PACKAGE = "ousast_stub_tasks"
SRC = Path(runner.__file__).resolve().parents[2]  # the ``src`` this test imports; the children must import it too


@pytest.fixture(scope="session")
def stub_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A throwaway package holding the stub, so the runner starts it as ``python -m ousast_stub_tasks.stub_task``."""
    root = tmp_path_factory.mktemp("stubs")
    (root / STUB_PACKAGE).mkdir()
    (root / STUB_PACKAGE / "__init__.py").write_text("", encoding="utf-8")
    shutil.copy(STUB, root / STUB_PACKAGE / "stub_task.py")
    return root


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stub_root: Path) -> Iterator[dict[str, str]]:
    """A private environment for one runner invocation, restored whole afterwards.

    The runner and the stub read and write ``os.environ`` directly (that is the contract), so monkeypatch alone
    would not undo what the runner exports; the snapshot does. ``AX_RUNNER_EXIT_AFTER_COMMAND`` makes ``main()``
    return after delivery instead of serving until SIGTERM, as the image does.
    """
    saved = dict(os.environ)
    for key in list(os.environ):
        if key.startswith(("OUSAST_", "AX_", "STUB_")):
            monkeypatch.delenv(key)
    monkeypatch.setenv("AX_RUNNER_HTTP", "0")
    monkeypatch.setenv("AX_RUNNER_EXIT_AFTER_COMMAND", "1")
    monkeypatch.setenv("AX_RUNNER_AUTOSTART", "1")  # the start-request tests below take it away again
    monkeypatch.setenv("AX_RUNNER_TASK_PACKAGE", STUB_PACKAGE)
    monkeypatch.setenv("OUSAST_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("OUSAST_DELIVERY_BACKOFF", "0")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(filter(None, [str(stub_root), str(SRC), os.environ.get("PYTHONPATH")])))
    try:
        yield os.environ
    finally:
        os.environ.clear()
        os.environ.update(saved)


def task_yaml(output: Path, workspace: Path, *, command: list[str] | None = None, name: str = "stub") -> str:
    cmd = command or ["stub-task", "--pass", "a"]
    env_lines = "\n".join(
        f"    - name: {k}\n      value: {json.dumps(v)}"
        for k, v in {
            "OUSAST_OUTPUT_DIR": str(output),
            "OUSAST_BUDGET_USD": "0.5",
            "OUSAST_BUDGET_CALLS": "40",
            "OUSAST_INPUT_CANDIDATES": str(workspace / "candidates.json"),
        }.items()
    )
    return (
        "apiVersion: ax.io/v1alpha1\nkind: Task\nmetadata:\n  name: " + name + "\nspec:\n  command: " + json.dumps(cmd) + "\n"
        "  env:\n" + env_lines + "\n  workspaces:\n    - name: case\n      path: " + json.dumps(str(workspace)) + "\n"
    )


def files_workspace_yaml() -> str:
    return (
        "apiVersion: ax.io/v1alpha1\nkind: Workspace\nmetadata:\n  name: case\nspec:\n  files:\n"
        '    - path: candidates.json\n      content: \'{"sinks": ["a"]}\'\n'
        "    - path: src/app.py\n      content: |\n        def handler():\n            return 1\n"
    )


def run_main(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, workspace_yaml: str, **extra: str) -> tuple[int, Path]:
    output = tmp_path / "out"
    workspace = tmp_path / "ws"
    monkeypatch.setenv("AX_TASK_YAML", task_yaml(output, workspace))
    monkeypatch.setenv("AX_WORKSPACES_YAML", workspace_yaml)
    for key, value in extra.items():
        monkeypatch.setenv(key, value)
    return runner.main(), output


# --- env contract on a files workspace (Requirement 4.1, 4.3) --------------------------------------------------------


def test_env_contract_on_a_files_workspace(env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml())
    assert code == 0
    facts = json.loads((output / "facts.json").read_text())
    assert facts["argv"] == ["--pass", "a"], "the command's tail is the task's argv"
    assert facts["workspace_files"] == ["candidates.json", "src/app.py"], "spec.files written verbatim at the bound path"
    assert (tmp_path / "ws" / "src" / "app.py").read_text() == "def handler():\n    return 1\n"
    contract = facts["env"]
    assert contract["OUSAST_OUTPUT_DIR"] == str(output)
    assert contract["OUSAST_WORKSPACE_DIR"] == str(tmp_path / "ws"), "set by the runner from the first binding"
    assert contract["OUSAST_INPUT_CANDIDATES"] == str(tmp_path / "ws" / "candidates.json")
    assert contract["OUSAST_BUDGET_USD"] == "0.5" and contract["OUSAST_BUDGET_CALLS"] == "40"
    assert json.loads((output / "summary.json").read_text())["status"] == "done"


def test_workspace_dir_from_the_task_env_is_kept(env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OUSAST_WORKSPACE_DIR", str(tmp_path / "ws"))
    code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml())
    assert code == 0
    assert json.loads((output / "facts.json").read_text())["env"]["OUSAST_WORKSPACE_DIR"] == str(tmp_path / "ws")


def test_a_bound_workspace_missing_from_the_stream_fails_before_the_task(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, output = run_main(monkeypatch, tmp_path, "")
    assert code == EXIT_BY_STATUS["failed"]
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == "failed" and "case" in summary["reason"]
    assert not (output / "facts.json").exists(), "the task never ran"


# --- readiness (Requirement 4.2) -----------------------------------------------------------------------------------------


def get(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return exc.code


def test_readyz_is_503_until_workspaces_are_ready_then_200() -> None:
    ready = threading.Event()
    server = start_health_server(0, ready)
    try:
        base = f"http://127.0.0.1:{server.port}"
        assert get(f"{base}/healthz") == 200
        assert get(f"{base}/readyz") == 503
        assert get(f"{base}/other") == 404
        assert get(f"{base}/readyz?check=workspace") == 503, "ax's controller probes with a query string"
        ready.set()
        assert get(f"{base}/readyz") == 200
        assert get(f"{base}/readyz?check=workspace") == 200
    finally:
        server.stop()


def test_main_serves_readiness_on_a_free_port_and_the_task_sees_200(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml(), AX_RUNNER_HTTP="1", AX_RUNNER_PORT="0")
    assert code == 0
    facts = json.loads((output / "facts.json").read_text())
    assert facts["readyz"] == 200, "workspaces were materialised before the task started"
    port = os.environ["AX_RUNNER_BOUND_PORT"]
    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2)


# --- artifact delivery (Requirement 4.4) --------------------------------------------------------------------------------


class Receiver(ThreadingHTTPServer):
    """Records every POST (headers and body) and answers with ``status``."""

    def __init__(self, status: int) -> None:
        super().__init__(("127.0.0.1", 0), _ReceiverHandler)
        self.status = status
        self.posts: list[tuple[dict[str, str], bytes]] = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/artifacts"

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


class _ReceiverHandler(BaseHTTPRequestHandler):
    server: Receiver

    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.posts.append(({k: v for k, v in self.headers.items()}, body))
        self.send_response(self.server.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture
def receiver() -> Iterator[Receiver]:
    server = Receiver(200)
    try:
        yield server
    finally:
        server.stop()


def test_output_dir_is_delivered_as_a_tar_with_the_headers(
    env: dict[str, str], receiver: Receiver, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml(), OUSAST_ARTIFACT_URL=receiver.url, OUSAST_RUN="validation-46")
    assert code == 0
    assert len(receiver.posts) == 1
    headers, body = receiver.posts[0]
    assert headers["Content-Type"] == "application/x-tar"
    assert headers["X-Ousast-Task"] == "stub"
    assert headers["X-Ousast-Run"] == "validation-46"
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as archive:
        names = sorted(archive.getnames())
        summary = archive.extractfile("summary.json")
        assert summary is not None
        assert json.loads(summary.read())["status"] == "done"
    assert names == ["facts.json", "summary.json"]


def test_run_header_is_absent_without_ousast_run(
    env: dict[str, str], receiver: Receiver, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, _ = run_main(monkeypatch, tmp_path, files_workspace_yaml(), OUSAST_ARTIFACT_URL=receiver.url)
    assert code == 0
    assert "X-Ousast-Run" not in receiver.posts[0][0]


def test_delivery_failure_is_reported_as_failed_with_exit_2(env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    broken = Receiver(500)
    try:
        code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml(), OUSAST_ARTIFACT_URL=broken.url)
    finally:
        broken.stop()
    assert code == EXIT_BY_STATUS["failed"] == 2
    assert len(broken.posts) == 3, "three attempts"
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == "failed"
    assert summary["reason"].startswith("artifact delivery failed: HTTP 500")
    assert summary["units_done"] == 1 and summary["units_total"] == 1, "the task's other fields are kept"


def test_deliver_retries_on_connection_errors_then_raises() -> None:
    closed = Receiver(200)
    url = closed.url
    closed.stop()
    with pytest.raises(DeliveryError, match="3 attempts"):
        deliver(url, b"x", {"Content-Type": "application/x-tar"}, backoff=0)


# --- exit codes (design: error handling) ------------------------------------------------------------------------------------


def test_a_crash_yields_failed_with_the_traceback(env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml(), STUB_MODE="crash")
    assert code == 2
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == "failed"
    assert "Traceback" in summary["reason"] and "stub exploded" in summary["reason"]
    assert (output / "facts.json").exists(), "artifacts written before the crash stay for resume"


@pytest.mark.parametrize(("mode", "code"), [("done", 0), ("failed", 2), ("unfinished", 3), ("nosummary", 2), ("exit", 2)])
def test_exit_code_follows_the_summary_status(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str, code: int
) -> None:
    got, output = run_main(monkeypatch, tmp_path, files_workspace_yaml(), STUB_MODE=mode)
    assert got == code
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == (mode if mode in EXIT_BY_STATUS else "failed")


def test_an_unknown_task_module_is_failed(env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output, workspace = tmp_path / "out", tmp_path / "ws"
    monkeypatch.setenv("AX_TASK_YAML", task_yaml(output, workspace, command=["no-such-task"]))
    monkeypatch.setenv("AX_WORKSPACES_YAML", files_workspace_yaml())
    assert runner.main() == 2
    assert "no_such_task" in json.loads((output / "summary.json").read_text())["reason"]


# --- ax's lifecycle: a child process, stay up, SIGTERM, completion marker (docs/runner.md, docs/sandbox.md) -----------------


def test_the_command_is_a_child_in_its_own_group_in_the_first_workspace(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml(), AX_RUNNER_HTTP="1", AX_RUNNER_PORT="0")
    assert code == 0
    facts = json.loads((output / "facts.json").read_text())
    assert facts["pid"] != os.getpid(), "the task is a child process, not an import"
    assert facts["pgid"] == facts["pid"] != os.getpgid(0), "the child leads its own process group"
    assert facts["cwd"] == str(tmp_path / "ws"), "the first workspace is the working directory"
    assert facts["metadata_url"] == f"http://127.0.0.1:{os.environ['AX_RUNNER_BOUND_PORT']}"
    assert "name: stub" in facts["metadata_task"], "AX_METADATA_URL serves the Task YAML"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def alive(pid: int) -> bool:
    """True while ``pid`` exists and is not a zombie (a killed orphan may wait for its reaper)."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0] != "Z"
    except (FileNotFoundError, ProcessLookupError, IndexError):
        return False


def wait_for(predicate: object, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():  # type: ignore[operator]
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.05)


def spawn_runner(tmp_path: Path, port: int, *, autostart: bool = True, log_name: str = "runner.log", **extra: str) -> subprocess.Popen:
    """``python -m openultrasast.plane.runner`` as the image runs it: HTTP on, no exit-after-command escape;
    ``autostart=False`` also drops the autostart escape, so the command waits for a start request."""
    dropped = {"AX_RUNNER_EXIT_AFTER_COMMAND"} | (set() if autostart else {"AX_RUNNER_AUTOSTART"})
    child_env = {k: v for k, v in os.environ.items() if k not in dropped}
    child_env.update(AX_TASK_YAML=task_yaml(tmp_path / "out", tmp_path / "ws"), AX_WORKSPACES_YAML=files_workspace_yaml())
    child_env.update(AX_RUNNER_HTTP="1", AX_RUNNER_PORT=str(port), **extra)
    log = (tmp_path / log_name).open("wb")
    return subprocess.Popen([sys.executable, "-m", "openultrasast.plane.runner"], env=child_env, stdout=log, stderr=log)


def test_the_runner_keeps_serving_after_the_command_and_exits_0_on_sigterm(env: dict[str, str], receiver: Receiver, tmp_path: Path) -> None:
    port = free_port()
    proc = spawn_runner(tmp_path, port, OUSAST_ARTIFACT_URL=receiver.url)
    marker = tmp_path / "state" / "stub.done.json"
    try:
        wait_for(marker.exists)
        time.sleep(0.5)
        assert proc.poll() is None, "PID 1 must outlive the command (ax: 'Container guest is stopped' otherwise)"
        base = f"http://127.0.0.1:{port}"
        assert get(f"{base}/healthz") == 200 and get(f"{base}/readyz?check=workspace") == 200
        assert get(f"{base}/metadata/v1alpha1/ax/workspaces") == 200
        assert len(receiver.posts) == 1
        assert json.loads(marker.read_text()) | {"summary": None} == {"exit": 0, "status": "done", "delivered": True, "summary": None}
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 0
    finally:
        proc.kill()
        proc.wait()


def test_sigterm_goes_to_the_commands_group_then_sigkill_after_the_grace(env: dict[str, str], receiver: Receiver, tmp_path: Path) -> None:
    port = free_port()
    proc = spawn_runner(tmp_path, port, OUSAST_ARTIFACT_URL=receiver.url, STUB_MODE="sleep", OUSAST_TERM_GRACE="1")
    pids_file = tmp_path / "out" / "pids.json"
    try:
        wait_for(pids_file.exists)
        pids = json.loads(pids_file.read_text())
        assert all(alive(pid) for pid in pids)
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=15) == 0
        assert time.monotonic() - started >= 0.9, "the command ignored SIGTERM, so the runner waited out the grace"
        wait_for(lambda: not any(alive(pid) for pid in pids), timeout=5)
    finally:
        proc.kill()
        proc.wait()
    assert not (tmp_path / "state" / "stub.done.json").exists(), "an interrupted command is not complete"
    assert receiver.posts == [], "nothing is delivered for an interrupted command"


def test_the_completion_marker_prevents_a_rerun_on_resume(
    env: dict[str, str], receiver: Receiver, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    counter = tmp_path / "runs.txt"
    code, _ = run_main(monkeypatch, tmp_path, files_workspace_yaml(), OUSAST_ARTIFACT_URL=receiver.url, STUB_COUNTER=str(counter))
    assert code == 0 and len(counter.read_text().splitlines()) == 1 and len(receiver.posts) == 1
    (tmp_path / "ws" / "candidates.json").write_text("changed by the task\n")
    code, _ = run_main(monkeypatch, tmp_path, files_workspace_yaml(), OUSAST_ARTIFACT_URL=receiver.url, STUB_COUNTER=str(counter))
    assert code == 0
    assert len(counter.read_text().splitlines()) == 1, "a resumed actor must not repeat billed work"
    assert len(receiver.posts) == 1, "a delivered result is not delivered again"
    assert (tmp_path / "ws" / "candidates.json").read_text() == "changed by the task\n", "workspaces are prepared once"


def test_a_failed_delivery_is_retried_alone_on_the_next_boot(
    env: dict[str, str], receiver: Receiver, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    counter = tmp_path / "runs.txt"
    broken = Receiver(500)
    try:
        code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml(), OUSAST_ARTIFACT_URL=broken.url, STUB_COUNTER=str(counter))
    finally:
        broken.stop()
    assert code == 2
    marker = json.loads((tmp_path / "state" / "stub.done.json").read_text())
    assert marker["delivered"] is False and marker["status"] == "failed" and marker["exit"] == 0
    code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml(), OUSAST_ARTIFACT_URL=receiver.url, STUB_COUNTER=str(counter))
    assert code == 0
    assert len(counter.read_text().splitlines()) == 1, "only the delivery is retried"
    with tarfile.open(fileobj=io.BytesIO(receiver.posts[0][1]), mode="r:") as archive:
        summary = archive.extractfile("summary.json")
        assert summary is not None and json.loads(summary.read())["status"] == "done", "the task's own summary"
    marker = json.loads((tmp_path / "state" / "stub.done.json").read_text())
    assert marker["delivered"] is True and marker["status"] == "done"


# --- git workspaces from the case cache and by shallow clone ----------------------------------------------------------------


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, str]:
    """A local repository with two commits; returns it and the first commit (the pin)."""
    repo = tmp_path / "upstream"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo)
    (repo / "hello.py").write_text("print('v1')\n")
    git("add", ".", cwd=repo)
    git("commit", "-q", "-m", "v1", cwd=repo)
    pin = git("rev-parse", "HEAD", cwd=repo)
    (repo / "hello.py").write_text("print('v2')\n")
    git("commit", "-q", "-am", "v2", cwd=repo)
    return repo, pin


def git_workspace_yaml(repo_url: str, extra: str = "") -> str:
    """ax's Workspace as ax hands it over: no annotations, no commit (the pin travels in ``OUSAST_GIT_PINS``)."""
    return (
        "apiVersion: ax.io/v1alpha1\nkind: Workspace\nmetadata:\n  name: case\nspec:\n  git:\n"
        f"    - name: code\n      repo: {repo_url}\n      branch: main\n{extra}"
        "  files:\n    - path: candidates.json\n      content: '{\"sinks\": []}'\n"
    )


def pins(pin: str, key: str = "case/code") -> str:
    return json.dumps({key: pin})


def test_git_entry_is_exported_from_the_case_cache_at_the_pin(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, upstream: tuple[Path, str]
) -> None:
    repo, pin = upstream
    url = "https://example.invalid/acme/Repo.git"
    cache = tmp_path / "cache"
    case = cache / "acme-case-sqli"
    subprocess.run(["git", "clone", "-q", "--no-checkout", str(repo), str(case)], check=True)
    git("remote", "set-url", "origin", url, cwd=case)
    assert find_cached_checkout(cache, "https://example.invalid/acme/repo") == case
    assert find_cached_checkout(cache, "https://example.invalid/other/repo.git") is None
    code, output = run_main(monkeypatch, tmp_path, git_workspace_yaml(url), OUSAST_CASE_CACHE=str(cache), OUSAST_GIT_PINS=pins(pin))
    assert code == 0, (output / "summary.json").read_text()
    checkout = tmp_path / "ws" / "code"
    assert (checkout / "hello.py").read_text() == "print('v1')\n", "the pinned commit, not the branch tip"
    assert not (checkout / ".git").exists(), "an export, as evaluate.export makes"
    facts = json.loads((output / "facts.json").read_text())
    assert facts["workspace_files"] == ["candidates.json", "code/hello.py"]


def test_git_entry_without_a_cache_is_shallow_cloned_at_the_pin(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, upstream: tuple[Path, str]
) -> None:
    repo, pin = upstream
    code, output = run_main(
        monkeypatch, tmp_path, git_workspace_yaml(repo.as_uri()), OUSAST_CASE_CACHE=str(tmp_path / "no-cache"), OUSAST_GIT_PINS=pins(pin)
    )
    assert code == 0, (output / "summary.json").read_text()
    checkout = tmp_path / "ws" / "code"
    assert (checkout / "hello.py").read_text() == "print('v1')\n"
    assert git("rev-parse", "HEAD", cwd=checkout) == pin


def test_a_materialised_repo_survives_a_resume(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, upstream: tuple[Path, str]
) -> None:
    repo, pin = upstream
    checkout = tmp_path / "ws" / "code"
    checkout.mkdir(parents=True)
    (checkout / "hello.py").write_text("kept\n")
    code, _ = run_main(monkeypatch, tmp_path, git_workspace_yaml(repo.as_uri()), OUSAST_GIT_PINS=pins(pin))
    assert code == 0
    assert (checkout / "hello.py").read_text() == "kept\n", "/workspace persists across suspend and resume; no re-clone"


# --- ax's GitRepo fields: dir, depth; the commit pin from OUSAST_GIT_PINS ------------------------------------------------


@pytest.mark.parametrize(
    ("name", "repo", "dir_", "expected"),
    [
        ("code", "https://github.com/chalk/chalk.git", None, "/ws/code"),
        ("repo", "https://github.com/chalk/chalk.git", None, "/ws/chalk"),
        ("origin", "git@github.com:chalk/chalk", None, "/ws/chalk"),
        ("code", "https://github.com/chalk/chalk.git", "src", "/ws/src"),
        ("code", "https://github.com/chalk/chalk.git", ".", "/ws"),
        ("code", "https://github.com/chalk/chalk.git", "/elsewhere", "/elsewhere"),
    ],
)
def test_clone_destination_follows_ax_setup(name: str, repo: str, dir_: str | None, expected: str) -> None:
    """ax internal/workspace/setup.go cloneDestination: dir wins; placeholder names derive from the URL."""
    assert clone_destination(GitSource(name, repo, dir=dir_), Path("/ws")) == Path(expected)


def test_git_dir_and_depth_are_honoured(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, upstream: tuple[Path, str]
) -> None:
    repo, _ = upstream
    code, output = run_main(monkeypatch, tmp_path, git_workspace_yaml(repo.as_uri(), "      dir: src\n      depth: 1\n"))
    assert code == 0, (output / "summary.json").read_text()
    checkout = tmp_path / "ws" / "src"
    assert (checkout / "hello.py").read_text() == "print('v2')\n", "no pin: the branch tip"
    assert git("rev-parse", "--is-shallow-repository", cwd=checkout) == "true", "depth 1 is a shallow fetch"
    assert not (tmp_path / "ws" / "code").exists()


def test_a_pin_naming_no_bound_git_entry_fails_the_task(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, upstream: tuple[Path, str]
) -> None:
    repo, pin = upstream
    code, output = run_main(monkeypatch, tmp_path, git_workspace_yaml(repo.as_uri()), OUSAST_GIT_PINS=pins(pin, "case/other"))
    assert code == EXIT_BY_STATUS["failed"]
    assert "case/other" in json.loads((output / "summary.json").read_text())["reason"]


def test_unreadable_pins_fail_the_task(env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml(), OUSAST_GIT_PINS='{"case/code": "abc"}')
    assert code == EXIT_BY_STATUS["failed"]
    assert "OUSAST_GIT_PINS" in json.loads((output / "summary.json").read_text())["reason"]


def test_git_commits_annotation_round_trips_to_the_checkout(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, upstream: tuple[Path, str]
) -> None:
    """Workspace annotation -> reconciler -> ``OUSAST_GIT_PINS`` in the Task env -> the runner checks out the pin."""
    import yaml

    from openultrasast.plane import reconciler

    repo, pin = upstream
    output, workspace = tmp_path / "out", tmp_path / "ws"
    manifest = tmp_path / "run.yaml"
    manifest.write_text(
        "apiVersion: ax.io/v1alpha1\nkind: Workspace\nmetadata:\n  name: case\n"
        f"  annotations: {{openultrasast.io/git-commits: 'code={pin}'}}\n"
        f"spec:\n  git: [{{name: code, repo: '{repo.as_uri()}', branch: main}}]\n---\n"
        "apiVersion: ax.io/v1alpha1\nkind: Task\nmetadata: {name: stub}\n"
        f"spec: {{command: [stub-task], workspaces: [{{name: case, path: '{workspace}'}}]}}\n---\n"
        "apiVersion: openultrasast.io/v1alpha1\nkind: Run\nmetadata: {name: rt}\nspec: {tasks: [{name: stub, task: stub}]}\n"
    )
    run, manifests = reconciler.load_run(manifest)
    task_doc, *rest = reconciler.render_task(run, run.tasks[0], manifests, tmp_path, "unused")
    assert rest[0]["metadata"] == {"name": "case"}, "annotations are stripped before ax"
    assert rest[0]["spec"]["git"] == [{"name": "code", "repo": repo.as_uri(), "branch": "main"}], "no commit for ax"
    overrides = {"OUSAST_OUTPUT_DIR": str(output)}
    task_doc["spec"]["env"] = [
        {"name": e["name"], "value": overrides.get(e["name"], e["value"])}
        for e in task_doc["spec"]["env"]
        if e["name"] != "OUSAST_ARTIFACT_URL"
    ]
    assert json.loads({e["name"]: e["value"] for e in task_doc["spec"]["env"]}["OUSAST_GIT_PINS"]) == {"case/code": pin}
    monkeypatch.setenv("AX_TASK_YAML", yaml.safe_dump(task_doc))
    monkeypatch.setenv("AX_WORKSPACES_YAML", yaml.safe_dump_all([d for d in rest if d["kind"] == "Workspace"]))
    assert runner.main() == 0, (output / "summary.json").read_text()
    checkout = workspace / "code"
    assert git("rev-parse", "HEAD", cwd=checkout) == pin, "the pinned commit, not the branch tip"
    assert (checkout / "hello.py").read_text() == "print('v1')\n"


def test_the_runner_accepts_what_ax_hands_it() -> None:
    """ax's server adds metadata.creationTimestamp and status (live cluster, 2026-09-29); other fields stay strict."""
    from openultrasast.plane.runner import RunnerError, load_task, load_workspaces

    task = load_task(
        "apiVersion: ax.io/v1alpha1\nkind: Task\nmetadata:\n  name: t\n  atespace: default\n"
        "  creationTimestamp: '2026-09-29T17:11:58Z'\nspec:\n  command: [repo-facts]\n"
        "status:\n  phase: Running\n  id: task-t-1\n"
    )
    assert task.metadata.name == "t"
    spaces = load_workspaces(
        "apiVersion: ax.io/v1alpha1\nkind: Workspace\nmetadata:\n  name: w\n"
        "  creationTimestamp: '2026-09-29T17:11:58Z'\nspec:\n  files:\n  - path: a.py\n    content: x\n"
    )
    assert list(spaces) == ["w"]
    with pytest.raises(RunnerError, match="uid"):
        load_task("apiVersion: ax.io/v1alpha1\nkind: Task\nmetadata:\n  name: t\n  uid: x\nspec: {}\n")


# --- the start request and credentials (Requirements 4.5, 4.6) -----------------------------------------------------------

SECRET = "sk-test-0f3c9a-never-written-anywhere"
SECRET_SHA = hashlib.sha256(SECRET.encode()).hexdigest()


def post_start(port: int | str, body: object) -> tuple[int, str]:
    data = json.dumps(body).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}{START_PATH}", data=data, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return int(response.status), response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def ready_on(port: int | str) -> bool:
    try:
        return get(f"http://127.0.0.1:{port}/readyz") == 200
    except urllib.error.URLError:
        return False  # not listening yet


def files_containing(root: Path, needle: str) -> list[str]:
    return sorted(str(p) for p in root.rglob("*") if p.is_file() and needle.encode() in p.read_bytes())


def main_in_thread(tmp_path: Path, **extra: str) -> tuple[threading.Thread, dict[str, str], list[int]]:
    """``runner.main`` on a private environment in a thread: HTTP on a free port, no autostart; the exit code lands
    in the returned list once the command was started and delivered."""
    environ = {k: v for k, v in os.environ.items() if k != "AX_RUNNER_AUTOSTART"}
    environ.update(AX_TASK_YAML=task_yaml(tmp_path / "out", tmp_path / "ws"), AX_WORKSPACES_YAML=files_workspace_yaml())
    environ.update(AX_RUNNER_HTTP="1", AX_RUNNER_PORT="0", OUSAST_RUN="run-1", STUB_SECRET_VAR="DEEPSEEK_API_KEY", **extra)
    codes: list[int] = []
    thread = threading.Thread(target=lambda: codes.append(runner.main(environ=environ)), daemon=True)
    thread.start()
    wait_for(lambda: "AX_RUNNER_BOUND_PORT" in environ)
    wait_for(lambda: ready_on(environ["AX_RUNNER_BOUND_PORT"]))
    return thread, environ, codes


def test_the_command_waits_for_the_start_request_and_the_credential_reaches_only_the_child(
    env: dict[str, str], receiver: Receiver, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    counter = tmp_path / "runs.txt"
    thread, environ, codes = main_in_thread(tmp_path, OUSAST_ARTIFACT_URL=receiver.url, STUB_COUNTER=str(counter))
    port = environ["AX_RUNNER_BOUND_PORT"]
    time.sleep(0.5)
    assert not counter.exists() and thread.is_alive(), "ready, but the command waits for the start request"
    assert post_start(port, {"run": "run-2", "task": "stub"})[0] == 409, "another run's start"
    assert post_start(port, {"run": "run-1", "task": "golden"})[0] == 409, "another task's start"
    assert post_start(port, {"run": "run-1", "task": "stub", "credentials": {"lower": "x"}})[0] == 400
    assert post_start(port, {"run": "run-1", "task": "stub", "credentials": {"OUSAST_OUTPUT_DIR": "/"}})[0] == 400
    assert not counter.exists()
    status, text = post_start(port, {"run": "run-1", "task": "stub", "credentials": {"DEEPSEEK_API_KEY": SECRET}})
    assert (status, text) == (202, "started")
    status, text = post_start(port, {"run": "run-1", "task": "stub", "credentials": {"DEEPSEEK_API_KEY": SECRET}})
    assert status == 409 and "already started" in text, "one start per boot"
    thread.join(timeout=30)
    assert codes == [0] and len(counter.read_text().splitlines()) == 1
    facts = json.loads((tmp_path / "out" / "facts.json").read_text())
    assert facts["secret_sha256"] == SECRET_SHA, "the credential is in the command's environment"
    assert "DEEPSEEK_API_KEY" not in environ and "DEEPSEEK_API_KEY" not in os.environ, "and only there"
    assert str(tmp_path / "out" / "facts.json") in files_containing(tmp_path, SECRET_SHA), "the scan reads the output files"
    assert files_containing(tmp_path, SECRET) == [], "no file holds the credential"
    assert SECRET not in receiver.posts[0][1].decode("latin-1"), "nor the delivered tar"
    assert all(SECRET not in record.getMessage() for record in caplog.records), "nor any log record"
    assert any("start request: 202" in record.getMessage() for record in caplog.records)


def test_a_crash_that_prints_the_credential_is_redacted(
    env: dict[str, str], receiver: Receiver, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    thread, environ, codes = main_in_thread(tmp_path, OUSAST_ARTIFACT_URL=receiver.url, STUB_MODE="leak")
    start = {"run": "run-1", "task": "stub", "credentials": {"DEEPSEEK_API_KEY": SECRET}}
    assert post_start(environ["AX_RUNNER_BOUND_PORT"], start)[0] == 202
    thread.join(timeout=30)
    assert codes == [EXIT_BY_STATUS["failed"]]
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert "auth failed for key [redacted]" in summary["reason"], "the stderr tail keeps the line, not the value"
    assert files_containing(tmp_path, SECRET) == []
    assert SECRET not in capfd.readouterr().err, "the echoed stderr is redacted too"


def test_start_before_the_workspaces_are_ready_is_503_and_a_delivered_run_refuses_it() -> None:
    gate = StartGate()
    assert gate.offer(b'{"run": "r", "task": "t"}')[0] == 503, "the reconciler retries until the workspaces are ready"
    gate.refuse("task t already ran and was delivered (done)")
    status, text = gate.offer(b'{"run": "r", "task": "t"}')
    assert status == 409 and "already ran and was delivered" in text
    assert "sk-" not in repr(Start({"K": "sk-x"})), "a Start never prints a value"


def test_http_off_without_autostart_is_refused(env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("AX_RUNNER_AUTOSTART")
    code, output = run_main(monkeypatch, tmp_path, files_workspace_yaml())
    assert code == EXIT_BY_STATUS["failed"] and not (output / "facts.json").exists()


def test_the_golden_boot_never_runs_the_command(env: dict[str, str], receiver: Receiver, tmp_path: Path) -> None:
    """Agent Substrate's golden-snapshot boot runs the same image with the same env; only the router-addressed
    actor gets the start request, so only it runs the command. A later boot of a delivered task refuses a start."""
    counter = tmp_path / "runs.txt"
    same = {"OUSAST_ARTIFACT_URL": receiver.url, "STUB_COUNTER": str(counter), "OUSAST_RUN": "run-1"}
    real_port, golden_port = free_port(), free_port()
    real = spawn_runner(tmp_path, real_port, autostart=False, log_name="real.log", **same)
    golden = spawn_runner(tmp_path, golden_port, autostart=False, log_name="golden.log", **same)
    try:
        for port in (real_port, golden_port):
            wait_for(lambda port=port: ready_on(port))
        Router(f"http://127.0.0.1:{real_port}").start_task("default", "stub", "run-1", {"DEEPSEEK_API_KEY": SECRET})
        marker = tmp_path / "state" / "stub.done.json"
        wait_for(marker.exists)
        time.sleep(1.0)
        assert len(counter.read_text().splitlines()) == 1, "the golden boot never ran the command"
        assert golden.poll() is None and len(receiver.posts) == 1
        with pytest.raises(StartError, match="already started"):
            Router(f"http://127.0.0.1:{real_port}").start_task("default", "stub", "run-1", {})
        again_port = free_port()
        again = spawn_runner(tmp_path, again_port, autostart=False, log_name="again.log", **same)
        try:
            with pytest.raises(StartError, match="already ran and was delivered"):
                Router(f"http://127.0.0.1:{again_port}").start_task("default", "stub", "run-1", {})
        finally:
            again.kill()
            again.wait()
    finally:
        for proc in (real, golden):
            proc.kill()
            proc.wait()
    assert len(counter.read_text().splitlines()) == 1
    assert files_containing(tmp_path, SECRET) == [], "no log, workspace, output or state file holds the credential"
