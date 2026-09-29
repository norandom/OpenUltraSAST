"""ax runner contract (ai-service-plane task 3, Requirements 4.1-4.4): env contract, readiness, delivery, exit codes."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from openultrasast.plane import runner
from openultrasast.plane.manifests import GitSource
from openultrasast.plane.runner import (
    EXIT_BY_STATUS,
    DeliveryError,
    clone_destination,
    deliver,
    find_cached_checkout,
    start_health_server,
)

STUB = Path(__file__).parent / "plane_stub_task.py"
STUB_MODULE = f"{runner.TASK_PACKAGE}.stub_task"


@pytest.fixture(autouse=True)
def stub_task() -> Iterator[None]:
    """Register the stub as ``openultrasast.plane.tasks.stub_task`` for the runner's import; no src package needed."""
    spec = importlib.util.spec_from_file_location(STUB_MODULE, STUB)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[STUB_MODULE] = module
    spec.loader.exec_module(module)
    try:
        yield
    finally:
        sys.modules.pop(STUB_MODULE, None)


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, str]]:
    """A private environment for one runner invocation, restored whole afterwards.

    The runner and the stub read and write ``os.environ`` directly (that is the contract), so monkeypatch alone
    would not undo what the runner exports; the snapshot does.
    """
    saved = dict(os.environ)
    for key in list(os.environ):
        if key.startswith(("OUSAST_", "AX_", "STUB_")):
            monkeypatch.delenv(key)
    monkeypatch.setenv("AX_RUNNER_HTTP", "0")
    monkeypatch.setenv("OUSAST_DELIVERY_BACKOFF", "0")
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
        ready.set()
        assert get(f"{base}/readyz") == 200
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
