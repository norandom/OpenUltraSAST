"""Offline executor boundary and mailbox protocol checks."""

import json

import pytest

from openultrasast.search.executor import MAX_RESULT_BYTES, Command, InProcessExecutor, ObjectStoreExecutor, clean_environment, serve


def test_order_retry_stop(tmp_path):
    (tmp_path / "input").write_text("hello")
    executor = InProcessExecutor(tmp_path)
    command = Command(1, "read_file", {"path": "input"})
    first = executor.execute(command)
    assert first["text"] == "hello" and first["input_bytes"] == 5
    (tmp_path / "input").write_text("changed")
    assert executor.execute(command) == first
    with pytest.raises(ValueError, match="sequence"):
        executor.execute(Command(3, "list_files", {}))
    with pytest.raises(ValueError, match="retry"):
        executor.execute(Command(1, "list_files", {}))
    assert executor.execute(Command(2, "stop", {}))["stopped"]
    with pytest.raises(ValueError, match="stopped"):
        executor.execute(Command(3, "list_files", {}))


def test_paths_and_oversize(tmp_path):
    executor = InProcessExecutor(tmp_path)
    with pytest.raises(ValueError):
        executor.submit("read_file", {"path": "../secret"})
    (tmp_path / "huge").write_text("x" * 100000)
    result = executor.submit("read_file", {"path": "huge"}, limits={"result_bytes": 1024})
    assert result["truncated"]
    assert len(json.dumps(result).encode()) <= 1024
    with pytest.raises(ValueError):
        Command(1, "run", {}, timeout_seconds=0).validate()


def test_environment_allowlist():
    assert clean_environment(
        {"OPENROUTER_API_KEY": "secret", "GEMINI_API_KEY": "secret", "PATH": "/evil", "AWS_SECRET_ACCESS_KEY": "secret"}
    ) == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


class Mailbox:
    def __init__(self, executor):
        self.executor, self.result, self.writes = executor, None, 0

    def put(self, url, data, timeout):
        self.writes += 1
        result = self.executor.execute(Command(**json.loads(data)))
        self.result = json.dumps(result).encode()
        if self.writes == 1:
            raise TimeoutError("lost acknowledgement")

    def get(self, url, timeout):
        return self.result


def test_mailbox_retry_is_idempotent(tmp_path):
    mailbox = Mailbox(InProcessExecutor(tmp_path))
    client = ObjectStoreExecutor("https://store.example/command", "https://store.example/result", transport=mailbox, poll_seconds=0.001)
    assert client.submit("list_files", {})["files"] == []
    assert client.submit("stop", {})["stopped"]
    assert mailbox.writes >= 2


def test_mailbox_timeout():
    class Empty:
        def put(self, *args):
            pass

        def get(self, *args):
            return None

    client = ObjectStoreExecutor("https://store.example/command", "https://store.example/result", transport=Empty(), poll_seconds=0.001)
    with pytest.raises(TimeoutError):
        client.submit("list_files", {}, timeout_seconds=0.01)
    with pytest.raises(RuntimeError, match="uncertain"):
        client.submit("list_files", {})


def test_serve_retries_result_without_reexecuting(tmp_path):
    executor = InProcessExecutor(tmp_path)

    class Transport:
        writes = 0

        def get(self, url, timeout):
            return json.dumps({"seq": 1, "name": "stop", "args": {}, "timeout_seconds": 0.01}).encode()

        def put(self, url, data, timeout):
            self.writes += 1
            if self.writes == 1:
                raise TimeoutError()
            assert json.loads(data)["stopped"]

    transport = Transport()
    serve(executor, "command", "result", transport=transport, deadline_seconds=0.2, poll_seconds=0.001)
    assert transport.writes == 2


def test_local_run_fails_closed_without_namespaces(tmp_path, monkeypatch):
    from openultrasast.search import _sandbox

    def unavailable(**kwargs):
        raise _sandbox.IsolationUnavailable("no namespaces")

    monkeypatch.setattr(_sandbox, "isolation_check", unavailable)
    with pytest.raises(_sandbox.IsolationUnavailable):
        InProcessExecutor(tmp_path).submit("run", {"command": ["/bin/true"]})


def test_task_run_child_environment_is_key_free(tmp_path, monkeypatch):
    from openultrasast.search import _sandbox
    from openultrasast.search import executor as module

    def unavailable(**kwargs):
        raise _sandbox.IsolationUnavailable("no namespaces")

    monkeypatch.setattr(_sandbox, "isolation_check", unavailable)
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret")
    seen = {}

    class Process:
        pid = 123456789
        returncode = 0

        def __init__(self, argv, **kwargs):
            seen.update(kwargs)

        def wait(self, **kwargs):
            pass

    monkeypatch.setattr(module.subprocess, "Popen", Process)
    monkeypatch.setattr(module.os, "killpg", lambda *args: None)
    result = InProcessExecutor(tmp_path, task_boundary=True).submit("run", {"command": ["/bin/true"]})
    assert result["isolation_mode"] == "task-boundary"
    assert seen["env"] == clean_environment()
    assert seen["cwd"] == tmp_path


def test_mailbox_oversize_and_future_sequence():
    class Response:
        value = b"x" * (MAX_RESULT_BYTES + 1)

        def put(self, *args):
            pass

        def get(self, *args):
            return self.value

    response = Response()
    client = ObjectStoreExecutor("https://store.example/command", "https://store.example/result", transport=response)
    with pytest.raises(ValueError, match="large"):
        client.submit("list_files", {})
    response.value = b'{"seq": 9}'
    client = ObjectStoreExecutor("https://store.example/command", "https://store.example/result", transport=response)
    with pytest.raises(ValueError, match="future"):
        client.submit("list_files", {})


def test_archive_rejects_links_and_parent_paths(tmp_path):
    import io
    import tarfile

    from openultrasast.search.executor import unpack_checkout

    for index, name in enumerate(("../escape", "/outside", ".git/config", "link")):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w") as archive:
            member = tarfile.TarInfo(name)
            if name == "link":
                member.type = tarfile.SYMTYPE
                member.linkname = "/outside"
            archive.addfile(member)
        with pytest.raises(ValueError, match="unsafe"):
            unpack_checkout(content.getvalue(), tmp_path / str(index))


@pytest.mark.parametrize("key", ["OPENROUTER_API_KEY", "GEMINI_API_KEY", "OPENAI_KEY", "DEEPSEEK_TOKEN", "GEMINI_TOKEN"])
def test_entrypoint_rejects_initial_credentials(tmp_path, monkeypatch, key):
    import sys

    from openultrasast.search.executor import main

    monkeypatch.setattr(sys, "argv", ["executor", "--repo", str(tmp_path)])
    monkeypatch.setenv(key, "sentinel-not-to-print")
    with pytest.raises(SystemExit, match="refuses inherited credentials"):
        main()


def test_stale_result_is_polled_until_matching_sequence(tmp_path):
    class Stale(Mailbox):
        def get(self, url, timeout):
            if self.writes == 1:
                return b'{"seq": 0, "files": ["stale"]}'
            return self.result

        def put(self, url, data, timeout):
            self.writes += 1
            self.result = json.dumps(self.executor.execute(Command(**json.loads(data)))).encode()

    transport = Stale(InProcessExecutor(tmp_path))
    client = ObjectStoreExecutor("https://store.example/command", "https://store.example/result", transport=transport, poll_seconds=0.001)
    assert client.submit("list_files", {})["files"] == []
    assert transport.writes == 2


def test_task_boundary_run_honors_shorter_argument_timeout(tmp_path, monkeypatch):
    import time

    from openultrasast.search import _sandbox

    def unavailable(**kwargs):
        raise _sandbox.IsolationUnavailable("no namespaces")

    monkeypatch.setattr(_sandbox, "isolation_check", unavailable)
    started = time.monotonic()
    result = InProcessExecutor(tmp_path, task_boundary=True).submit(
        "run", {"command": ["/bin/sleep", "2"], "timeout_seconds": 1}, timeout_seconds=4
    )
    assert result["timed_out"] is True
    assert result["exit_code"] != 0
    assert time.monotonic() - started < 1.8


def test_sandbox_receives_exact_remaining_wall_limit(tmp_path, monkeypatch):
    from openultrasast.sandbox import SandboxResult
    from openultrasast.search import _sandbox

    seen = {}
    monkeypatch.setattr(_sandbox, "isolation_check", lambda **kwargs: seen.update(probe=kwargs["timeout_seconds"]))

    def run(job, **kwargs):
        seen.update(wall=kwargs.get("wall_timeout_seconds"))
        return SandboxResult(0, "", "", False)

    monkeypatch.setattr(_sandbox, "run", run)
    InProcessExecutor(tmp_path).submit("run", {"command": ["/bin/true"]}, timeout_seconds=0.2)
    assert 0 < seen["probe"] <= 0.2
    assert 0 < seen["wall"] <= 0.2
