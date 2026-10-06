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
    ) == {"PATH": "/venv/bin:/opt/java/openjdk/bin:/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "JAVA_HOME": "/opt/java/openjdk"}


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
        client.submit("stop", {})


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
    serve(executor, "command", "result", transport=transport, deadline_seconds=1, poll_seconds=0.001)
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


def test_spawn_failure_has_diagnostic(tmp_path):
    result = InProcessExecutor(tmp_path, task_boundary=True).execute(Command(1, "run", {"command": ["/missing-executor-program"]}))
    assert result["phase"] == "spawn"
    assert result["exit_code"] is None
    assert "FileNotFoundError:" in result["reason"]
    assert "No such file" in result["reason"]


def test_timeout_preserves_child_diagnostics(tmp_path):
    import sys

    result = InProcessExecutor(tmp_path, task_boundary=True).execute(
        Command(
            1,
            "run",
            {"command": [sys.executable, "-c", "import sys,time; print('before timeout',file=sys.stderr,flush=True); time.sleep(10)"]},
            0.3,
        )
    )
    assert result["phase"] == "timeout"
    assert result["exit_code"] is not None
    assert result["stderr"] == "before timeout"
    assert result["reason"].startswith("TimeoutError:")


def test_upload_failure_reports_phase(tmp_path, monkeypatch):
    app = InProcessExecutor(tmp_path, task_boundary=True)

    def upload(command):
        app.phase = "result upload"
        raise OSError("upload HTTP 403 https://host/path?X-Amz-Signature=secret")

    monkeypatch.setattr(app, "_execute", upload)
    result = app.execute(Command(1, "prepare_verification", {}))
    assert result["phase"] == "result upload"
    assert "HTTP 403" in result["reason"]
    assert "secret" not in result["reason"]


def test_diagnostics_sanitize_before_tail_and_keep_twenty_lines(monkeypatch):
    from openultrasast.search.task_storage import diagnostic, exception_reason

    monkeypatch.setenv("SERVICE_TOKEN", "environment-secret")
    detail = (
        "https://host/repo?X-Amz-Signature=url-secret Authorization: Bearer bearer-secret X-Amz-Signature=bare-secret environment-secret"
    )
    result = exception_reason(ValueError(detail))
    assert result.startswith("ValueError:") and len(result) <= 300
    for secret in ("url-secret", "bearer-secret", "bare-secret", "environment-secret", "host/repo"):
        assert secret not in result
    assert len(diagnostic("\n".join(str(i) for i in range(40)), maximum=4000).splitlines()) == 20
    assert len(exception_reason(ValueError("x" * 1000))) <= 300


def test_guard_io_failure_after_child_exit_is_not_success(tmp_path, monkeypatch):
    import sys

    from openultrasast.search import task_storage

    checks = []
    original = task_storage.check

    def check(*args, **kwargs):
        checks.append(1)
        if len(checks) >= 3:
            raise PermissionError("cache cannot be read")
        return original(*args, **kwargs)

    monkeypatch.setattr(task_storage, "check", check)
    result = InProcessExecutor(tmp_path, task_boundary=True).execute(Command(1, "run", {"command": [sys.executable, "-c", "pass"]}))
    assert result["error"] == "PermissionError"
    assert result["phase"] == "scratch guard"
    assert result["exit_code"] is not None
    assert "cache cannot be read" in result["reason"]


@pytest.mark.parametrize("side", ["host", "task"])
@pytest.mark.parametrize("method", ["put", "get"])
@pytest.mark.parametrize("error", ["timeout", "connection", "503"])
def test_transient_mailbox_failures_retry_same_sequence(tmp_path, monkeypatch, side, method, error):
    import urllib.error

    from openultrasast.search import executor as module

    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(module.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))
    app = InProcessExecutor(tmp_path)
    failures, payloads, results = [], [], []

    def fail():
        failures.append(now[0])
        if len(failures) <= 4:
            if error == "503":
                raise urllib.error.HTTPError("https://store.example", 503, "unavailable", {}, None)
            raise (TimeoutError if error == "timeout" else ConnectionError)("temporary store failure")

    class Flaky:
        def put(self, url, data, timeout):
            payloads.append(data)
            if side == "host":
                results[:] = [app.execute(Command(**json.loads(data)))]
            if method == "put":
                fail()

        def get(self, url, timeout):
            if method == "get":
                fail()
            if side == "host":
                return json.dumps(results[-1]).encode()
            return Command(1, "stop", {}, 1).validate()

    if side == "host":
        client = ObjectStoreExecutor("https://store.example/command", "https://store.example/result", transport=Flaky())
        assert client.submit("stop", {}, timeout_seconds=1)["stopped"]
        assert client.seq == 1 and not client.uncertain
    else:
        serve(app, "command", "result", transport=Flaky(), deadline_seconds=100)
    assert app.seq == 1 and app.stopped
    assert len(set(payloads)) == 1
    assert len(failures) == 5 and now[0] > 1


def test_retry_budget_is_90_seconds_and_permanent_http_errors_fail_fast(monkeypatch):
    import urllib.error

    from openultrasast.search import executor as module

    now, calls = [0.0], []
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(module.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))

    def fail(timeout):
        calls.append(timeout)
        raise TimeoutError("still unavailable")

    with pytest.raises(TimeoutError):
        module.retry_mailbox(fail)
    assert now[0] == 90 and all(0 < value <= 10 for value in calls)

    def forbidden(timeout):
        raise urllib.error.HTTPError("https://store.example", 403, "forbidden", {}, None)

    with pytest.raises(urllib.error.HTTPError):
        module.retry_mailbox(forbidden)
    assert now[0] == 90


def test_uncertain_command_can_be_resubmitted_without_changing_seq(tmp_path):
    class Lost(Mailbox):
        available = False

        def put(self, url, data, timeout):
            self.writes += 1
            self.result = json.dumps(self.executor.execute(Command(**json.loads(data)))).encode()

        def get(self, url, timeout):
            return self.result if self.available else None

    (tmp_path / "input").write_text("original")
    mailbox = Lost(InProcessExecutor(tmp_path))
    client = ObjectStoreExecutor("https://store.example/command", "https://store.example/result", transport=mailbox, poll_seconds=0.001)
    with pytest.raises(TimeoutError):
        client.submit("read_file", {"path": "input"}, timeout_seconds=0.01)
    (tmp_path / "input").write_text("changed")
    mailbox.available = True
    assert client.submit("read_file", {"path": "input"})["text"] == "original"
    assert client.seq == 1


def test_url_transport_uploads_file_without_buffering(tmp_path):
    from contextlib import nullcontext

    from openultrasast.search.executor import URLTransport

    path = tmp_path / "archive"
    path.write_bytes(b"synthetic archive" * 10000)
    transport = URLTransport()
    seen = {}

    class Opener:
        def open(self, request, timeout):
            assert request.get_method() == "PUT"
            assert not isinstance(request.data, bytes)
            seen["length"] = int(request.get_header("Content-length"))
            seen["bytes"] = 0
            while block := request.data.read(8192):
                seen["bytes"] += len(block)
            return nullcontext()

    transport.opener = Opener()
    with path.open("rb") as stream:
        transport.put("https://files.example/archive", stream, 10)
    assert seen["length"] == seen["bytes"] == path.stat().st_size
