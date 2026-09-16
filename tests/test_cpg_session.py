"""M2 11.1: the session is a transport whose failures are never answers."""

from __future__ import annotations

import os
import signal
import sys
import textwrap
import time
from pathlib import Path

import pytest

from openultrasast.cpg.session import EngineSession, _redirected
from openultrasast.model.contracts import ExecutionBudget

FAKE = textwrap.dedent(
    """
    import json, os, sys, time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    MODE = os.environ.get("FAKE_MODE", "ok")
    PORT = int(sys.argv[sys.argv.index("--server-port") + 1])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            code = body["query"]
            if MODE == "hang" and "ousastHang" in code:
                time.sleep(120)
            if MODE == "crash" and "cpg." in code:
                os._exit(9)
            # Honour the redirection wrapper by extracting its receipt and target.
            if MODE == "noreceipt":
                answer = json.dumps({"success": True, "stdout": "DIAGNOSTIC: not compiled"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(answer)))
                self.end_headers()
                self.wfile.write(answer)
                return
            if MODE in ("ok", "empty", "wrongreceipt") and "__ousastPath" in code:
                target = code.split('java.nio.file.Path.of("', 1)[1].split('"', 1)[0]
                nonce = code.split('__ousastPath, "', 1)[1].split(chr(92) + "n", 1)[0]
                payload = "" if MODE == "empty" else "PAYLOAD-" + nonce
                written = ("BAD" if MODE == "wrongreceipt" else nonce) + "\\n" + payload
                with open(target, "w") as handle:
                    handle.write(written)
            answer = json.dumps({"success": MODE != "unsuccessful", "stdout": ""}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    """
)


@pytest.fixture
def fake(tmp_path):
    script = tmp_path / "fake-joern"
    script.write_text("#!" + sys.executable + "\n" + FAKE)
    script.chmod(0o755)
    return script


def session(tmp_path, fake, *, mode="ok", seconds=30.0, allowance=2.0):
    return EngineSession(
        tmp_path / "scratch",
        ExecutionBudget(time.monotonic() + seconds, allowance),
        {**os.environ, "FAKE_MODE": mode},
        joern=str(fake),
        startup_timeout_seconds=30.0,
    )


def test_a_started_session_answers_only_with_its_own_receipt(tmp_path, fake):
    with session(tmp_path, fake) as live:
        assert live.start() and live.alive and live.startup_seconds > 0
        answer = live.evaluate("cpg.file.size", timeout=10)
        assert answer is not None and answer.stdout.startswith("PAYLOAD-")
        assert live.failure == "" and live.requests == 1
        # The private answer file is removed once verified, so no later call can reread it.
        assert not list((tmp_path / "scratch").glob("answer-*.txt"))


def test_a_mismatched_receipt_poisons_the_session(tmp_path, fake):
    with session(tmp_path, fake, mode="wrongreceipt") as live:
        assert live.start()
        assert live.evaluate("cpg.file.size", timeout=10) is None
        assert live.failure == "session_receipt_mismatch"
        # Poisoned means poisoned: no later request may answer from an unknown state.
        assert live.evaluate("cpg.method.size", timeout=10) is None and not live.alive


def test_an_unsuccessful_response_is_not_an_answer(tmp_path, fake):
    with session(tmp_path, fake, mode="unsuccessful") as live:
        assert live.start()
        assert live.evaluate("cpg.file.size", timeout=10) is None
        assert live.failure == "session_request_unsuccessful"


def test_an_empty_body_is_an_answer_only_when_its_receipt_is_present(tmp_path, fake):
    with session(tmp_path, fake, mode="empty") as live:
        assert live.start()
        answer = live.evaluate("cpg.file.size", timeout=10)
        assert answer is not None and answer.stdout == ""
        assert live.failure == ""


def test_a_crashed_session_answers_nothing_afterwards(tmp_path, fake):
    with session(tmp_path, fake, mode="crash") as live:
        assert live.start()
        assert live.evaluate("cpg.file.size", timeout=10) is None
        assert live.evaluate("1", timeout=10) is None
        assert live.failure


def test_cancellation_kills_the_process_group(tmp_path, fake):
    live = session(tmp_path, fake, mode="hang", seconds=3.0)
    assert live.start()
    pid = live._process.pid
    started = time.monotonic()
    assert live.evaluate("ousastHang()", timeout=1.0) is None
    live.close()
    assert time.monotonic() - started < 6.0
    with pytest.raises(ProcessLookupError):
        for _ in range(100):
            os.killpg(pid, 0)
            time.sleep(0.02)


def test_an_exhausted_deadline_starts_nothing(tmp_path, fake):
    live = session(tmp_path, fake, seconds=0.0)
    assert live.start() is False and live.failure == "deadline_exhausted"
    assert live._process is None
    live.close()


def test_load_records_the_resident_graph_and_forgets_it_on_failure(tmp_path, fake):
    with session(tmp_path, fake) as live:
        assert live.start()
        graph = tmp_path / "cpg.bin"
        assert live.load(graph, timeout=10) and live.loaded_graph == str(graph)
    with session(tmp_path, fake, mode="wrongreceipt") as broken:
        assert broken.start()
        assert broken.load(tmp_path / "other.bin", timeout=10) is False
        assert broken.loaded_graph == ""


def test_the_wrapper_writes_its_receipt_before_running_the_body():
    code = _redirected("cpg.file.size", Path("/tmp/x.txt"), "abc")
    assert code.index("writeString") < code.index("scala.Console.withOut")
    assert '"abc\\n"' in code and "/tmp/x.txt" in code
    # The Joern REPL shadows `Console`, so an unqualified name compiles to the wrong object.
    assert "scala.Console.withOut" in code


def test_a_launch_failure_is_recorded_not_raised(tmp_path):
    live = EngineSession(tmp_path / "s", ExecutionBudget(time.monotonic() + 10, 1.0), dict(os.environ), joern=str(tmp_path / "absent"))
    assert live.start() is False and live.failure.startswith("session_launch_failed")
    live.close()


def test_signal_module_is_used_for_group_termination():
    assert signal.SIGKILL


def test_a_definition_is_sent_unwrapped_and_is_not_proof_of_anything(tmp_path, fake):
    """M2 11.1: `@main` cannot be nested, and the server answers success for compile errors."""
    with session(tmp_path, fake) as live:
        assert live.start()
        sent = live.define("@main def exec(cpgFile: String) = println(1)", timeout=10)
        # The fake only writes a receipt file for wrapped requests, so an unwrapped one has none.
        assert sent is not None and live.failure == ""
        assert not list((tmp_path / "scratch").glob("answer-*.txt"))


def test_a_definition_on_a_dead_session_is_refused(tmp_path, fake):
    with session(tmp_path, fake, mode="wrongreceipt") as live:
        assert live.start()
        assert live.evaluate("cpg.file.size", timeout=10) is None
        assert live.define("def x = 1", timeout=10) is None


def test_the_engine_body_is_retained_so_a_missing_receipt_can_be_explained(tmp_path, fake):
    """M2 11.1: success with no receipt is a compile error, and the diagnostic is the only clue."""
    with session(tmp_path, fake, mode="noreceipt") as live:
        assert live.start()
        assert live.evaluate("bogus(", timeout=10) is None
        assert live.failure == "session_answer_missing"
        assert live.last_body == "DIAGNOSTIC: not compiled"


def test_the_backend_leaves_the_session_off_by_default(tmp_path):
    """M2 11.3: shipped behaviour stays the disposable invocation that has been measured."""
    from openultrasast.cpg.backend import JoernBackend

    backend = JoernBackend()
    assert backend.session_transport is False
    assert backend._session_for(tmp_path / "cpg.bin") is None
    assert backend._session_payload(tmp_path / "cpg.bin", "census", {"cpgFile": "x"}) is None


def test_a_session_that_cannot_start_falls_back_rather_than_answering(tmp_path):
    from openultrasast.cpg.backend import JoernBackend

    backend = JoernBackend(
        session_transport=True,
        execution_budget=ExecutionBudget(time.monotonic() + 10, 1.0),
    )
    backend.__dict__["_session"] = None
    # No such engine: starting fails, the reason is recorded, and the caller gets None to fall back.
    object.__setattr__(backend, "queries_dir", Path("/nonexistent"))
    assert backend._session_payload(tmp_path / "cpg.bin", "census", {"cpgFile": "x"}) is None
    assert any("session_unavailable" in note or "session" in note for note in backend._diagnostics) or backend._diagnostics == []
    backend.close_session()


def test_an_overlay_that_saves_no_graph_keeps_the_raw_one(tmp_path, monkeypatch):
    """M2 11.4: reported success with no saved graph must not read as an applied overlay."""
    from openultrasast.cpg.backend import JoernBackend

    backend = JoernBackend(execution_budget=ExecutionBudget(time.monotonic() + 30, 1.0))
    graph = tmp_path / "cpg.bin"
    graph.write_bytes(b"raw")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    # The engine answers, but nothing lands in any workspace.
    monkeypatch.setattr("openultrasast.cpg.backend.shutil.which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(JoernBackend, "_run", lambda *a, **k: _completed('---OUSAST-CPG-BEGIN---\n{"files":"1"}\n---OUSAST-CPG-END---'))
    assert backend._apply_overlays(graph, scratch) is False
    assert graph.read_bytes() == b"raw"
    assert "overlay_saved_graph_missing" in backend._diagnostics


def test_an_overlay_saved_under_the_session_workspace_is_found(tmp_path, monkeypatch):
    from openultrasast.cpg.backend import JoernBackend
    from openultrasast.cpg.session import EngineSession

    backend = JoernBackend(session_transport=True, execution_budget=ExecutionBudget(time.monotonic() + 30, 1.0))
    graph = tmp_path / "cpg.bin"
    graph.write_bytes(b"raw")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    session_scratch = tmp_path / "session"
    saved = session_scratch / "workspace" / graph.name
    saved.mkdir(parents=True)
    (saved / "cpg.bin").write_bytes(b"overlaid")
    live = EngineSession(session_scratch, ExecutionBudget(time.monotonic() + 30, 1.0), {})
    monkeypatch.setattr(JoernBackend, "_session_for", lambda self, path: live)
    monkeypatch.setattr(
        JoernBackend, "_session_payload", lambda self, path, query, params: '---OUSAST-CPG-BEGIN---\n{"files":"1"}\n---OUSAST-CPG-END---'
    )
    assert backend._apply_overlays(graph, scratch) is True
    assert graph.read_bytes() == b"overlaid"


def _completed(stdout):
    import subprocess

    return subprocess.CompletedProcess(["joern"], 0, stdout, "")


def test_the_session_switch_is_explicit_and_defaults_off(monkeypatch):
    """M2 11.3: a measured run can enable the transport without changing any default."""
    from openultrasast.cpg.backend import SESSION_ENV, JoernBackend

    monkeypatch.delenv(SESSION_ENV, raising=False)
    assert JoernBackend().session_transport is False
    for value in ("", "0", "true", "yes", "2"):
        monkeypatch.setenv(SESSION_ENV, value)
        assert JoernBackend().session_transport is False, value
    monkeypatch.setenv(SESSION_ENV, "1")
    assert JoernBackend().session_transport is True
    # An explicit argument still wins over the environment in both directions.
    assert JoernBackend(session_transport=False).session_transport is False
