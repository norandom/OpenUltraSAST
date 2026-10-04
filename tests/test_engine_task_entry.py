"""Offline AX worker entry controls; HTTP is loopback only."""

import importlib.util
import io
import json
import tarfile
import threading
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "benchmarks/learn"


def load(name):
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(SCRIPTS))
        spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


def test_engine_cluster_heap_flags(monkeypatch):
    worker = load("engine_trace_worker")
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Xmx9999m")
    backend = worker.MeasuredBackend(30, 10, lambda: None, heap_profile="cluster")
    flags = (
        "-Xms1700m -Xmx1700m -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=128m "
        "-XX:MaxDirectMemorySize=256m -Xss512k -XX:ActiveProcessorCount=2 -XX:+UseG1GC"
    )
    assert backend._jvm_env()["JAVA_TOOL_OPTIONS"] == flags
    assert backend._heap_flag() == "-J-Xmx1700m"
    assert worker.MeasuredBackend(30, 10, lambda: None)._heap_flag() == "-J-Xmx2560m"


@pytest.mark.parametrize("readiness", ["ready", "delayed", "closed", "source_denied"])
@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("transport", ["memory", "loopback"])
def test_task_entry_http_roundtrip(tmp_path, monkeypatch, failure, transport, readiness):
    entry = load("engine_task_entry")
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        data = b"print('input proof')\n"
        info = tarfile.TarInfo("app.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    pin = {"pin": "abc", "units": [{"unit": "u", "supported": True}], "questions": {"u": {}}}
    uploads = []
    gets = []
    puts = []
    started = time.monotonic()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            gets.append((self.path, time.monotonic() - started))
            if readiness == "source_denied" and self.path == "/source":
                self.send_response(403)
                self.end_headers()
                return
            if readiness == "closed" or (readiness == "delayed" and gets[-1][1] < 3):
                self.send_response(403 if len(gets) % 2 else 503)
                self.end_headers()
                return
            data = archive.getvalue() if self.path == "/source" else json.dumps(pin).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(data)

        def do_PUT(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            puts.append(time.monotonic())
            if readiness == "closed" and len(puts) == 1:
                self.send_response(403)
                self.end_headers()
                return
            uploads.append(body)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    fake_worker = tmp_path / "worker.py"
    fake_worker.write_text(
        "import argparse,json,pathlib,sys\np=argparse.ArgumentParser()\n"
        "for key in ['worker','root','output','deadline','question-deadline','heap-profile']: p.add_argument('--'+key)\n"
        "a=p.parse_args()\nassert a.heap_profile == 'cluster'\n"
        "assert (pathlib.Path(a.root)/'app.py').stat().st_size > 0\n"
        + ("sys.exit(7)\n" if failure else "pathlib.Path(a.output).write_text(json.dumps({'done':True,'units':[]}))\n")
    )
    if transport == "loopback":
        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError:
            pytest.skip("sandbox prohibits loopback sockets; in-memory HTTP roundtrip still runs")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
    else:
        base = "https://fake-store.invalid"

        def urlopen(request, timeout):
            method = request.get_method() if hasattr(request, "get_method") else "GET"
            url = request.full_url if hasattr(request, "full_url") else request
            body = request.data or b"" if method == "PUT" else b""
            raw = f"{method} {url.removeprefix(base)} HTTP/1.0\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body

            class Socket:
                def __init__(self):
                    self.sent = bytearray()

                def makefile(self, *args):
                    return io.BytesIO(raw)

                def sendall(self, data):
                    self.sent.extend(data)

            connection = Socket()
            Handler(connection, ("127.0.0.1", 0), None)
            headers, payload = bytes(connection.sent).split(b"\r\n\r\n", 1)
            status = int(headers.split()[1])
            if status != 200:
                raise urllib.error.HTTPError(url, status, "denied", {}, io.BytesIO(payload))
            return io.BytesIO(payload)

        monkeypatch.setattr(entry.urllib.request, "urlopen", urlopen)
    try:
        for name, suffix in [("SOURCE_URL", "source"), ("QUESTIONS_URL", "questions"), ("RESULT_URL", "result")]:
            monkeypatch.setenv(name, base + "/" + suffix)
        budget = 0.7 if readiness == "closed" else 60
        assert entry.main(work_root=tmp_path / "work", worker_script=fake_worker, readiness_budget=budget) == 0
        if readiness == "delayed":
            assert len(gets) >= 5
            assert gets[-1][1] >= 3
        if readiness == "closed":
            assert 0.7 <= puts[0] - started < 1.5
            assert len(puts) == 2
            assert puts[1] - puts[0] >= 0.5
            assert all(path == "/questions" for path, _ in gets)
    finally:
        if transport == "loopback":
            server.shutdown()
            thread.join()
            server.server_close()
    assert len(uploads) == 1
    with tarfile.open(fileobj=io.BytesIO(uploads[0])) as tar:
        result = json.load(tar.extractfile("result.json"))
    assert result["done"]
    if readiness == "closed":
        assert result["status"] == "failed"
        assert result["reason"] == "GET questions: egress not open after 60 s"
        assert json.loads((tmp_path / "work/out/result.json").read_text()) == result
    elif readiness == "source_denied":
        assert result["status"] == "failed"
        assert result["reason"] == "GET source: HTTP 403"
        assert result["units"][0]["reason"] == "GET source: HTTP 403"
        assert base not in json.dumps(result)
        assert json.loads((tmp_path / "work/out/result.json").read_text()) == result
    elif failure:
        assert result["units"][0]["status"] == "failed"
        assert "7" in result["units"][0]["reason"]


def test_engine_cluster_profile_recorded_on_input_failure(tmp_path):
    worker = load("engine_trace_worker")
    pin = {
        "units": [{"unit": "u", "file": "missing.py", "language": "python", "supported": True, "reason": ""}],
        "questions": {"u": {}},
    }
    result = worker.worker(pin, tmp_path, tmp_path / "result.json", 30, 10, heap_profile="cluster")
    assert result["units"][0]["status"] == "failed"
    assert result["instrument"]["heap_profile"] == "cluster"
    assert result["instrument"]["heap_mb"] == 1700
    assert result["instrument"]["java_tool_options"] == worker.CLUSTER_JVM_FLAGS


def test_task_entry_rejects_tar_traversal(tmp_path):
    entry = load("engine_task_entry")
    source = tmp_path / "source.tar"
    with tarfile.open(source, "w") as archive:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="unsafe"):
        entry.unpack(source, tmp_path / "case")
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("error", [urllib.error.URLError("refused"), ConnectionResetError("reset")])
def test_readiness_connection_errors_back_off_to_cap(tmp_path, monkeypatch, error):
    entry = load("engine_task_entry")
    now = [0.0]
    pauses = []
    timeouts = []

    def pause(seconds):
        pauses.append(seconds)
        now[0] += seconds

    def refused(request, timeout):
        timeouts.append(timeout)
        raise error

    monkeypatch.setattr(entry.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(entry.time, "sleep", pause)
    monkeypatch.setattr(entry.urllib.request, "urlopen", refused)
    with pytest.raises(RuntimeError, match="^egress not open after 60 s$"):
        entry.download("https://fake.invalid", tmp_path / "input", readiness_budget=60)
    assert now[0] == 60
    assert pauses[:5] == [0.5, 1, 2, 4, 8]
    assert max(pauses) == 8
    assert timeouts[-1] == pauses[-1]


@pytest.mark.parametrize("status, attempts", [(403, 3), (503, 3), (404, 1)])
def test_later_transfers_keep_short_retry(monkeypatch, status, attempts):
    entry = load("engine_task_entry")
    calls = []
    pauses = []

    def refused(request, timeout):
        calls.append(timeout)
        raise urllib.error.HTTPError(request, status, "denied", {}, io.BytesIO())

    monkeypatch.setattr(entry.time, "sleep", pauses.append)
    monkeypatch.setattr(entry.urllib.request, "urlopen", refused)
    with pytest.raises(urllib.error.HTTPError):
        entry.transfer("https://fake.invalid")
    assert len(calls) == attempts
    assert pauses == list(range(1, attempts))
