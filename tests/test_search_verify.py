"""Schema-only verification, owned observations and adversarial public inputs."""

import json
import socket

import pytest

from openultrasast.search import _sandbox
from openultrasast.search.probe import materialise
from openultrasast.search.verify import RunObservation, SideRecord, verify, verify_side_task


@pytest.fixture
def pair(tmp_path):
    sides, demos = materialise(tmp_path / "pair", "path")
    return sides, demos["real"]


def edit(demo, change):
    path = demo / "demo.json"
    value = json.loads(path.read_text())
    change(value)
    path.write_text(json.dumps(value))


@pytest.mark.parametrize("family", ["path", "sql", "command", "ssrf"])
def test_real_differential(tmp_path, family):
    if family == "ssrf":
        try:
            with socket.socket():
                pass
        except PermissionError:
            pytest.skip("host policy prohibits localhost sockets")
    sides, demos = materialise(tmp_path / family, family)
    assert (sides[0].checkout / "app.py").stat().st_size > 0
    result = verify(
        *sides, demos["real"], {"sql": "injection", "command": "injection", "ssrf": "untrusted_destination"}.get(family, family)
    )
    assert result.outcome == "demonstrated", result
    assert [r.observed for r in result.sides[0].runs] == [True] * 3
    assert [r.observed for r in result.sides[1].runs] == [False] * 3
    assert result.isolation_mode == _sandbox.isolation_mode()


@pytest.mark.parametrize("argument", ["/fixture/canary", "/proc/1/environ", "${CANARY}", "$CALLBACK_URL"])
def test_gaming_private_references_rejected_before_process(pair, argument, monkeypatch):
    sides, demo = pair
    edit(demo, lambda value: value["steps"][0].update(arguments=[argument]))
    monkeypatch.setattr(_sandbox, "run", lambda *a, **kw: pytest.fail("invalid demo spawned a process"))
    result = verify(*sides, demo, "path")
    assert result.outcome == "inconclusive"
    assert "invalid declarative demo" in result.reason


def test_legacy_scripts_rejected_before_process(pair, monkeypatch):
    sides, demo = pair
    (demo / "attack.sh").write_text("echo demonstrated")
    monkeypatch.setattr(_sandbox, "run", lambda *a, **kw: pytest.fail("script executed"))
    assert verify(*sides, demo, "path").outcome == "inconclusive"


def test_safe_build_failure_inconclusive(pair):
    sides, demo = pair
    (sides[1].checkout / "app.py").unlink()
    result = verify(*sides, demo, "path")
    assert result.outcome == "inconclusive"
    assert result.sides[1].outcome == "could_not_build"


def test_affected_build_failure(pair):
    sides, demo = pair
    (sides[0].checkout / "app.py").unlink()
    assert verify(*sides, demo, "path").outcome == "could_not_build"


def test_readiness_failure(pair):
    sides, demo = pair
    (sides[1].checkout / "broken").touch()
    result = verify(*sides, demo, "path")
    assert result.outcome == "inconclusive"
    assert result.sides[1].outcome == "could_not_run"


@pytest.mark.parametrize("family", ["deserialization", "access_control", "config_secrets"])
def test_no_oracle(pair, family):
    sides, demo = pair
    assert verify(*sides, demo, family).outcome == "no_oracle"


def test_flaky_observation_inconclusive(pair, monkeypatch):
    from openultrasast.search import oracles

    nonces = iter(["a" * 48, "b" * 48, "c" * 48] * 2)
    monkeypatch.setattr(oracles.secrets, "token_hex", lambda _: next(nonces))
    sides, demo = pair
    (sides[0].checkout / "flaky").touch()
    result = verify(*sides, demo, "path")
    assert result.outcome == "inconclusive"
    assert [r.observed for r in result.sides[0].runs] == [True, False, False]


def test_no_inherited_environment(pair, monkeypatch):
    for key in ("PYTHONPATH", "NODE_OPTIONS", "LD_PRELOAD", "GEMINI_API_KEY"):
        monkeypatch.setenv(key, "/bogus-key")
    sides, demo = pair
    assert verify(*sides, demo, "path").outcome == "demonstrated"


def test_symlink_input_refused(pair):
    sides, demo = pair
    (sides[0].checkout / "escape").symlink_to("/etc/passwd")
    assert verify(*sides, demo, "path").outcome != "demonstrated"


def test_six_fresh_canaries(pair, monkeypatch):
    from openultrasast.search import oracles

    nonces = []
    prepare = oracles.PathOracle.prepare

    def record(self, canary):
        nonces.append(canary.nonce)
        return prepare(self, canary)

    monkeypatch.setattr(oracles.PathOracle, "prepare", record)
    sides, demo = pair
    assert verify(*sides, demo, "path").outcome == "demonstrated"
    assert len(set(nonces)) == 6


def test_missing_isolation_requires_fresh_task_dispatcher(pair, monkeypatch):
    def failed(**kwargs):
        raise _sandbox.IsolationUnavailable("namespace denied")

    monkeypatch.setattr(_sandbox, "isolation_check", failed)
    sides, demo = pair
    with pytest.raises(_sandbox.IsolationUnavailable, match="fresh-task dispatcher"):
        verify(*sides, demo, "path")
    calls = []

    def dispatch(**kwargs):
        calls.append(kwargs)
        observed = kwargs["side"] == sides[0]
        return SideRecord("observed", (RunObservation(observed, "", 0),) * 3, 0, "", isolation_mode="task-boundary")

    result = verify(*sides, demo, "path", task_dispatcher=dispatch)
    assert result.outcome == "demonstrated"
    assert result.isolation_mode == "task-boundary"
    assert len(calls) == 2 and all(call["fresh_task"] for call in calls)


def test_task_side_runs_one_repetition_without_model_environment(pair, monkeypatch):
    sides, demo = pair
    monkeypatch.setenv("GEMINI_API_KEY", "must-not-leak")
    for side in sides:
        source = side.checkout / "app.py"
        source.write_text('import os\nassert "GEMINI_API_KEY" not in os.environ\n' + source.read_text())
    monkeypatch.setattr(_sandbox, "run", lambda *a, **kw: pytest.fail("task entry attempted namespaces"))
    result = verify_side_task(sides[0], demo, "path")
    assert result.outcome == "observed", result.reason
    assert len(result.runs) == 1 and result.runs[0].observed
    assert result.isolation_mode == "task-boundary"


def test_capture_canary_cannot_replay(pair):
    sides, demo = pair
    edit(demo, lambda value: value["steps"][0].update(capture={"name": "stolen", "source": "output"}))
    result = verify(*sides, demo, "path")
    assert result.outcome != "demonstrated"
    assert "canary values cannot be captured" in result.sides[0].reason


def test_ordered_cli_capture_and_stdin(pair):
    sides, demo = pair
    app = """import json, os, sys
if sys.argv[1:] == ['--ready']: sys.exit(0)
if sys.argv[1:] == ['token']: print(json.dumps({'token':'public-token'}))
elif sys.argv[1:] == ['use', 'public-token'] and sys.stdin.read() == 'public-token':
    from pathlib import Path
    if not (Path(__file__).parent / 'fixed').exists(): print((Path(os.environ['SERVED_ROOT']).parent / 'canary').read_text())
"""
    for side in sides:
        (side.checkout / "app.py").write_text(app)
    edit(
        demo,
        lambda value: value.update(
            steps=[
                {"type": "cli", "arguments": ["token"], "capture": {"name": "token", "source": "json", "path": ["token"]}},
                {"type": "cli", "arguments": ["use", "${token}"], "stdin": "${token}"},
            ]
        ),
    )
    assert verify(*sides, demo, "path").outcome == "demonstrated"


def test_http_steps_and_capture(pair):
    try:
        with socket.socket():
            pass
    except PermissionError:
        pytest.skip("host policy prohibits localhost sockets")
    sides, demo = pair
    app = """from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import json, os
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200); self.end_headers()
  if self.path == '/token': result=json.dumps({'token':'public-token'})
  elif self.path == '/use/public-token' and not (Path(__file__).parent/'fixed').exists():
   result=(Path(os.environ['SERVED_ROOT']).parent/'canary').read_text()
  else: result='safe'
  self.wfile.write(result.encode())
 def log_message(self, *args): pass
HTTPServer(('127.0.0.1', 18765), Handler).serve_forever()
"""
    for side in sides:
        (side.checkout / "app.py").write_text(app)

    def change(value):
        value["start"].update(mode="http", port=18765)
        value["steps"] = [
            {"type": "http", "method": "GET", "path": "/token", "capture": {"name": "token", "source": "json", "path": ["token"]}},
            {"type": "http", "method": "GET", "path": "/use/${token}"},
        ]

    edit(demo, change)
    result = verify(*sides, demo, "path")
    assert result.outcome == "demonstrated", result


def test_private_namespace_handoff_without_sockets(tmp_path):
    import subprocess

    from openultrasast.sandbox import SandboxJob
    from openultrasast.search import _sandbox

    # Proves the actual nsenter -> bwrap handoff without requiring socket().
    process = subprocess.Popen(
        [
            "/usr/bin/unshare",
            "--user",
            "--map-root-user",
            "--net",
            "/usr/bin/python3",
            "-I",
            "-c",
            "import os,time; print(os.getpid(), flush=True); time.sleep(10)",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        pid = int(process.stdout.readline())
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        job = SandboxJob("", ("/usr/bin/python3", "-I", "-c", 'print("namespace-ready")'), tmp_path, {}, 3, 256, 128)
        result = _sandbox.run(job, scratch=scratch, namespace_pid=pid)
        assert result.exit_code == 0, result.stderr
        assert result.stdout.strip() == "namespace-ready"
    finally:
        process.terminate()
        process.wait(timeout=3)
        process.stdout.close()


def test_listener_accepts_nonce_path_for_post_without_sockets(monkeypatch, capsys):
    import fcntl
    import http.server
    import io

    from openultrasast.search import oracles

    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Connection:
        def __init__(self, path):
            self.input = io.BytesIO(b"POST " + path + b" HTTP/1.0\r\nContent-Length: 0\r\n\r\n")

        def makefile(self, *args):
            return self.input

        def sendall(self, data):
            pass

    class Server:
        server_port = 12345

        def __init__(self, address, handler):
            self.handler = handler

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def serve_forever(self):
            for path in (b"/wrong", b"/secret?query=1"):
                self.handler(Connection(path), ("127.0.0.1", 1), self)

    monkeypatch.setattr(socket, "socket", lambda *args: Socket())
    monkeypatch.setattr(fcntl, "ioctl", lambda *args: None)
    monkeypatch.setattr(http.server, "HTTPServer", Server)
    oracles._listen("secret")
    assert capsys.readouterr().out.splitlines()[1:] == ["observed"]


def test_pip_products_imported_by_runtime_and_immutable(pair, monkeypatch):
    from openultrasast.sandbox import SandboxResult

    sides, demo = pair
    for side in sides:
        source = side.checkout / "app.py"
        source.write_text("import dependency\nassert dependency.VALUE == 42\n" + source.read_text())
        (side.checkout / "requirements.txt").write_text("dependency==1\n")
    edit(demo, lambda value: value["build"].update(recipe="pip", arguments=["requirements.txt"]))
    original = _sandbox.run
    builds = []

    def runner(job, **kwargs):
        if "pip" in job.command:
            assert "--no-index" in job.command and "--no-deps" in job.command
            packages = kwargs["scratch"] / "packages"
            packages.mkdir()
            (packages / "dependency.py").write_text("VALUE = 42\n")
            builds.append(job)
            return SandboxResult(0, "", "", False)
        return original(job, **kwargs)

    monkeypatch.setattr(_sandbox, "run", runner)
    result = verify(*sides, demo, "path")
    assert result.outcome == "demonstrated", result
    assert len(builds) == 6


@pytest.mark.parametrize("count", [0, 1, 2, 4])
def test_dispatcher_incomplete_repetitions_never_demonstrate(pair, monkeypatch, count):
    sides, demo = pair

    def unavailable(**kwargs):
        raise _sandbox.IsolationUnavailable("denied")

    monkeypatch.setattr(_sandbox, "isolation_check", unavailable)

    def dispatch(**kwargs):
        return SideRecord("observed", (RunObservation(kwargs["side"] == sides[0], "", 0),) * count, 0, "", isolation_mode="task-boundary")

    assert verify(*sides, demo, "path", task_dispatcher=dispatch).outcome == "inconclusive"


def test_json_file_accepted_without_directory_wrapper(pair):
    sides, demo = pair
    assert verify(*sides, demo / "demo.json", "path").outcome == "demonstrated"


def test_http_startup_effect_vetoed_before_request_steps(tmp_path):
    from openultrasast.sandbox import SandboxJob, SandboxResult
    from openultrasast.search.verify import _http_steps

    checks = []

    def runner(job, **kwargs):
        config = json.loads(kwargs["input_text"])
        (kwargs["scratch"] / config["ready"]).touch()
        # A startup effect must veto the go signal; no requests get authorized.
        import time

        time.sleep(0.05)
        assert not (kwargs["scratch"] / config["go"]).exists()
        return SandboxResult(1, "", "not authorized", False)

    def check():
        checks.append(True)
        raise ValueError("startup effect")

    with pytest.raises(ValueError, match="startup effect"):
        _http_steps(
            {"steps": []},
            (),
            lambda command: SandboxJob("", command, tmp_path, {}, 1, 256, 128),
            tmp_path,
            {},
            {},
            None,
            "nonce",
            runner,
            check,
        )
    assert checks == [True]


def test_explicit_task_dispatcher_used_on_userns_host(pair, monkeypatch):
    sides, demo = pair
    monkeypatch.setattr(_sandbox, "isolation_check", lambda **kwargs: pytest.fail("remote verification must not probe local execution"))
    calls = []

    def dispatch(**kwargs):
        calls.append(kwargs)
        return SideRecord("observed", (RunObservation(kwargs["side"] == sides[0], "", 0),) * 3, 0, "", isolation_mode="task-boundary")

    result = verify(*sides, demo, "path", task_dispatcher=dispatch)
    assert result.outcome == "demonstrated" and len(calls) == 2
    assert result.isolation_mode == "task-boundary"


@pytest.mark.parametrize("handshake", [False, True])
def test_http_driver_requires_readiness_and_complete_outputs(tmp_path, handshake):
    from openultrasast.sandbox import SandboxJob, SandboxResult
    from openultrasast.search.verify import _http_steps

    def runner(job, **kwargs):
        config = json.loads(kwargs["input_text"])
        if handshake:
            (kwargs["scratch"] / config["ready"]).touch()
        return SandboxResult(0, "[]", "", False)

    with pytest.raises(ValueError, match="readiness|invalid HTTP driver output"):
        _http_steps(
            {"steps": [{}]},
            (),
            lambda command: SandboxJob("", command, tmp_path, {}, 1, 256, 128),
            tmp_path,
            {},
            {},
            None,
            "nonce",
            runner,
            lambda: None,
        )


def test_generated_build_links_confined_and_hashed(tmp_path):
    from openultrasast.search.verify import _tree

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    module = checkout / "node_modules" / "package"
    module.mkdir(parents=True)
    (module / "cli.js").write_text("original")
    bins = checkout / "node_modules" / ".bin"
    bins.mkdir()
    (bins / "cli").symlink_to("../package/cli.js")
    initial = _tree(checkout, generated_links=True)
    with pytest.raises(ValueError, match="links"):
        _tree(checkout)
    (module / "cli.js").write_text("changed")
    assert _tree(checkout, generated_links=True) != initial
    (bins / "escape").symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="escapes"):
        _tree(checkout, generated_links=True)


@pytest.mark.parametrize("target", ["missing", "link", "."])
def test_generated_dangling_and_cyclic_links_rejected(tmp_path, target):
    from openultrasast.search.verify import _tree

    (tmp_path / "link").symlink_to(target)
    with pytest.raises(ValueError, match="dangling|cyclic"):
        _tree(tmp_path, generated_links=True)


def test_http_failure_keeps_exception_tail(tmp_path):
    from openultrasast.sandbox import SandboxJob, SandboxResult
    from openultrasast.search.verify import _http_steps

    traceback = "Traceback (most recent call last):\n" + "  frame\n" * 200 + "FileNotFoundError: /dev/null\n"
    with pytest.raises(ValueError, match="FileNotFoundError: /dev/null"):
        _http_steps(
            {"steps": []},
            ("/bin/true",),
            lambda command: SandboxJob("", command, tmp_path, {}, 1, 256, 128),
            tmp_path,
            {},
            {},
            None,
            "nonce",
            lambda *a, **kw: SandboxResult(1, "", traceback, False),
            lambda: None,
        )


@pytest.mark.parametrize(
    "family,oracle",
    [
        ("injection", "sql"),
        ("injection", "command"),
        ("path", "path"),
        ("output_encoding", "xss"),
        ("untrusted_destination", "ssrf"),
    ],
)
def test_verifier_routes_demo_oracle(pair, monkeypatch, family, oracle):
    from openultrasast.search import verify as module
    from openultrasast.search.oracles import BrowserExecutor

    sides, demo = pair
    edit(demo, lambda value: value.update(oracle=oracle))
    seen = []
    monkeypatch.setattr(_sandbox, "isolation_check", lambda **kwargs: None)

    def side(checkout, artefact, kind, *args):
        seen.append(kind)
        return SideRecord("could_not_run", (), 0, "stub")

    monkeypatch.setattr(module, "_side", side)
    result = verify(*sides, demo, family, oracle=oracle, browser=BrowserExecutor() if oracle == "xss" else None)
    assert seen == [oracle, oracle] and result.outcome != "no_oracle"
    edit(demo, lambda value: value.update(oracle="path" if oracle != "path" else "sql"))
    seen.clear()
    result = verify(*sides, demo, family)
    assert result.outcome == "inconclusive" and not seen
    assert "not allowed" in result.reason


def test_xss_without_browser_is_unavailable_not_no_oracle(pair):
    sides, demo = pair
    edit(demo, lambda value: value.update(oracle="xss"))
    result = verify(*sides, demo, "output_encoding")
    assert result.outcome == "inconclusive" and "runtime unavailable" in result.reason


def test_app_requires_environment_and_data_files_on_both_sides(pair):
    sides, demo = pair
    for side in sides:
        path = side.checkout / "app.py"
        source = path.read_text()
        startup = (
            "import os\nfrom pathlib import Path\n"
            "assert os.environ['JWT_SECRET'] == 'local-test-key'\n"
            "assert Path(os.environ['JWT_KEY_FILE']).read_text() == 'local-key-data'\n"
        )
        path.write_text(startup + source)
    missing = verify(*sides, demo, "path")
    assert missing.outcome == "inconclusive", missing
    assert [side.outcome for side in missing.sides] == ["could_not_run", "could_not_run"]
    edit(
        demo,
        lambda value: value["start"].update(
            environment={"JWT_SECRET": "local-test-key", "JWT_KEY_FILE": ".demo/keys/jwt.pem"},
            files={"keys/jwt.pem": "local-key-data"},
        ),
    )
    result = verify(*sides, demo, "path")
    assert result.outcome == "demonstrated", result
    assert all(len(side.runs) == 3 for side in result.sides)
    assert all(not (side.checkout / ".demo").exists() for side in sides)


@pytest.mark.parametrize("delay,timeout,expected", [(8, None, "observed"), (8, 1, "could_not_run")])
def test_delayed_http_readiness_and_timeout_diagnostics(pair, monkeypatch, delay, timeout, expected):
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
    except PermissionError:
        pytest.skip("host policy prohibits localhost sockets")
    sides, demo = pair
    app = f"""import sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
print('x' * 2000 + ' boot stdout token=hidden', flush=True)
print('y' * 2000 + ' boot stderr password=hidden', file=sys.stderr, flush=True)
time.sleep({delay})
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(503); self.end_headers()
  self.wfile.write(b'listening')
 def log_message(self, *args): pass
HTTPServer(('127.0.0.1', {port}), Handler).serve_forever()
"""
    (sides[0].checkout / "app.py").write_text(app)

    def change(value):
        value["start"].update(mode="http", port=port)
        value["steps"] = [{"type": "http", "method": "GET", "path": "/attack"}]

    edit(demo, change)
    result = verify_side_task(sides[0], demo, "path", timeout)
    assert result.outcome == expected, result
    assert "boot stdout" in result.stdout and "boot stderr" in result.stderr
    assert "hidden" not in result.stdout + result.stderr
    assert len(result.stdout) <= 1500 and len(result.stderr) <= 1500
    if expected == "observed":
        assert result.ready_seconds >= 8
        assert len(result.runs) == 1
    else:
        assert result.phase == "start" and result.exit_code != 0
        assert 0.9 <= result.ready_seconds < 4
        assert not result.runs


def test_killed_http_driver_retains_app_logs(pair, monkeypatch):
    from openultrasast.sandbox import SandboxResult
    from openultrasast.search import verify as module

    sides, demo = pair
    edit(
        demo,
        lambda value: (
            value["start"].update(mode="http", port=18080),
            value.update(steps=[{"type": "http", "method": "GET", "path": "/"}]),
        ),
    )

    def killed(job, **kwargs):
        config = json.loads(kwargs["input_text"])
        for key in ("output", "errors"):
            (kwargs["scratch"] / config[key]).write_text("app log token=hidden")
        return SandboxResult(-9, "", "", True)

    monkeypatch.setattr(module, "_run_task", killed)
    result = verify_side_task(sides[0], demo, "path", 1)
    assert result.phase == "start" and result.exit_code == -9
    assert result.ready_seconds >= 0
    assert result.stdout == result.stderr == "app log token=[redacted]"


@pytest.mark.parametrize("timeout,ready", [(90, True), (1, False)])
def test_http_driver_polls_eight_second_listener_before_get_and_steps(tmp_path, monkeypatch, capsys, timeout, ready):
    import http.client
    import io
    import subprocess
    import sys
    import time
    from types import SimpleNamespace

    from openultrasast.search import demo as demo_module
    from openultrasast.search.verify import _HTTP_DRIVER

    tick = [0.0]
    polls, requests = [], []
    monkeypatch.setattr(time, "monotonic", lambda: tick[0])

    def sleep(seconds):
        assert seconds == 0.5
        tick[0] += seconds

    monkeypatch.setattr(time, "sleep", sleep)

    def connect(address, timeout):
        assert address == ("127.0.0.1", 18080)
        polls.append(tick[0])
        if tick[0] < 8:
            raise ConnectionRefusedError()
        return SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(socket, "create_connection", connect)

    class HTTP:
        def __init__(self, host, port, timeout):
            assert tick[0] >= 8

        def request(self, method, path, **kwargs):
            requests.append((method, path))

        def getresponse(self):
            return SimpleNamespace(status=503, read=lambda size: b"listening")

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", HTTP)

    def app(*args, **kwargs):
        kwargs["stdout"].write(b"boot stdout")
        kwargs["stderr"].write(b"boot stderr")
        return SimpleNamespace(poll=lambda: None, terminate=lambda: None, wait=lambda **kw: None)

    monkeypatch.setattr(subprocess, "Popen", app)
    config = dict(
        schema={"start": {"port": 18080}, "steps": [{"method": "GET", "path": "/attack"}]},
        command=["fake-app"],
        timeout=timeout,
        nonce="nonce",
        ready="ready",
        go="go",
        errors="errors",
        output="output",
    )
    (tmp_path / "go").touch()
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(config)))
    driver = _HTTP_DRIVER.replace("/verifier-demo.py", demo_module.__file__).replace("/scratch/", str(tmp_path) + "/")
    if ready:
        exec(driver, {})
        assert requests == [("GET", "/"), ("GET", "/attack")]
        assert json.loads(capsys.readouterr().out) == ["listening"]
        assert tick[0] == 8
    else:
        with pytest.raises(RuntimeError, match="readiness timed out"):
            exec(driver, {})
        assert not requests and not (tmp_path / "ready").exists()
    assert polls == [i * 0.5 for i in range(len(polls))]
    assert (tmp_path / "output").read_text() == "boot stdout"
    assert (tmp_path / "errors").read_text() == "boot stderr"
