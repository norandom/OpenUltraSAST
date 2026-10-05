"""Owned observations and adversarial artefacts, with real isolated toy processes."""

import os
import shutil
import signal
import socket
from pathlib import Path

import pytest

from openultrasast.search.verify import Side, verify

FIXTURE = Path(__file__).parent / "fixtures/search/app.py"
PAYLOADS = {
    "path": "../canary",
    "sql": "' OR public=0 --",
    "command": '; touch "$PROOF_MARKER"',
    "ssrf": "$CALLBACK_URL",
}


@pytest.fixture
def pair(tmp_path):
    sides = []
    for name in ("vulnerable", "fixed"):
        root = tmp_path / name
        root.mkdir()
        shutil.copyfile(FIXTURE, root / "app.py")
        if name == "fixed":
            (root / "fixed").touch()
        sides.append(Side(root, ("/usr/bin/python3", "-I", "/workspace/app.py")))
    demo = tmp_path / "demo"
    demo.mkdir()
    (demo / "build.sh").write_text("test -s /workspace/app.py\n")
    return sides, demo


def request(demo, family):
    import json

    (demo / "request.json").write_text(json.dumps([family, PAYLOADS[family]]))


@pytest.mark.parametrize("family", ["path", "sql", "command", "ssrf"])
def test_real_differential(pair, family):
    if family == "ssrf":
        try:
            with socket.socket():
                pass
        except PermissionError:
            pytest.skip("host policy prohibits even localhost sockets")
    sides, demo = pair
    request(demo, family)
    result = verify(*sides, demo, family)
    assert result.outcome == "demonstrated", result
    assert [r.observed for r in result.sides[0].runs] == [True] * 3
    assert [r.observed for r in result.sides[1].runs] == [False] * 3
    assert result.elapsed_seconds > 0


@pytest.mark.parametrize(
    "script",
    [
        "cat /fixture/canary; echo success; exit 42",
        "if test ! -f /workspace/fixed; then echo demonstrated; fi",
        "echo hacked > /workspace/sitecustomize.py",
        "echo hacked > /usr/lib/python3.12/sitecustomize.py",
        "echo hacked > /deps/0/module.py",
        "cat /proc/1/environ; echo demonstrated",
        '/usr/bin/python3 -I -c "import socket; socket.create_connection(("127.0.0.1",12345))"',
    ],
)
def test_gaming_cannot_demonstrate(pair, tmp_path, script):
    sides, demo = pair
    deps = tmp_path / "deps"
    deps.mkdir()
    (deps / "module.py").write_text("original")
    sides = [Side(s.checkout, s.command, dependencies=(deps,)) for s in sides]
    (demo / "attack.sh").write_text(script)
    result = verify(*sides, demo, "path")
    assert result.outcome != "demonstrated"
    assert (deps / "module.py").read_text() == "original"
    assert not (sides[0].checkout / "sitecustomize.py").exists()


def test_attack_exit_and_stdout_ignored(pair):
    sides, demo = pair
    (demo / "attack.sh").write_text('"$TARGET" path ../canary\necho fake\nexit 99\n')
    assert verify(*sides, demo, "path").outcome == "demonstrated"


def test_safe_build_failure_is_inconclusive(pair):
    sides, demo = pair
    request(demo, "path")
    (demo / "build.sh").write_text("test ! -f /workspace/fixed")
    result = verify(*sides, demo, "path")
    assert result.outcome == "inconclusive"
    assert result.sides[1].outcome == "could_not_build"


def test_readiness_failure(pair):
    sides, demo = pair
    request(demo, "path")
    (sides[1].checkout / "broken").touch()
    result = verify(*sides, demo, "path")
    assert result.outcome == "inconclusive"
    assert result.sides[1].outcome == "could_not_run"


@pytest.mark.parametrize("family", ["xss", "deserialisation", "access_control", "secrets"])
def test_no_oracle(pair, family):
    sides, demo = pair
    assert verify(*sides, demo, family).outcome == "no_oracle"


def test_flaky_observation_is_inconclusive(pair, monkeypatch):
    from openultrasast.search import oracles

    nonces = iter(["a" * 48, "b" * 48, "c" * 48] * 2)
    monkeypatch.setattr(oracles.secrets, "token_hex", lambda _: next(nonces))
    sides, demo = pair
    (sides[0].checkout / "flaky").touch()
    request(demo, "path")
    result = verify(*sides, demo, "path")
    assert result.outcome == "inconclusive"
    assert [r.observed for r in result.sides[0].runs] == [True, False, False]


def test_environment_injection_stays_in_artefact(pair, monkeypatch):
    sides, demo = pair
    monkeypatch.setenv("PYTHONPATH", "/bogus")
    monkeypatch.setenv("NODE_OPTIONS", "--require=/bogus")
    monkeypatch.setenv("LD_PRELOAD", "/bogus")
    (demo / "attack.sh").write_text(
        'test -z "$PYTHONPATH$NODE_OPTIONS$LD_PRELOAD" || exit 3\n'
        'echo "raise RuntimeError()" > /scratch/sitecustomize.py\n'
        "export PYTHONPATH=/scratch NODE_OPTIONS=--require=/scratch/sitecustomize.py LD_PRELOAD=/bogus\n"
        '"$TARGET" path ../canary\n'
    )
    assert verify(*sides, demo, "path").outcome == "demonstrated"


def test_untracked_file_outside_scratch_refused(pair):
    sides, demo = pair
    (demo / "attack.sh").write_text('echo hacked > /untracked\n"$TARGET" path ../canary\n')
    assert verify(*sides, demo, "path").outcome == "inconclusive"


def test_unknown_app_failure_cannot_prove_effect(pair):
    sides, demo = pair
    (sides[0].checkout / "app.py").write_text('raise RuntimeError("no app")')
    request(demo, "path")
    assert verify(*sides, demo, "path").outcome == "could_not_run"


def test_affected_build_failure(pair):
    sides, demo = pair
    request(demo, "path")
    (demo / "build.sh").write_text("test -f /workspace/fixed")
    assert verify(*sides, demo, "path").outcome == "could_not_build"


def test_missing_isolation_fails_closed(pair, monkeypatch):
    from openultrasast.search import _sandbox

    def unavailable(*args, **kwargs):
        raise FileNotFoundError("bwrap unavailable")

    monkeypatch.setattr(_sandbox, "run", unavailable)
    sides, demo = pair
    request(demo, "path")
    with pytest.raises(_sandbox.IsolationUnavailable, match="bwrap unavailable"):
        verify(*sides, demo, "path")


def test_bwrap_failure_raises_before_product_outcomes(pair, monkeypatch):
    from openultrasast.sandbox import SandboxResult
    from openultrasast.search import _sandbox

    calls = []
    stderr = "bwrap: Creating new namespace failed: Resource temporarily unavailable"

    def failed(job, **kwargs):
        calls.append(job)
        return SandboxResult(1, "", stderr, False)

    monkeypatch.setattr(_sandbox, "run", failed)
    sides, demo = pair
    with pytest.raises(_sandbox.IsolationUnavailable, match=stderr):
        verify(*sides, demo, "path")
    assert len(calls) == 1
    assert calls[0].command == ("/bin/cat", "/workspace/probe")


def test_verification_with_many_host_processes(pair, monkeypatch):
    from openultrasast.search import _sandbox

    checks = []
    original = _sandbox.isolation_check

    def checked(**kwargs):
        checks.append(True)
        return original(**kwargs)

    monkeypatch.setattr(_sandbox, "isolation_check", checked)
    sides, demo = pair
    request(demo, "path")
    children = []
    try:
        for _ in range(300):
            pid = os.fork()
            if pid == 0:
                try:
                    while True:
                        signal.pause()
                finally:
                    os._exit(0)
            children.append(pid)
        assert verify(*sides, demo, "path").outcome == "demonstrated"
        assert checks == [True]
    finally:
        for pid in children:
            os.kill(pid, signal.SIGKILL)
        for pid in children:
            os.waitpid(pid, 0)


def test_symlink_input_refused(pair):
    sides, demo = pair
    (demo / "escape").symlink_to("/etc/passwd")
    request(demo, "path")
    assert verify(*sides, demo, "path").outcome == "inconclusive"


def test_xss_executor_contract(tmp_path):
    from openultrasast.search.oracles import Canary, oracle_for

    calls = []

    def browser(document, nonce):
        calls.append((document, nonce))
        return document == "<script>execute()</script>"

    oracle = oracle_for("xss", browser)
    canary = Canary.fresh(tmp_path / "fixture")
    assert oracle.prepare(canary) == {}
    oracle.capture("<script>execute()</script>")
    assert oracle.observe()[0]
    assert calls == [("<script>execute()</script>", canary.nonce)]


def test_six_fresh_canaries(pair, monkeypatch):
    from openultrasast.search import oracles

    nonces = []
    prepare = oracles.PathOracle.prepare

    def record(self, canary):
        nonces.append(canary.nonce)
        return prepare(self, canary)

    monkeypatch.setattr(oracles.PathOracle, "prepare", record)
    sides, demo = pair
    request(demo, "path")
    assert verify(*sides, demo, "path").outcome == "demonstrated"
    assert len(set(nonces)) == 6


def test_readiness_effect_cannot_prove_ssrf(pair, monkeypatch):
    from openultrasast.search import verify as module
    from openultrasast.search.oracles import OutputOracle

    class ReadinessOracle(OutputOracle):
        def observe(self):
            return True, "request during readiness"

    monkeypatch.setattr(module, "oracle_for", lambda *args: ReadinessOracle())
    sides, demo = pair
    result = module.verify(*sides, demo, "ssrf")
    assert result.outcome == "inconclusive"
    assert not result.sides[0].runs


def test_dependency_hash_detects_replacement(pair, tmp_path, monkeypatch):
    from openultrasast.search import _sandbox

    original = _sandbox.run
    dependency = tmp_path / "dependency"
    dependency.mkdir()
    (dependency / "module.py").write_text("original")
    sides, demo = pair
    sides = [Side(s.checkout, s.command, dependencies=(dependency,)) for s in sides]
    request(demo, "path")

    def changed(job, **kwargs):
        result = original(job, **kwargs)
        if job.command[-1] == "/demo/build.sh":
            (kwargs["mounts"]["/deps/0"] / "module.py").write_text("replacement")
        return result

    monkeypatch.setattr(_sandbox, "run", changed)
    result = verify(*sides, demo, "path")
    assert result.outcome == "inconclusive"
    assert result.sides[0].reason == "build changed immutable inputs"


def test_trusted_build_products_are_used_readonly(pair):
    sides, demo = pair
    sides = [
        Side(s.checkout, ("/usr/bin/python3", "-I", "/build/app.py"), build_command=("/bin/cp", "/workspace/app.py", "/scratch/app.py"))
        for s in sides
    ]
    request(demo, "path")
    assert verify(*sides, demo, "path").outcome == "demonstrated"
    (demo / "build.sh").write_text("echo patched > /build/app.py")
    assert verify(*sides, demo, "path").outcome == "inconclusive"


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


def test_attacker_sees_only_external_bridge_and_scratch(pair):
    sides, demo = pair
    (demo / "attack.sh").write_text(
        "test ! -e /workspace/app.py || exit 3\n"
        "test ! -e /fixture/canary || exit 3\n"
        "test ! -e /build/app.py || exit 3\n"
        "test ! -e /deps/0 || exit 3\n"
        'test -z "$CALLBACK_URL$PROOF_MARKER$DATABASE$SERVED_ROOT" || exit 3\n'
        '"$TARGET" path ../canary\n'
    )
    assert verify(*sides, demo, "path").outcome == "demonstrated"


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
