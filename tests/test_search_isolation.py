"""Root command construction is tested without requiring root privileges."""

import subprocess
from dataclasses import asdict

import pytest

from openultrasast.sandbox import SandboxJob
from openultrasast.search import _sandbox, probe
from openultrasast.search.oracles import BrowserExecutor, Canary, SSRFOracle
from openultrasast.search.verify import SideRecord, VerificationRecord


@pytest.mark.parametrize("uid,mode", [(0, "root-no-userns"), (1000, "userns")])
def test_selection_and_records(monkeypatch, uid, mode):
    monkeypatch.setattr(_sandbox.os, "geteuid", lambda: uid)
    assert _sandbox.isolation_mode() == mode
    assert asdict(SideRecord("observed", (), 0, ""))["isolation_mode"] == mode
    assert asdict(VerificationRecord("inconclusive", (), 0, ""))["isolation_mode"] == mode


@pytest.mark.parametrize("pid", [None, 123])
def test_root_argv(monkeypatch, tmp_path, pid):
    monkeypatch.setattr(_sandbox.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_sandbox.os, "chown", lambda *a, **kw: None)
    monkeypatch.setattr(_sandbox.os, "killpg", lambda *a: None)
    commands = []

    class Process:
        returncode = 0
        pid = 987

        def __init__(self, argv, **kwargs):
            commands.append(argv)
            assert kwargs["pass_fds"]
            assert kwargs["preexec_fn"]

        def wait(self, **kwargs):
            return 0

        def communicate(self, **kwargs):
            return None, None

    monkeypatch.setattr(_sandbox.subprocess, "Popen", Process)
    job = SandboxJob("", ("/bin/true",), tmp_path, {}, 5, 256, 128)
    _sandbox.run(job, scratch=tmp_path, namespace_pid=pid)
    argv = commands[0]
    assert "--unshare-user" not in argv
    assert not any(a.startswith("--user=") for a in argv)
    assert {"--unshare-pid", "--unshare-ipc", "--unshare-uts", "--seccomp"} <= set(argv)
    drop = _sandbox.drop_privileges()
    start = argv.index(drop[0])
    assert argv[start : start + len(drop)] == drop
    assert argv.index("/usr/bin/prlimit") > start
    assert "--nproc=128:128" in argv
    if pid:
        assert "--net=/proc/123/ns/net" in argv
    else:
        assert "/usr/bin/nsenter" not in argv


def test_root_browser(monkeypatch):
    monkeypatch.setattr(_sandbox.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_sandbox.os, "chown", lambda *a, **kw: None)

    def run(argv, **kwargs):
        assert "--unshare-user" not in argv and "--unshare-all" not in argv
        assert "--unshare-net" in argv and "--unshare-pid" in argv
        assert "--no-sandbox" in argv
        assert argv.index("/usr/bin/setpriv") < argv.index("/fake/chromium")
        return subprocess.CompletedProcess(argv, 0, "<html></html>", "")

    monkeypatch.setattr(subprocess, "run", run)
    browser = BrowserExecutor("/fake/chromium")
    assert browser.no_sandbox
    assert not browser("", "nonce")


def test_namespace_diagnostics_precede_failed_preflight(monkeypatch, tmp_path):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "denied")

    def fail():
        assert len(calls) == 8
        raise _sandbox.IsolationUnavailable("denied")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(probe, "image_facts", lambda: {})
    monkeypatch.setattr(_sandbox, "isolation_check", fail)
    record = probe.probe(tmp_path)
    assert record["status"] == "instrument_failure"
    assert set(record["namespaces"]) == {"user", "pid", "net", "ipc", "uts", "cgroup", "mount", "setpriv"}
    assert all(row["exit_code"] == 1 and row["stderr"] == "denied" for row in record["namespaces"].values())
    assert record["isolation_mode"] == "task-boundary"
    assert record["requires_fresh_side_tasks"]


@pytest.mark.parametrize("uid", [0, 1000])
def test_listener_namespace_setup(monkeypatch, tmp_path, uid):
    import os

    monkeypatch.setattr(_sandbox.os, "geteuid", lambda: uid)
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"[123, 4567]\n")
    os.close(write_fd)
    stream = os.fdopen(read_fd)
    commands = []

    class Process:
        stdout = stream

        def __init__(self, argv, **kwargs):
            commands.append(argv)

        def terminate(self):
            pass

        def wait(self, **kwargs):
            return 0

    monkeypatch.setattr(subprocess, "Popen", Process)
    oracle = SSRFOracle()
    try:
        env = oracle.prepare(Canary.fresh(tmp_path / "fixture"))
        assert oracle.namespace_pid == 123
        assert ":4567/" in env["CALLBACK_URL"]
        assert "--net" in commands[0]
        assert ("--user" in commands[0]) == (uid != 0)
        assert ("--map-root-user" in commands[0]) == (uid != 0)
    finally:
        oracle.close()


def test_root_fixture_permissions_and_browser_records(monkeypatch, tmp_path):
    from openultrasast.sandbox import SandboxResult
    from openultrasast.search import verify as verifier

    monkeypatch.setattr(_sandbox.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_sandbox, "isolation_check", lambda **kw: None)
    sides, demos = probe.materialise(tmp_path / "pair", "path")
    app_calls = []

    def run(job, *, scratch, mounts, **kwargs):
        if "/fixture" in mounts:
            fixture = mounts["/fixture"]
            assert fixture.name == "app-fixture"
            original = fixture.parent / "fixture"
            assert original.stat().st_mode & 0o777 == 0o700
            assert (original / "canary").stat().st_mode & 0o777 == 0o600
            assert (fixture / "canary").read_bytes() == (original / "canary").read_bytes()
            assert fixture.stat().st_mode & 0o777 == 0o555
            app_calls.append(job)
        return SandboxResult(0, "", "", False)

    monkeypatch.setattr(_sandbox, "run", run)
    browser = BrowserExecutor("/fake/chromium")
    record = verifier.verify(*sides, demos["real"], "path", browser=browser)
    assert app_calls
    assert record.isolation_mode == "root-no-userns"
    assert record.chromium_no_sandbox
    assert all(s.chromium_no_sandbox and s.isolation_mode == "root-no-userns" for s in record.sides)


def test_devnull_can_be_opened_by_nested_launcher(tmp_path):
    """The HTTP driver's Popen opens /dev/null inside bwrap, before any socket."""
    _sandbox.isolation_check()
    source = tmp_path / "input"
    source.write_text("readable")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    code = (
        "from pathlib import Path; import subprocess; "
        "print(Path('/workspace/input').stat().st_size); "
        "p=subprocess.Popen(['/bin/true'], stdin=subprocess.DEVNULL, "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
        "raise SystemExit(p.wait())"
    )
    result = _sandbox.run(SandboxJob("", ("/usr/bin/python3", "-I", "-c", code), tmp_path, {}, 5, 256, 128), scratch=scratch)
    assert result.stdout.strip() == "8", result
    assert result.exit_code == 0 and not result.timed_out, result
