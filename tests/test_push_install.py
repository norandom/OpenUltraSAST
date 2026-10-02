"""`ousast pre-push install|uninstall` and the hook-callable Docker wrapper (task 17.6, Req 7.4, 9.6)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from test_push_runner import history

from openultrasast.cli import main
from openultrasast.push.install import install, packaged, uninstall

OPS = Path(__file__).resolve().parents[1] / "ops"


def repo(tmp_path):
    root, base, head, git = history(tmp_path)
    git("config", "core.hooksPath", ".custom-hooks")
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    git("remote", "add", "origin", str(remote))
    return root, git


def test_packaged_hook_and_wrapper_are_the_ops_scripts():
    assert packaged("pre-push") == (OPS / "pre-push").read_bytes()
    assert packaged("ousast-docker") == (OPS / "ousast-docker").read_bytes()


def test_install_uninstall_through_the_cli_honours_hooks_path(tmp_path, capsys):
    root, git = repo(tmp_path)
    assert main(["pre-push", "install", str(root)]) == 0
    hook = root / ".custom-hooks" / "pre-push"
    assert hook.read_bytes() == packaged("pre-push") and os.access(hook, os.X_OK)
    assert git("config", "core.hooksPath") == ".custom-hooks"
    assert main(["pre-push", "install", str(root)]) == 1  # already installed: refused without --force
    assert "already installed" in capsys.readouterr().err
    assert main(["pre-push", "install", str(root), "--force"]) == 0
    assert main(["pre-push", "uninstall", str(root)]) == 0
    assert not hook.exists()


def test_existing_hook_is_refused_then_chained_and_restored(tmp_path):
    root, git = repo(tmp_path)
    hooks = root / ".custom-hooks"
    hooks.mkdir()
    log = tmp_path / "prior-input"
    original = f'#!/bin/sh\ncat > "{log}"\nexit 0\n'.encode()
    (hooks / "pre-push").write_bytes(original)
    (hooks / "pre-push").chmod(0o755)
    code, lines = install(root)
    assert code == 1 and "existing pre-push hook" in lines[0] and (hooks / "pre-push").read_bytes() == original
    code, lines = install(root, force=True)
    assert code == 0 and (hooks / "pre-push.before-ousast").read_bytes() == original
    env = {**os.environ, "OUSAST_COMMAND": "ousast-not-installed-anywhere", "OUSAST_ARTIFACT_DIR": str(tmp_path / "a")}
    pushed = subprocess.run(["git", "-C", str(root), "push", "origin", "HEAD:refs/heads/main"], env=env, capture_output=True)
    assert pushed.returncode == 0 and "refs/heads/main" in log.read_text()
    code, _ = uninstall(root)
    assert code == 0 and (hooks / "pre-push").read_bytes() == original
    assert not (hooks / "pre-push.before-ousast").exists()
    code, lines = uninstall(root)
    assert code == 1 and "not written by OpenUltraSAST" in lines[0]


def fake_docker(tmp_path, *, inspect=0, run=0):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "docker-args"
    stdin = tmp_path / "docker-stdin"
    script = f'#!/bin/sh\nif [ "$1" = image ]; then exit {inspect}; fi\nprintf "%s\\n" "$@" > "{record}"\ncat > "{stdin}"\nexit {run}\n'
    (bin_dir / "docker").write_text(script)
    (bin_dir / "docker").chmod(0o755)
    return bin_dir, record, stdin


def test_docker_install_routes_the_hook_through_the_wrapper_with_stdin_and_mounts(tmp_path):
    root, git = repo(tmp_path)
    assert install(root, docker=True)[0] == 0
    bin_dir, record, stdin = fake_docker(tmp_path)
    artifacts = tmp_path / "artifacts"
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "OUSAST_ARTIFACT_DIR": str(artifacts)}
    env.pop("OUSAST_COMMAND", None)
    pushed = subprocess.run(["git", "-C", str(root), "push", "origin", "HEAD:refs/heads/main"], env=env, capture_output=True)
    assert pushed.returncode == 0, pushed.stderr
    args = record.read_text().splitlines()
    real = str(root.resolve())
    assert args[:2] == ["run", "--rm"] and "-i" in args and "--network" in args and "none" in args
    assert f"{real}:{real}:ro" in args and str(artifacts.resolve()) + ":" + str(artifacts.resolve()) in args
    assert args[args.index("-w") + 1] == real
    assert "ghcr.io/norandom/openultrasast:2.0.1" in args and "pre-push" in args and "--remote" in args
    assert stdin.read_text().startswith("HEAD ") and "refs/heads/main" in stdin.read_text()


@pytest.mark.parametrize(("inspect", "run", "needle"), [(1, 0, "is not present"), (0, 125, "could not start")])
def test_wrapper_failures_never_block(tmp_path, inspect, run, needle):
    bin_dir, _, _ = fake_docker(tmp_path, inspect=inspect, run=run)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "OUSAST_ARTIFACT_DIR": str(tmp_path / "artifacts")}
    result = subprocess.run(
        [str(OPS / "ousast-docker"), "pre-push", ".", "--artifact", str(tmp_path / "x" / "r.json")],
        env=env,
        cwd=tmp_path,
        input=b"",
        capture_output=True,
    )
    assert result.returncode == 0 and needle.encode() in result.stdout


@pytest.mark.parametrize(("mode", "status", "expected"), [("blocking", 1, 1), ("advisory", 1, 0), ("advisory", 2, 0)])
def test_only_explicit_blocking_passes_a_nonzero_exit_through(tmp_path, mode, status, expected):
    bin_dir, _, _ = fake_docker(tmp_path, run=status)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "OUSAST_ARTIFACT_DIR": str(tmp_path / "artifacts"),
        "OUSAST_PUSH_MODE": mode,
    }
    result = subprocess.run([str(OPS / "ousast-docker"), "pre-push", "."], env=env, cwd=tmp_path, input=b"", capture_output=True)
    assert result.returncode == expected


def test_hook_passes_optional_settings_only_when_set():
    text = (OPS / "pre-push").read_text()
    assert '--engine "$OUSAST_PUSH_ENGINE"' in text and 'if [ -n "${OUSAST_PUSH_ENGINE:-}" ]' in text
