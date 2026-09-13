"""Real local Git pushes; never install in the project being developed."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from test_push_runner import history


@pytest.mark.parametrize("prior_exit", [0, 7])
def test_existing_hook_stdin_remote_exit_and_removal(tmp_path, prior_exit):
    root, base, head, git = history(tmp_path)
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    git("remote", "add", "origin", str(remote))
    hooks = root / ".custom-hooks"
    hooks.mkdir()
    git("config", "core.hooksPath", ".custom-hooks")
    hook = hooks / "pre-push"
    prior = hooks / "pre-push.before-ousast"
    log = tmp_path / "prior-input"
    args = tmp_path / "prior-args"
    prior.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{args}"\ncat > "{log}"\nexit {prior_exit}\n')
    prior.chmod(0o755)
    shutil.copyfile(Path(__file__).resolve().parents[1] / "ops/pre-push", hook)
    hook.chmod(0o755)
    before = (root / ".git/index").read_bytes(), (root / "api.js").read_bytes(), git("rev-parse", "HEAD")
    env = {
        **os.environ,
        "PATH": str(Path(".venv/bin").resolve()) + os.pathsep + os.environ["PATH"],
        "OUSAST_ARTIFACT_DIR": str(tmp_path / "artifacts"),
        "OUSAST_PUSH_DEADLINE": "0.1",
    }
    result = subprocess.run(["git", "-C", str(root), "push", "origin", "HEAD:refs/heads/test"], env=env, capture_output=True)
    assert (result.returncode == 0) == (prior_exit == 0), result.stderr
    assert log.read_text() == f"HEAD {head} refs/heads/test {'0' * 40}\n"
    assert args.read_text().splitlines() == ["origin", str(remote)]
    assert ((root / ".git/index").read_bytes(), (root / "api.js").read_bytes(), git("rev-parse", "HEAD")) == before
    assert git("config", "core.hooksPath") == ".custom-hooks"
    assert list((tmp_path / "artifacts").glob("*.json"))
    # Explicit removal restores the prior hook byte-for-byte, without config/source/ref edits.
    original = prior.read_bytes()
    hook.unlink()
    prior.rename(hook)
    assert hook.read_bytes() == original
    result = subprocess.run(["git", "-C", str(root), "push", "origin", "HEAD:refs/heads/after-removal"], env=env, capture_output=True)
    assert (result.returncode == 0) == (prior_exit == 0)
    assert "refs/heads/after-removal" in log.read_text()


def test_install_refuses_existing_and_honors_hooks_path(tmp_path):
    root, _, _, git = history(tmp_path)
    git("config", "core.hooksPath", ".custom-hooks")
    installer = Path(__file__).resolve().parents[1] / "ops/install-pre-push"
    first = subprocess.run([str(installer), str(root)], capture_output=True)
    assert first.returncode == 0, first.stderr
    hook = root / ".custom-hooks/pre-push"
    hook.write_text("#!/bin/sh\nexit 23\n")
    before = hook.read_bytes()
    second = subprocess.run([str(installer), str(root)], capture_output=True)
    assert second.returncode != 0
    assert hook.read_bytes() == before
    assert git("config", "core.hooksPath") == ".custom-hooks"


def test_chain_preserves_exact_nonzero_even_for_advisory(tmp_path):
    import sys

    root, _, _, _ = history(tmp_path)
    prior = tmp_path / "prior"
    prior.write_text("#!/bin/sh\ncat >/dev/null\nexit 23\n")
    prior.chmod(0o755)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "openultrasast.cli",
            "pre-push",
            str(root),
            "--artifact",
            str(tmp_path / "result.json"),
            "--prior-hook",
            str(prior),
            "--remote",
            "origin",
            "/tmp/remote",
        ],
        input=b"",
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 23


def test_install_refuses_dangling_symlink(tmp_path):
    root, _, _, git = history(tmp_path)
    git("config", "core.hooksPath", ".custom-hooks")
    hooks = root / ".custom-hooks"
    hooks.mkdir()
    target = tmp_path / "must-not-create"
    (hooks / "pre-push").symlink_to(target)
    installer = Path(__file__).resolve().parents[1] / "ops/install-pre-push"
    result = subprocess.run([str(installer), str(root)], capture_output=True)
    assert result.returncode != 0
    assert not target.exists()
