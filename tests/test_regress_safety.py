"""Reject unsafe regression snippets before the sandbox runner sees them (task 4.3)."""

from pathlib import Path

import pytest

from openultrasast.regress import RegressionRunner, UnsafeSnippetError, check_snippet_safety
from openultrasast.sandbox import FakeSandboxRunner, SandboxJob

BENIGN_ASSERT = "assert 1 + 1 == 2\n"


def _job(tmp_path: Path, snippet: str) -> SandboxJob:
    repo = tmp_path / "repo"
    repo.mkdir()
    return SandboxJob(
        image="python:3.12-alpine",
        command=("python", "/scratch/case.py"),
        repo_root=repo,
        scratch_files={"case.py": snippet},
        timeout_seconds=30,
        memory_mb=256,
        pids_limit=128,
    )


def test_docker_sock_rejected_does_not_create_runner_job(tmp_path: Path) -> None:
    snippet = 'client = docker.DockerClient(base_url="unix://var/run/docker.sock")\n'
    sandbox = FakeSandboxRunner()
    runner = RegressionRunner(sandbox)

    with pytest.raises(UnsafeSnippetError, match="Docker socket"):
        check_snippet_safety(snippet)
    verdict = runner.run_snippet(snippet, _job(tmp_path, snippet))

    assert verdict.verdict == "inconclusive"
    assert verdict.reason == "safety_rejected"
    assert sandbox.jobs == []


def test_host_network_rejected_does_not_create_runner_job(tmp_path: Path) -> None:
    snippet = "subprocess.run(['docker', 'run', '--network', 'host', 'alpine'])\n"
    sandbox = FakeSandboxRunner()
    runner = RegressionRunner(sandbox)

    with pytest.raises(UnsafeSnippetError, match="host network"):
        check_snippet_safety(snippet)
    verdict = runner.run_snippet(snippet, _job(tmp_path, snippet))

    assert verdict.verdict == "inconclusive"
    assert verdict.reason == "safety_rejected"
    assert sandbox.jobs == []


def test_write_under_workspace_rejected_does_not_create_runner_job(tmp_path: Path) -> None:
    snippet = 'open("/workspace/pwned.py", "w").write("owned")\n'
    sandbox = FakeSandboxRunner()
    runner = RegressionRunner(sandbox)

    with pytest.raises(UnsafeSnippetError, match="/workspace"):
        check_snippet_safety(snippet)
    verdict = runner.run_snippet(snippet, _job(tmp_path, snippet))

    assert verdict.verdict == "inconclusive"
    assert verdict.reason == "safety_rejected"
    assert sandbox.jobs == []


def test_benign_python_assert_snippet_is_allowed(tmp_path: Path) -> None:
    assert check_snippet_safety(BENIGN_ASSERT) is None
    sandbox = FakeSandboxRunner()
    job = _job(tmp_path, BENIGN_ASSERT)
    RegressionRunner(sandbox).run_snippet(BENIGN_ASSERT, job)
    assert sandbox.jobs == [job]


@pytest.mark.parametrize(
    "snippet",
    [
        "import socket\nsocket.create_connection(('127.0.0.1', 80))\n",
        "curl https://example.invalid/pwn\n",
    ],
)
def test_socket_and_curl_mentions_are_rejected(snippet: str) -> None:
    with pytest.raises(UnsafeSnippetError):
        check_snippet_safety(snippet)
