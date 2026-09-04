"""Stage-3 regression on split-sink: fake runner always; live Docker skips without a daemon."""

from pathlib import Path

import pytest

from openultrasast.config import SandboxConfig
from openultrasast.regress.recipes import recipe_for
from openultrasast.regress.safety import check_snippet_safety
from openultrasast.regress.verdict import TRIGGERABLE, verdict_from_result
from openultrasast.sandbox import DockerCliRunner, FakeSandboxRunner, SandboxProbe, SandboxResult

_SPLIT_SINK_PYTHON = Path("benchmarks/fixtures/split-sink-python")
_LIMITS = SandboxConfig(memory_mb=256, timeout_seconds=30, pids_limit=128)
_PYTHON_IMAGE = "python:3.12-alpine"
_SNIPPET = 'term = "x\'; drop"\nquery = "select * from items where title like \'%" + term + "%\'"\nassert "\'" not in query\n'


def _split_sink_job():
    check_snippet_safety(_SNIPPET)
    job = recipe_for("python", _SNIPPET, _PYTHON_IMAGE, _LIMITS, repo_root=_SPLIT_SINK_PYTHON.resolve())
    assert job is not None
    return job


def test_fake_runner_marks_split_sink_snippet_triggerable() -> None:
    fake = FakeSandboxRunner(SandboxResult(exit_code=1, stdout="", stderr="AssertionError", timed_out=False))
    result = fake.run(_split_sink_job())
    verdict = verdict_from_result(result)
    assert verdict.verdict == TRIGGERABLE
    assert fake.jobs


@pytest.mark.docker
def test_docker_marks_split_sink_python_triggerable() -> None:
    if not SandboxProbe().available():
        pytest.skip("docker daemon unavailable")
    result = DockerCliRunner().run(_split_sink_job())
    verdict = verdict_from_result(result)
    assert verdict.verdict == TRIGGERABLE, (result.exit_code, result.stdout, result.stderr)
