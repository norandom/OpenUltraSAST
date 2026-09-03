"""Language recipes for isolated regression snippets (task 5.2)."""

from pathlib import Path

from openultrasast.config import SandboxConfig
from openultrasast.regress import INCONCLUSIVE, RegressionRunner
from openultrasast.regress.recipes import recipe_for
from openultrasast.sandbox import FakeSandboxRunner, SandboxJob

LIMITS = SandboxConfig(memory_mb=256, timeout_seconds=30, pids_limit=128)
PYTHON_SNIPPET = "assert 1 + 1 == 2\n"
JS_SNIPPET = "console.log('ok')\n"
C_SNIPPET = "int main(void) { return 0; }\n"
JAVA_SNIPPET = "class Case { public static void main(String[] args) {} }\n"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    return repo


def test_python_recipe_runs_scratch_snippet_with_repo_on_pythonpath(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    job = recipe_for("python", PYTHON_SNIPPET, "python:3.12-alpine", LIMITS, repo_root=repo)

    assert isinstance(job, SandboxJob)
    joined = " ".join(job.command)
    assert job.image == "python:3.12-alpine"
    assert job.repo_root == repo
    assert job.scratch_files == {"case.py": PYTHON_SNIPPET}
    assert "python" in job.command
    assert "/scratch/case.py" in job.command
    assert "PYTHONPATH=/workspace" in joined
    assert job.timeout_seconds == LIMITS.timeout_seconds
    assert job.memory_mb == LIMITS.memory_mb
    assert job.pids_limit == LIMITS.pids_limit


def test_javascript_recipe_runs_scratch_snippet_with_repo_on_node_path(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    job = recipe_for("javascript", JS_SNIPPET, "node:22-alpine", LIMITS, repo_root=repo)

    assert isinstance(job, SandboxJob)
    joined = " ".join(job.command)
    assert job.image == "node:22-alpine"
    assert job.repo_root == repo
    assert job.scratch_files == {"case.js": JS_SNIPPET}
    assert "node" in job.command
    assert "/scratch/case.js" in job.command
    assert "NODE_PATH=/workspace" in joined
    assert job.timeout_seconds == LIMITS.timeout_seconds
    assert job.memory_mb == LIMITS.memory_mb
    assert job.pids_limit == LIMITS.pids_limit


def test_c_recipe_compiles_and_runs_when_image_has_compiler(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    job = recipe_for("c", C_SNIPPET, "gcc:13", LIMITS, repo_root=repo)

    assert isinstance(job, SandboxJob)
    joined = " ".join(job.command)
    assert job.scratch_files == {"case.c": C_SNIPPET}
    assert "cc" in joined
    assert "/scratch/case.c" in joined
    assert "-o" in joined
    assert "/scratch/case" in joined


def test_unknown_language_recipe_is_none(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    assert recipe_for("java", JAVA_SNIPPET, "eclipse-temurin:21", LIMITS, repo_root=repo) is None
    assert recipe_for("unknown", "print(1)\n", "python:3.12-alpine", LIMITS, repo_root=repo) is None


def test_python_and_javascript_recipes_produce_runner_jobs(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    python_job = recipe_for("python", PYTHON_SNIPPET, "python:3.12-alpine", LIMITS, repo_root=repo)
    js_job = recipe_for("javascript", JS_SNIPPET, "node:22-alpine", LIMITS, repo_root=repo)
    sandbox = FakeSandboxRunner()
    runner = RegressionRunner(sandbox)

    python_verdict = runner.run_recipe("python", PYTHON_SNIPPET, "python:3.12-alpine", LIMITS, repo_root=repo)
    js_verdict = runner.run_recipe("javascript", JS_SNIPPET, "node:22-alpine", LIMITS, repo_root=repo)

    assert python_job is not None
    assert js_job is not None
    assert python_verdict.reason != "missing_recipe"
    assert js_verdict.reason != "missing_recipe"
    assert sandbox.jobs == [python_job, js_job]


def test_unknown_language_returns_inconclusive_without_calling_runner(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    sandbox = FakeSandboxRunner()
    runner = RegressionRunner(sandbox)

    assert recipe_for("java", JAVA_SNIPPET, "eclipse-temurin:21", LIMITS, repo_root=repo) is None
    verdict = runner.run_recipe("java", JAVA_SNIPPET, "eclipse-temurin:21", LIMITS, repo_root=repo)

    assert verdict.verdict == INCONCLUSIVE
    assert verdict.reason == "missing_recipe"
    assert sandbox.jobs == []
