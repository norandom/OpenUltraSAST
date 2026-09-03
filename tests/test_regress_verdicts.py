"""Map sandbox outcomes to the four verdicts and the worth-fixing gate (task 5.3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from openultrasast.regress import RegressionRunner
from openultrasast.regress.verdict import (
    ALREADY_COVERED,
    INCONCLUSIVE,
    NOT_TRIGGERABLE,
    TRIGGERABLE,
    is_worth_fixing,
    verdict_from_result,
)
from openultrasast.sandbox import FakeSandboxRunner, SandboxJob, SandboxResult

_REACHABLE = "reachable"
_INFERRED = "inferred-file-surface"
_UNKNOWN = "unknown"


def _result(*, exit_code: int = 0, stdout: str = "", stderr: str = "", timed_out: bool = False) -> SandboxResult:
    return SandboxResult(exit_code=exit_code, stdout=stdout, stderr=stderr, timed_out=timed_out)


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


# observation kwargs, sandbox result, reachability, expected verdict, expected reason, worth-fixing
_CASES = (
    pytest.param(
        {"recipe_missing": True},
        None,
        _REACHABLE,
        INCONCLUSIVE,
        "missing_recipe",
        False,
        id="recipe-missing-inconclusive",
    ),
    pytest.param(
        {"sandbox_missing": True},
        None,
        _REACHABLE,
        INCONCLUSIVE,
        "sandbox_unavailable",
        False,
        id="sandbox-missing-inconclusive",
    ),
    pytest.param(
        {},
        _result(exit_code=-1, timed_out=True),
        _REACHABLE,
        INCONCLUSIVE,
        "timeout",
        False,
        id="timeout-inconclusive",
    ),
    pytest.param(
        {"safety_rejected": True},
        None,
        _INFERRED,
        INCONCLUSIVE,
        "safety_rejected",
        False,
        id="safety-reject-inconclusive",
    ),
    pytest.param(
        {"covering_test": True},
        _result(exit_code=0, stdout="ok\n"),
        _REACHABLE,
        ALREADY_COVERED,
        "covered_test_passed",
        False,
        id="covering-test-passed-already-covered",
    ),
    pytest.param(
        {},
        _result(exit_code=1, stderr="AssertionError: boom\n"),
        _REACHABLE,
        TRIGGERABLE,
        "assertion",
        True,
        id="assertion-triggerable-reachable-worth-fixing",
    ),
    pytest.param(
        {},
        _result(exit_code=1, stderr="ERROR: AddressSanitizer: heap-buffer-overflow\n"),
        _INFERRED,
        TRIGGERABLE,
        "sanitizer_abort",
        True,
        id="sanitizer-triggerable-inferred-worth-fixing",
    ),
    pytest.param(
        {},
        _result(exit_code=139, stderr="Segmentation fault\n"),
        _UNKNOWN,
        TRIGGERABLE,
        "crash",
        False,
        id="crash-triggerable-unknown-not-worth-fixing",
    ),
    pytest.param(
        {},
        _result(exit_code=0, stdout="ok\n"),
        _REACHABLE,
        NOT_TRIGGERABLE,
        "exit_zero",
        False,
        id="exit-zero-not-triggerable",
    ),
    pytest.param(
        {"covering_test": True},
        _result(exit_code=0),
        _UNKNOWN,
        ALREADY_COVERED,
        "covered_test_passed",
        False,
        id="already-covered-unknown-does-not-fail-build",
    ),
    pytest.param(
        {},
        _result(exit_code=0),
        _INFERRED,
        NOT_TRIGGERABLE,
        "exit_zero",
        False,
        id="not-triggerable-inferred-does-not-fail-build",
    ),
    pytest.param(
        {},
        _result(exit_code=-1, timed_out=True),
        _INFERRED,
        INCONCLUSIVE,
        "timeout",
        False,
        id="inconclusive-inferred-does-not-fail-build",
    ),
)


@pytest.mark.parametrize(
    ("flags", "result", "reachability", "expected_verdict", "expected_reason", "expected_worth_fixing"),
    _CASES,
)
def test_sandbox_outcomes_map_to_verdicts_and_worth_fixing(
    flags: dict[str, bool],
    result: SandboxResult | None,
    reachability: str,
    expected_verdict: str,
    expected_reason: str,
    expected_worth_fixing: bool,
) -> None:
    mapped = verdict_from_result(result, **flags)

    assert mapped.verdict == expected_verdict
    assert mapped.reason == expected_reason
    assert mapped.reason
    assert is_worth_fixing(mapped.verdict, reachability) is expected_worth_fixing


def test_table_covers_four_verdicts_and_worth_fixing_boolean() -> None:
    verdicts = {case.values[3] for case in _CASES}
    worth_fixing_values = {case.values[5] for case in _CASES}

    assert verdicts == {TRIGGERABLE, NOT_TRIGGERABLE, ALREADY_COVERED, INCONCLUSIVE}
    assert worth_fixing_values == {True, False}


def test_runner_maps_timeout_crash_and_exit_zero(tmp_path: Path) -> None:
    snippet = "assert 1 + 1 == 2\n"
    job = _job(tmp_path, snippet)
    timeout = FakeSandboxRunner(_result(exit_code=-1, timed_out=True))
    crash = FakeSandboxRunner(_result(exit_code=1, stderr="AssertionError\n"))
    ok = FakeSandboxRunner(_result(exit_code=0))

    timed_out = RegressionRunner(timeout).run_snippet(snippet, job)
    triggered = RegressionRunner(crash).run_snippet(snippet, job)
    not_triggered = RegressionRunner(ok).run_snippet(snippet, job)

    assert timed_out.verdict == INCONCLUSIVE
    assert timed_out.reason == "timeout"
    assert triggered.verdict == TRIGGERABLE
    assert not_triggered.verdict == NOT_TRIGGERABLE
    assert is_worth_fixing(timed_out.verdict, _REACHABLE) is False
    assert is_worth_fixing(triggered.verdict, _REACHABLE) is True
    assert is_worth_fixing(not_triggered.verdict, _REACHABLE) is False
