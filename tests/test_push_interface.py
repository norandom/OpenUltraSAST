import json
import time

import pytest
from test_push_runner import history

from openultrasast.config import PushConfig
from openultrasast.cpg.backend import NullBackend
from openultrasast.push.runner import push


def invoke(tmp_path, root, updates, **kwargs):
    return push(
        root,
        updates=updates,
        remote_name="origin",
        remote_url="https://secret@example.invalid/repo",
        artifact=tmp_path / "push.json",
        backend=NullBackend(),
        **kwargs,
    )


@pytest.mark.parametrize("updates", ["", "(delete) {zero} refs/heads/old {base}\n"])
def test_no_work(tmp_path, updates):
    root, base, head, _ = history(tmp_path)
    result = invoke(tmp_path, root, updates.format(zero="0" * 40, base=base))
    assert result.result.coverage_status == "not_applicable"
    assert result.exit_code == 0


def test_all_refs_deduplicated_and_missing_base_retained(tmp_path):
    root, base, head, _ = history(tmp_path)
    lines = "".join(f"refs/heads/local {head} refs/heads/{ref} {oid}\n" for ref, oid in [("one", base), ("two", base), ("new", "0" * 40)])
    result = invoke(tmp_path, root, lines, config=PushConfig(mode="blocking", incomplete_coverage_policy="block"))
    data = json.loads((tmp_path / "push.json").read_text())
    assert result.exit_code == 1
    assert len(data["resolution"]["updates"]) == 3
    assert len(result.result.analyses) == 2
    assert result.result.analyses[0].comparison.refs == ("refs/heads/one", "refs/heads/two")
    assert data["snapshots"][0]["bytes_read"] > 0
    assert len(data["change_contexts"]) == 1
    assert "secret@example.invalid" not in json.dumps(data)


def test_input_wait_is_inside_deadline(tmp_path):
    root, _, _, _ = history(tmp_path)

    def delayed():
        time.sleep(5)
        return ""

    start = time.monotonic()
    result = invoke(tmp_path, root, delayed, config=PushConfig(deadline_seconds=0.1, cancellation_allowance_seconds=0.5))
    assert time.monotonic() - start < 0.8
    assert result.result.coverage_status == "unavailable"
    assert result.exit_code == 0


def test_distinct_comparisons_share_deadline(tmp_path, monkeypatch):
    import openultrasast.push.runner as runner

    root, base, head, _ = history(tmp_path)
    original = runner._analyze
    budgets = []

    def analyze(*args, **kwargs):
        budgets.append(kwargs["execution_budget"])
        return original(*args, **kwargs)

    monkeypatch.setattr(runner, "_analyze", analyze)
    result = invoke(tmp_path, root, f"refs/heads/a {head} refs/heads/a {base}\nrefs/heads/b {base} refs/heads/b {head}\n")
    assert len(result.result.analyses) == 2
    assert len(budgets) == 2 and budgets[0] is budgets[1]
    assert len(json.loads((tmp_path / "push.json").read_text())["change_contexts"]) == 2


def test_cli_reads_git_stdin(tmp_path):
    import subprocess
    import sys

    root, base, _, _ = history(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "openultrasast.cli",
            "pre-push",
            str(root),
            "--remote",
            "origin",
            "/tmp/remote",
            "--artifact",
            str(tmp_path / "cli.json"),
        ],
        input=f"(delete) {'0' * 40} refs/heads/old {base}\n",
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads((tmp_path / "cli.json").read_text())
    assert data["result"]["coverage_status"] == "not_applicable"
    assert len(data["resolution"]["updates"]) == 1


@pytest.mark.parametrize(
    "mode,strict,admitted,exit_code",
    [
        ("advisory", "allow", True, 0),
        ("blocking", "allow", True, 1),
        ("advisory", "block", False, 0),
        ("blocking", "allow", False, 0),
        ("blocking", "block", False, 1),
    ],
)
def test_transaction_enforcement_and_dedup(tmp_path, monkeypatch, mode, strict, admitted, exit_code):
    from dataclasses import replace

    from test_push_report import report_with

    import openultrasast.push.runner as runner

    root, base, head, _ = history(tmp_path)

    def analyze(*args, **kwargs):
        report = report_with(admitted=admitted)
        comparison = kwargs["resolved"]
        admission = replace(
            report.admission,
            defects=tuple(replace(d, comparisons=(comparison,), refs=comparison.refs) for d in report.admission.defects),
            dispositions=tuple(replace(d, candidate=replace(d.candidate, comparison=comparison)) for d in report.admission.dispositions),
        )
        analyses = (replace(report.result.analyses[0], comparison=comparison),)
        result = runner.admission_push_result(admission, analyses, config=kwargs["config"])
        return replace(report, admission=admission, result=result, scans=tuple(replace(s, comparison=comparison) for s in report.scans))

    monkeypatch.setattr(runner, "_analyze", analyze)
    result = invoke(
        tmp_path,
        root,
        f"refs/heads/a {head} refs/heads/a {base}\nrefs/heads/b {base} refs/heads/b {head}\n",
        config=PushConfig(mode=mode, incomplete_coverage_policy=strict),
    )
    assert result.exit_code == exit_code
    assert result.result.finding_status == ("actionable" if admitted else "none")
    data = json.loads((tmp_path / "push.json").read_text())
    if admitted:
        assert len(data["admission"]["defects"]) == 1
        assert len(data["admission"]["defects"][0]["comparisons"]) == 2
