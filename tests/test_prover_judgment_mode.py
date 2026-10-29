"""End-to-end three-way judgment mode for ``prove_change`` (task 10.6).

The fixtures mirror ``tests/test_hunt_prover.py``: a real git repository whose head
commit introduces one Stapler-shaped Java class. Judgment mode is opt-in; the
legacy boolean flow must stay byte-identical without the keyword (Req 4.6).
"""

from __future__ import annotations

import subprocess
from typing import Any

from openultrasast.hunt.producers import Context
from openultrasast.hunt.prover import prove_change
from openultrasast.semantic.obligations.trace import parse_abstract_state


def repository(tmp_path: Any, java_text: str) -> tuple[Any, dict[str, Any]]:
    """Build a one-commit repository whose head commit introduces ``java_text``."""
    work = tmp_path / "repo"
    work.mkdir()
    run = lambda *args: subprocess.run(  # noqa: E731 - fixture-local shorthand
        args, cwd=work, check=True, capture_output=True, text=True
    )
    run("git", "init", "-q")
    run("git", "config", "user.email", "fixture@example.com")
    run("git", "config", "user.name", "fixture")
    (work / "Fixture.java").write_text("class Plain {}\n", encoding="utf-8")
    run("git", "add", "Fixture.java")
    run("git", "commit", "-qm", "base")
    head_lines = {
        "Fixture.java": [
            index for index, line in enumerate(java_text.splitlines(), start=1) if line.strip() and "class Fixture" not in line
        ]
    }
    (work / "Fixture.java").write_text(java_text, encoding="utf-8")
    run("git", "add", "Fixture.java")
    run("git", "commit", "-qm", "head")
    head = run("git", "rev-parse", "HEAD").stdout.strip()
    base = run("git", "rev-parse", "HEAD~1").stdout.strip()
    change = dict(
        id="change-1",
        repo="fixture/repo",
        kind="vulnerability",
        base=base,
        head=head,
        files=[{"path": "Fixture.java", "head_lines": [[1, len(java_text.splitlines())]]}],
        head_lines=head_lines,
    )
    return work, change


UNGUARDED = """class Fixture extends Descriptor<Thing> {
    public Object doTestConnection() {
        return CredentialsProvider.lookupCredentials(Thing.class);
    }
}
"""

GUARDED = """class Fixture extends Descriptor<Thing> {
    public Object doTestConnection() {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return CredentialsProvider.lookupCredentials(Thing.class);
    }
}
"""

CROSS_FUNCTION = """class Fixture extends Descriptor<Thing> {
    public Object doTestConnection() {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return this.helper();
    }

    private Object helper() {
        return CredentialsProvider.lookupCredentials(Thing.class);
    }
}
"""


def _prove(work: Any, change: dict[str, Any], **kwargs: Any) -> Any:
    context = Context(root=work, change=change)
    return prove_change(work, change, context, **kwargs)


def test_unguarded_fixture_flags_and_counts_unguarded(tmp_path: Any) -> None:
    work, change = repository(tmp_path, UNGUARDED)
    result = _prove(work, change, judgment_mode=True)
    assert len(result.findings) == 3
    finding = result.findings[0]
    assert finding["missing"] in {"path_guard", "ownership_check", "identity_constraint"}
    assert finding["family"] == "access_control"
    abstract = parse_abstract_state(finding["trace"]["abstract_state"])
    assert abstract.path_judgment.judgment.value == "unguarded"
    assert abstract.path_judgment.missing == ("identity_constraint", "ownership_check", "path_guard")
    assert result.coverage.pair_judgments.unguarded == 1


def test_guarded_fixture_is_indeterminate_without_resource_binding(tmp_path: Any) -> None:
    work, change = repository(tmp_path, GUARDED)
    result = _prove(work, change, judgment_mode=True)
    assert result.findings == ()
    assert result.coverage.pair_judgments.indeterminate == 1
    assert result.coverage.pair_judgments.discharged == 0
    abstract_states = [trace["abstract_state"] for trace in result.traces if "abstract_state" in trace]
    assert len(abstract_states) == 1
    assert parse_abstract_state(abstract_states[0]).path_judgment.judgment.value == "indeterminate"


def test_cross_function_guard_is_indeterminate_in_strict_mode(tmp_path: Any) -> None:
    work, change = repository(tmp_path, CROSS_FUNCTION)
    result = _prove(work, change, judgment_mode=True)
    assert result.findings == ()
    assert result.coverage.pair_judgments.indeterminate == 1
    assert result.coverage.pair_judgments.discharged == 0


def test_legacy_mode_is_unchanged_without_the_keyword(tmp_path: Any) -> None:
    work, change = repository(tmp_path, GUARDED)
    result = _prove(work, change)
    assert result.findings == ()
    assert all("abstract_state" not in trace for trace in result.traces)
    assert result.coverage.pair_judgments.unguarded == 0
    assert result.coverage.pair_judgments.discharged == 0
    assert result.coverage.pair_judgments.indeterminate == 0


def test_traces_carry_judgment_and_missing_kinds(tmp_path: Any) -> None:
    work, change = repository(tmp_path, UNGUARDED)
    result = _prove(work, change, judgment_mode=True)
    assert result.traces
    judgment_values = {
        parse_abstract_state(trace["abstract_state"]).path_judgment.judgment.value for trace in result.traces if "abstract_state" in trace
    }
    assert judgment_values == {"unguarded"}
