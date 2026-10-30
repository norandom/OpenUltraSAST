"""Task 13.2 -- cross-component validation scenarios.

Nine scenarios (Reqs 1.1, 1.2, 2.1, 2.2, 2.5, 2.6, 2.7, 2.8, 3.1-3.10, 4.1-4.3,
10.1-10.7): helper guards, registration entries, base attachment, resource
mismatch, authority insufficiency, ambiguous calls, unavailable CFGs, recursion
and budget cutoff. Each scenario asserts the expected trace, coverage reason or
three-way judgment at the level the engine surfaces it: the prover end-to-end
scenarios run prove_change(..., judgment_mode=True); the component scenarios
exercise the engine seams directly. Like 13.1 this is a validation task -- the
passing deterministic run is the deliverable.
"""

from __future__ import annotations

import importlib
import subprocess
from typing import Any

from pathlib import Path

import pytest

from openultrasast.hunt.producers import Context
from openultrasast.hunt.prover import prove_change
from openultrasast.mapping import analyze_entry_points
from openultrasast.mapping.registry import _STRATEGIES, register
from openultrasast.mapping.registration_sites import RegistrationSiteStrategy
from openultrasast.preprocess import FileTarget, detect_language
from openultrasast.semantic.ir import CallSite, FunctionIR
from openultrasast.semantic.obligations.abstract_domain import (
    AuthorityRef,
    ResourceRef,
)
from openultrasast.semantic.obligations.cfg_dominance import CfgDominance
from openultrasast.semantic.obligations.operations import Discharge, Operation
from openultrasast.semantic.obligations.resolution import (
    descendants_of,
    inherited_method,
    resolve_call,
    SymbolIndex,
)
from openultrasast.semantic.obligations.summaries import (
    ExplorationBudget,
    monotone_summaries,
)
from openultrasast.semantic.obligations.trace import parse_abstract_state
from openultrasast.semantic.obligations.witness import match_witness

GUARDED = """class Fixture extends Descriptor<Thing> {
    public Object doTestConnection() {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return CredentialsProvider.lookupCredentials(Thing.class);
    }
}
"""

HELPER_GUARD = """class Fixture extends Descriptor<Thing> {
    public Object doTestConnection() {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return this.helper();
    }

    private Object helper() {
        return CredentialsProvider.lookupCredentials(Thing.class);
    }
}
"""

REGISTRATION_JAVA = """class Handler {
    public void handle() {}
}
class Registry {
    void install() {
        addHandler(new Handler());
    }
}
"""

BASE_JAVA = """abstract class BaseHandler {
    public abstract void go(String payload);
}
class SubHandler extends BaseHandler {
    public void go(String payload) {}
}
class Other {
    public void go(String payload) {}
}
"""

AMBIGUOUS_JAVA = """class Auditor {
    public void check() {}
}
class Gate {
    public void check() {}
}
"""

RECURSIVE_JAVA = """class Node {
    public int walk() {
        return this.walk();
    }
}
"""


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


def _prove(work: Any, change: dict[str, Any], **kwargs: Any) -> Any:
    context = Context(root=work, change=change)
    return prove_change(work, change, context, **kwargs)


def _function(name: str, calls: tuple[str, ...] = ()) -> FunctionIR:
    return FunctionIR(
        name=name,
        params=(),
        start_line=1,
        end_line=9,
        binds=(),
        calls=tuple(
            CallSite(call_name, 3 + offset, (), (), (), False, offset)
            for offset, call_name in enumerate(calls)
        ),
    )


def _operation() -> Operation:
    return Operation(
        "src/C.java", 8, "handle", "protected_read", "f:op", "book",
        ("path_guard",),
    )


def _witness(
    resource: ResourceRef | None = None,
    authority: AuthorityRef | None = None,
) -> Discharge:
    return Discharge(
        "src/C.java", 3, "handle", "path_guard", "f:guard", "call",
        "statement", resource=resource, authority=authority,
    )


@pytest.fixture(autouse=True)
def _registry_roundtrip():
    saved = dict(_STRATEGIES)
    _STRATEGIES.clear()
    import openultrasast.mapping.stapler as stapler_module

    importlib.reload(stapler_module)
    yield
    _STRATEGIES.clear()
    _STRATEGIES.update(saved)


def test_same_function_guard_is_indeterminate_at_e2e(tmp_path: Any) -> None:
    work, change = repository(tmp_path, GUARDED)
    result = _prove(work, change, judgment_mode=True)
    assert result.findings == ()
    assert result.coverage.pair_judgments.indeterminate == 1
    abstract_states = [trace["abstract_state"] for trace in result.traces if "abstract_state" in trace]
    assert len(abstract_states) == 1
    assert parse_abstract_state(abstract_states[0]).path_judgment.judgment.value == "indeterminate"


def test_helper_guard_is_indeterminate_under_strict_dominance(tmp_path: Any) -> None:
    work, change = repository(tmp_path, HELPER_GUARD)
    result = _prove(work, change, judgment_mode=True)
    assert result.findings == ()
    assert result.coverage.pair_judgments.indeterminate == 1
    assert result.coverage.pair_judgments.discharged == 0


def test_registration_entries_surface_via_registry(tmp_path: Any) -> None:
    (tmp_path / "R.java").write_text(REGISTRATION_JAVA, encoding="utf-8")
    targets = [
        FileTarget(
            path="R.java",
            absolute_path=str(tmp_path / "R.java"),
            language=detect_language(tmp_path / "R.java"),
            loc=8,
            tags=[],
            has_fuzz_entry_point=False,
        )
    ]
    register(
        RegistrationSiteStrategy(
            identifier="scenario-registration",
            languages=("java",),
            vocabulary=("addHandler",),
        )
    )
    entries = analyze_entry_points(tmp_path, targets, include_manifests=False)
    names = {entry.function_name for entry in entries}
    assert "handle" in names
    registered = next(entry for entry in entries if entry.function_name == "handle")
    assert registered.provenance == "strategy:scenario-registration"


def test_base_declaration_attaches_through_descendants() -> None:
    index = SymbolIndex.build((("src/H.java", BASE_JAVA, "java"),))
    target = inherited_method(index, "BaseHandler", "go", arity=1)
    assert target.completeness.is_complete
    assert len(target.targets) == 1
    assert target.targets[0].enclosing_type == "BaseHandler"
    assert ("src/H.java", "SubHandler") in descendants_of(index, "BaseHandler")
    assert ("src/H.java", "Other") not in descendants_of(index, "BaseHandler")


def test_resource_mismatch_is_definite_no() -> None:
    witness = _witness(resource=ResourceRef(kind="exact", values=("volume",)))
    match = match_witness(witness, _operation())
    assert match.relation.value == "no"
    assert match.resource_relation.value == "no"


def test_authority_insufficiency_is_definite_no() -> None:
    witness = _witness(authority=AuthorityRef(values=("user",)))
    match = match_witness(
        witness,
        _operation(),
        required_authority=AuthorityRef(values=("admin",)),
    )
    assert match.authority_relation.value == "no"


def test_unavailable_cfg_is_unknown_never_order() -> None:
    graphs = CfgDominance({}, {})
    evidence = graphs.evidence(_witness(), _operation())
    assert evidence.relation.value == "unknown"
    assert evidence.reason == "cfg_unavailable"


def test_ambiguous_receiver_stays_a_candidate_set() -> None:
    index = SymbolIndex.build((("src/A.java", AMBIGUOUS_JAVA, "java"),))
    call = CallSite("check", 2, (), (), (), False, 0, receiver="auditor", arity=None)
    target = resolve_call(call, module="src/A.java", index=index)
    assert not target.completeness.is_complete
    assert len(target.targets) == 2
    assert any(
        reason.endswith("receiver_type_unknown")
        for reason in target.completeness.reasons
    )


def test_recursion_resolves_completely() -> None:
    index = SymbolIndex.build((("src/N.java", RECURSIVE_JAVA, "java"),))
    call = CallSite("walk", 3, (), (), (), False, 0, receiver="this", arity=0)
    target = resolve_call(call, module="src/N.java", index=index)
    assert target.completeness.is_complete
    assert len(target.targets) == 1


MUTUAL_JAVA = """class C {
    void a() {
        this.b();
    }
    void b() {
        this.a();
    }
}
"""


def test_budget_cutoff_records_its_reason() -> None:
    from openultrasast.semantic.obligations.resolution import SymbolId

    index = SymbolIndex.build((("src/M.java", MUTUAL_JAVA, "java"),))
    functions = {
        "src/M.java": (_function("a", ("b",)), _function("b", ("a",)))
    }
    callee = SymbolId(
        module="src/M.java", enclosing_type="C", name="b", signature=None
    )
    summaries = monotone_summaries(
        functions,
        index,
        operations_by_symbol={callee: (_operation(),)},
        budget=ExplorationBudget(depth=1),
    )
    by_name = {summary.symbol.name: summary for summary in summaries}
    assert any(
        reason.endswith("depth_cutoff")
        for reason in by_name["a"].completeness.reasons
    )
