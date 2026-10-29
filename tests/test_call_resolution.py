"""Call resolution tests: exact, finite-candidate and unresolved targets (task 8.3).

Req 3.3: multiple feasible targets stay a finite candidate set marked incomplete,
never merged under a bare name.
Req 3.4: no bounded candidate set -> unresolved, unusable for complete paths.
Req 11.1/11.6: grades distinguish definite/possible/unknown; precision loss never
flips a complete result to a different complete result.
"""

from __future__ import annotations

import pytest

from openultrasast.semantic.ir import CallSite, FunctionIR
from openultrasast.semantic.obligations.abstract_domain import Completeness
from openultrasast.semantic.obligations.resolution import (
    CallBindings,
    CallerBinding,
    CallTargetSet,
    SymbolId,
    SymbolIndex,
    bind_calls,
    resolve_call,
)


def _complete() -> Completeness:
    return Completeness(is_complete=True)


def _call(name: str, line: int, receiver: str | None = None, arity: int | None = None) -> CallSite:
    return CallSite(
        name=name,
        line=line,
        arg_texts=(),
        arg_is_constant=(),
        arg_names=(),
        extra_arg_is_sequence=False,
        receiver=receiver,
        arity=arity,
    )


JAVA_ONE_CLASS = (
    "src/a/Handler.java",
    """package pkg;
public class Handler {
    public void run(String command) { }
    public void handle() { run("x"); this.run("y"); }
}
""",
    "java",
)

JAVA_TWO_CLASSES_SAME_METHOD = (
    "src/a/Two.java",
    """package pkg;
public class Auditor { public void check(String item) { } }
public class Gate { public void check(String item) { } }
""",
    "java",
)

PYTHON_MODULE_SCOPE = (
    "src/svc.py",
    """def audit(request):
    pass

def other(request):
    audit(request)
""",
    "python",
)


def index_of(*files: tuple[str, str, str]) -> SymbolIndex:
    return SymbolIndex.build(files)


class TestResolveCall:
    def test_exact_self_receiver_in_one_class_is_complete(self) -> None:
        index = index_of(JAVA_ONE_CLASS)
        call = _call(name="run", line=5, receiver="this", arity=1)
        target_set = resolve_call(call, module="src/a/Handler.java", index=index)
        assert target_set.targets == (SymbolId("src/a/Handler.java", "Handler", "run", ("command",)),)
        assert target_set.completeness.reasons == ()

    def test_two_classes_same_method_stay_candidates_never_bare(self) -> None:
        index = index_of(JAVA_TWO_CLASSES_SAME_METHOD)
        call = _call(name="check", line=2, receiver="auditor", arity=1)
        target_set = resolve_call(call, module="src/a/Two.java", index=index)
        assert set(target_set.targets) == {
            SymbolId("src/a/Two.java", "Auditor", "check", ("item",)),
            SymbolId("src/a/Two.java", "Gate", "check", ("item",)),
        }
        assert target_set.completeness.reasons  # incomplete, not merged

    def test_overload_arity_narrows_but_variable_receiver_stays_incomplete(self) -> None:
        index = index_of(
            (
                "src/a/Ops.java",
                """public class Ops {
    public void run() { }
    public void run(String command) { }
}
""",
                "java",
            )
        )
        narrowed = resolve_call(
            _call(name="run", line=1, receiver="ops", arity=1),
            module="src/a/Ops.java",
            index=index,
        )
        assert narrowed.targets == (SymbolId("src/a/Ops.java", "Ops", "run", ("command",)),)
        assert narrowed.completeness.reasons  # partial type information stays incomplete

    def test_unknown_arity_keeps_overloads_as_candidates(self) -> None:
        index = index_of(
            (
                "src/a/Ops.java",
                """public class Ops {
    public void run() { }
    public void run(String command) { }
}
""",
                "java",
            )
        )
        candidates = resolve_call(
            _call(name="run", line=1, receiver="ops", arity=None),
            module="src/a/Ops.java",
            index=index,
        )
        assert len(candidates.targets) == 2
        assert candidates.completeness.reasons

    def test_no_candidate_is_unresolved_with_reason(self) -> None:
        index = index_of(JAVA_ONE_CLASS)
        call = _call(name="missing", line=3, receiver="helper", arity=1)
        target_set = resolve_call(call, module="src/a/Handler.java", index=index)
        assert target_set.targets == ()
        assert target_set.completeness.reasons

    def test_module_scope_unique_bare_call_is_complete(self) -> None:
        index = index_of(PYTHON_MODULE_SCOPE)
        call = _call(name="audit", line=5, receiver=None, arity=1)
        target_set = resolve_call(call, module="src/svc.py", index=index)
        assert target_set.targets == (SymbolId("src/svc.py", None, "audit", ("request",)),)
        assert target_set.completeness.reasons == ()

    def test_module_scope_shared_name_is_incomplete(self) -> None:
        index = index_of(
            (
                "src/twin.py",
                """def audit(request):
    pass

def audit(request, extra):
    pass
""",
                "python",
            )
        )
        call = _call(name="audit", line=4, receiver=None, arity=None)
        target_set = resolve_call(call, module="src/twin.py", index=index)
        assert len(target_set.targets) == 2
        assert target_set.completeness.reasons

    def test_precision_loss_never_flips_complete_to_complete(self) -> None:
        single = index_of(
            (
                "src/a/One.java",
                """public class Gate {
    public void check(String item) { }
    public void audit() { check("x"); }
}
""",
                "java",
            )
        )
        doubled = index_of(
            (
                "src/a/One.java",
                """public class Gate {
    public void check(String item) { }
    public void audit() { check("x"); }
}
public class Other {
    public void check(String item) { }
}
""",
                "java",
            )
        )
        call = _call(name="check", line=3, receiver="this", arity=1)
        before = resolve_call(call, module="src/a/One.java", index=single)
        after = resolve_call(call, module="src/a/One.java", index=doubled)
        assert before.completeness.reasons == ()
        assert after.completeness.reasons  # grew ambiguous, never silently complete


class TestBindCalls:
    def test_exact_binding_feeds_reverse_caller_index_and_counts(self) -> None:
        index = index_of(JAVA_ONE_CLASS)
        bindings = bind_calls(
            functions_by_module={
                "src/a/Handler.java": (
                    _ir_stub(
                        calls=(
                            _call(name="run", line=5, receiver="this", arity=1),
                            _call(name="run", line=5, receiver="this", arity=1),
                        ),
                        name="handle",
                    ),
                )
            },
            index=index,
        )
        assert isinstance(bindings, CallBindings)
        target = SymbolId("src/a/Handler.java", "Handler", "run", ("command",))
        assert bindings.exact_callers(target) == (CallerBinding(module="src/a/Handler.java", function="handle", line=5, exact=True),)
        assert bindings.counts["complete_calls"] == 2
        assert bindings.counts["unresolved_calls"] == 0

    def test_candidate_only_binding_is_not_an_exact_caller(self) -> None:
        index = index_of(JAVA_TWO_CLASSES_SAME_METHOD)
        bindings = bind_calls(
            functions_by_module={"src/a/Two.java": (_ir_stub(calls=(_call(name="check", line=3, receiver="gate", arity=1),)),)},
            index=index,
        )
        target = SymbolId("src/a/Two.java", "Gate", "check", ("item",))
        assert bindings.exact_callers(target) == ()
        assert bindings.counts["incomplete_calls"] == 1


def _ir_stub(calls: tuple[CallSite, ...], name: str = "caller") -> FunctionIR:
    return FunctionIR(name=name, params=(), start_line=1, end_line=9, binds=(), calls=calls)


@pytest.mark.parametrize("fixture", [JAVA_ONE_CLASS, PYTHON_MODULE_SCOPE])
def test_call_target_set_is_canonical_and_frozen(fixture: tuple[str, str, str]) -> None:
    index = index_of(fixture)
    assert index.declarations == tuple(sorted(index.declarations))
    target_set = CallTargetSet(targets=index.declarations, completeness=_complete())
    with pytest.raises(Exception):  # noqa: B017 - frozen contract
        target_set.targets = ()  # type: ignore[misc]
