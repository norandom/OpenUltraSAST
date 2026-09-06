"""authorization-obligations task 2.5: the checker, function-local and path-aware (offline)."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_obligation_operations import APP, ENTRIES, _entry  # noqa: E402

from openultrasast.semantic.facts import load_facts  # noqa: E402
from openultrasast.semantic.ir import parse_file  # noqa: E402

POLICY = (
    'version = 1\nidentity_source = "request.user"\n\n[[resource]]\nname = "book"\nsensitivity = "high"\nidentity_field = "user_id"\n\n'
    '[[route]]\npath = "/books/any/*"\naccess = "public"\n'
)


@dataclass(frozen=True)
class _Path:
    hops: tuple[tuple[str, int], ...]


def _check(
    *, policy_text: str | None = None, paths=(), dominance=None, min_siblings: int = 2, store_shapes=(), tmp_path: Path | None = None
):
    from openultrasast.semantic.obligations import load_obligation_facts
    from openultrasast.semantic.obligations.check import check_obligations
    from openultrasast.semantic.obligations.dominance import OrderDominance
    from openultrasast.semantic.obligations.policy import load_declared_policy

    policy = None
    if policy_text is not None and tmp_path is not None:
        (tmp_path / "obligations.toml").write_text(policy_text)
        policy = load_declared_policy(tmp_path / "obligations.toml")
    ir = parse_file("app.py", APP, "python")
    return check_obligations(
        irs={"app.py": (ir, APP)},
        entries=ENTRIES,
        facts=load_obligation_facts(),
        flow_facts=load_facts(),
        policy=policy,
        paths=paths,
        dominance=dominance or OrderDominance(texts={"app.py": APP}),
        store_shapes=store_shapes,
        min_siblings=min_siblings,
    )


def test_function_local_run_reports_the_consistency_violation_with_siblings_and_a_degradation() -> None:
    result = _check()
    identity = [f for f in result.findings if f.missing == "identity_constraint"]
    assert {f.operation.function for f in identity} == {"leaky", "guarded"}
    leaky = next(f for f in identity if f.operation.function == "leaky")
    assert leaky.label == "consistency_violation" and leaky.provenance == "request_input"
    assert "app.py::constrained" in leaky.evidence and "app.py::constrained_too" in leaky.evidence  # names both siblings
    assert leaky.operation.resource == "book" and leaky.operation.kind == "protected_read"
    assert not [f for f in result.findings if f.operation.function == "constrained" and f.missing == "identity_constraint"]
    (degradation,) = [d for d in result.degradations if d["reason"] == "obligations_function_local"]
    assert degradation["language"] == "python" and degradation["files"] == ["app.py"]  # Req 5.3: names the file
    assert result.sibling_sets and result.discharges


def test_declared_policy_outranks_consistency_and_public_routes_drop_only_the_guard(tmp_path: Path) -> None:
    result = _check(policy_text=POLICY, tmp_path=tmp_path)
    leaky = [f for f in result.findings if f.operation.function == "leaky"]
    identity = next(f for f in leaky if f.missing == "identity_constraint")
    assert identity.label == "declared_policy_violation" and any("resource book" in e for e in identity.evidence)
    assert not [f for f in leaky if f.missing == "path_guard"]  # /books/any/* is declared public
    constrained_guard = [f for f in result.findings if f.operation.function == "constrained_too" and f.missing == "path_guard"]
    assert constrained_guard and constrained_guard[0].label == "consistency_violation"  # not declared public: the guard anomaly stands


def test_path_records_gate_reachability_and_a_dominating_hop_discharges() -> None:
    from openultrasast.semantic.obligations.operations import Discharge

    class _HopAware:
        def __init__(self) -> None:
            self.calls = 0

        def dominates(self, witness: Discharge, operation, path) -> bool:  # type: ignore[no-untyped-def]
            self.calls += 1
            return witness.scope == "hop"

    reached = (_Path(hops=(("api.py::gateway", 3), ("app.py::leaky", 25))),)
    result = _check(paths=reached)
    assert {f.operation.function for f in result.findings} == {"leaky"}  # only the operation a path reaches
    assert not any(d["reason"] == "obligations_function_local" for d in result.degradations)
    dominance = _HopAware()
    hop_guard = Discharge(
        path="api.py", line=1, function="gateway", kind="identity_constraint", fact_id="x", provenance="authenticated_context", scope="hop"
    )
    covered = _check(paths=reached, dominance=dominance, store_shapes=(), min_siblings=2)
    assert dominance.calls == 0  # leaky's only witness is request-bound, so there is nothing valid to ask dominance about
    from openultrasast.semantic.obligations import load_obligation_facts
    from openultrasast.semantic.obligations.check import check_obligations

    ir = parse_file("app.py", APP, "python")
    with_hop = check_obligations(
        irs={"app.py": (ir, APP)},
        entries=ENTRIES,
        facts=load_obligation_facts(),
        flow_facts=load_facts(),
        policy=None,
        paths=reached,
        dominance=dominance,
        store_shapes=(),
        min_siblings=2,
        extra_witnesses=(hop_guard,),
    )
    assert dominance.calls > 0  # the hop witness is valid, so the checker consulted the injected Dominance implementation
    assert not [f for f in with_hop.findings if f.operation.function == "leaky" and f.missing == "identity_constraint"]
    assert covered.findings  # without the hop witness the finding stands


def test_findings_become_suspicion_static_findings_with_known_fix_and_labels(tmp_path: Path) -> None:
    from openultrasast.semantic.mechanisms import MechanismStore, append_from_pair
    from openultrasast.semantic.obligations.check import findings_to_static
    from openultrasast.semantic.obligations.shapes import ObligationShape, obligation_mechanisms

    store = MechanismStore(tmp_path / "m.jsonl")
    shape = ObligationShape(
        language="python",
        operation_kind="protected_read",
        discharger_kind="identity_constraint",
        provenance="authenticated_context",
        resource_class="owned",
        mechanism="missing_auth_guard",
    )
    record = append_from_pair(store, shape, summary="s", cwe="CWE-639", pair="vampi", provenance="human", tier="seeded")
    result = _check(store_shapes=obligation_mechanisms(store.load()))
    leaky = next(f for f in result.findings if f.operation.function == "leaky" and f.missing == "identity_constraint")
    assert leaky.known_fix == record.id
    statics = findings_to_static(result)
    ids = {s.finding_id for s in statics}
    guarded = next(f for f in result.findings if f.operation.function == "guarded" and f.missing == "identity_constraint")
    assert f"obligation:protected_read:app.py:{leaky.operation.line}:identity_constraint" in ids  # exact id contract
    assert f"obligation:protected_read:app.py:{guarded.operation.line}:identity_constraint" in ids
    static = next(s for s in statics if s.line == leaky.operation.line and "discharger:identity_constraint" in s.tags)
    assert static.evidence_level == "suspicion"
    assert {
        "obligation:protected_read",
        "discharger:identity_constraint",
        "obligation_evidence:consistency_violation",
        f"mechanism:{record.id}",
    } <= set(static.tags)
    assert "app.py::constrained" in static.rationale


def test_with_path_records_an_unjustified_obligation_yields_no_finding() -> None:
    """Round-2 finding: `function_local` is the degraded mode's label only; with paths and no sibling or clause, nothing."""
    reached = (_Path(hops=(("api.py::gateway", 3), ("app.py::leaky", 25))),)
    result = _check(paths=reached, min_siblings=5)  # every set under-populated: no consistency evidence, no policy
    assert result.findings == () and result.under_populated == (("app", "book"),)
    assert not any(d["reason"] == "obligations_function_local" for d in result.degradations)
    assert all(f.label != "consistency_violation" or f.evidence for f in _check(paths=reached, min_siblings=2).findings)


ADMIN = (
    "from flask import request\n\n\n"
    "@app.route('/admin/reset/<name>')\ndef reset(name):\n"
    "    set_password(name, 'temporary')\n"
    "    return Book.query.filter_by(book_title=name).first()\n"
)
ADMIN_ENTRIES = [_entry("reset", 4, 6, "public", [])]
ADMIN_POLICY = (
    'version = 1\nidentity_source = "request.user"\n\n[[resource]]\nname = "book"\nsensitivity = "high"\n\n'
    '[[route]]\npath = "/admin/*"\naccess = "public"\n'
)


def _check_admin(tmp_path: Path, policy_text: str | None):
    from openultrasast.semantic.obligations import load_obligation_facts
    from openultrasast.semantic.obligations.check import check_obligations
    from openultrasast.semantic.obligations.dominance import OrderDominance
    from openultrasast.semantic.obligations.policy import load_declared_policy

    policy = None
    if policy_text is not None:
        (tmp_path / "obligations.toml").write_text(policy_text)
        policy = load_declared_policy(tmp_path / "obligations.toml")
    ir = parse_file("app.py", ADMIN, "python")
    return check_obligations(
        irs={"app.py": (ir, ADMIN)},
        entries=ADMIN_ENTRIES,
        facts=load_obligation_facts(),
        flow_facts=load_facts(),
        policy=policy,
        paths=(),
        dominance=OrderDominance(texts={"app.py": ADMIN}),
        store_shapes=(),
        min_siblings=2,
    )


def test_a_declared_public_route_never_reports_its_missing_path_guard_but_keeps_the_resource_obligation(tmp_path: Path) -> None:
    """Round-3 finding (Req 4.4): the waiver must also cover the operation's own requirement, not only sibling anomalies."""
    without = _check_admin(tmp_path, None)
    assert [(f.operation.kind, f.missing) for f in without.findings if f.operation.kind == "privileged_action"] == [
        ("privileged_action", "path_guard")
    ]
    declared = _check_admin(tmp_path, ADMIN_POLICY)
    assert not [f for f in declared.findings if f.missing == "path_guard"]  # /admin/* is declared public: no guard obligation
    identity = [f for f in declared.findings if f.operation.kind == "protected_read" and f.missing == "identity_constraint"]
    assert identity and identity[0].label == "declared_policy_violation"  # the declared resource still owes its identity constraint


def test_a_malformed_store_row_is_a_degradation_not_a_crash() -> None:
    """Design Error Handling: store row with malformed obligation shape -> `obligations_store_row_invalid`."""

    @dataclass(frozen=True)
    class _Row:
        id: str
        shape: object

    result = _check(store_shapes=(_Row(id="corpus:bad", shape="garbage"), _Row(id="corpus:worse", shape={"family": "obligation"})))
    (degradation,) = [d for d in result.degradations if d["reason"] == "obligations_store_row_invalid"]
    assert degradation["records"] == ["corpus:bad", "corpus:worse"]
    assert all(f.known_fix is None for f in result.findings)
