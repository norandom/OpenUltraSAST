"""authorization-obligations task 1.1: obligated operations and dischargers are closed facts (offline)."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_default_obligation_facts_load_per_language_with_closed_kinds() -> None:
    from openultrasast.semantic.obligations.facts import DISCHARGER_KINDS, OPERATION_KINDS, PROVENANCE_KINDS, load_obligation_facts

    assert set(OPERATION_KINDS) == {"protected_read", "protected_write", "privileged_action", "security_setting"}
    assert set(DISCHARGER_KINDS) == {"path_guard", "identity_constraint", "ownership_check", "non_permissive_value", "validated_input"}
    assert {"authenticated_context", "request_input", "constant", "unknown"} <= set(PROVENANCE_KINDS)
    facts = load_obligation_facts()
    py = facts.for_language("python")
    reads = [op for op in py.operations if op.kind == "protected_read"]
    assert any("filter_by" in op.calls or "query" in op.calls for op in reads)  # ORM reads
    assert any("execute" in op.calls for op in py.operations)  # raw SQL access is an obligated operation too
    assert all(
        op.kind in OPERATION_KINDS and all(r in DISCHARGER_KINDS for r in op.requires) and op.sensitivity in {"low", "medium", "high"}
        for op in facts.operations
    )
    guards = [d for d in py.dischargers if d.kind == "path_guard"]
    assert any("login_required" in d.decorators for d in guards) and any(
        "token_validator" in d.calls or "jwt_required" in d.decorators for d in guards
    )
    identity = [d for d in py.dischargers if d.kind == "identity_constraint"]
    assert identity and any("user" in d.constraint_params and "owner_id" in d.constraint_params for d in identity)
    assert any("request.user" in d.identity_sources or "['sub']" in d.identity_sources for d in identity)
    assert facts.for_language("javascript").operations and facts.for_language("typescript").dischargers
    assert facts.for_language("cobol").operations == ()


def test_loader_rejects_kinds_and_fields_outside_the_closed_sets(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.facts import ObligationFactsError, load_obligation_facts

    good = (
        'version = "1"\nlanguage = "python"\n\n[[operation]]\nid = "orm-read"\nkind = "protected_read"\n'
        'calls = ["filter_by"]\nrequires = ["identity_constraint"]\nsensitivity = "high"\n'
    )
    (tmp_path / "python.toml").write_text(good)
    facts = load_obligation_facts(tmp_path)
    assert [op.id for op in facts.operations] == ["orm-read"] and facts.operations[0].resource_arg is None
    (tmp_path / "python.toml").write_text(good.replace('kind = "protected_read"', 'kind = "maybe_guard"'))
    with pytest.raises(ObligationFactsError, match="maybe_guard"):
        load_obligation_facts(tmp_path)
    (tmp_path / "python.toml").write_text(good + 'regex = "filter_.*"\n')
    with pytest.raises(ObligationFactsError, match="regex"):
        load_obligation_facts(tmp_path)
    (tmp_path / "python.toml").write_text(good.replace('requires = ["identity_constraint"]', 'requires = ["vibes"]'))
    with pytest.raises(ObligationFactsError, match="vibes"):
        load_obligation_facts(tmp_path)
    (tmp_path / "python.toml").write_text(
        good + '\n[[discharger]]\nid = "g"\nkind = "path_guard"\ndecorators = ["login_required"]\nmood = "strict"\n'
    )
    with pytest.raises(ObligationFactsError, match="mood"):
        load_obligation_facts(tmp_path)
    (tmp_path / "python.toml").write_text(good + '\n[[discharger]]\nid = "g"\nkind = "maybe_guard"\ndecorators = ["login_required"]\n')
    with pytest.raises(ObligationFactsError, match="maybe_guard"):
        load_obligation_facts(tmp_path)


def test_flow_facts_loader_ignores_the_obligation_facts_directory() -> None:
    """Obligation facts live beside the flow facts, never inside their directory: `load_facts()` must not see them."""
    from openultrasast.semantic.facts import load_facts
    from openultrasast.semantic.obligations.facts import DEFAULT_OBLIGATION_FACTS_DIR

    assert DEFAULT_OBLIGATION_FACTS_DIR.is_dir() and DEFAULT_OBLIGATION_FACTS_DIR.name == "obligations"
    flow = load_facts()
    assert not any(source.language == "obligations" for source in flow.sources)


@pytest.mark.parametrize(
    ("language", "text", "operation", "discharger"),
    [
        ("java", "class App { void run() { checkPermission(ADMINISTER); save(); } }", "jenkins-item-write", "jenkins-permission-guard"),
        ("php", "<?php function run($id) { Gate::authorize('view'); Product::findOrFail($id); }", "eloquent-read", "authorization-guard"),
    ],
)
def test_java_php_facts_resolve_operations_and_dischargers(language, text, operation, discharger) -> None:
    from openultrasast.semantic.facts import load_facts
    from openultrasast.semantic.ir import parse_file
    from openultrasast.semantic.obligations.facts import load_obligation_facts
    from openultrasast.semantic.obligations.operations import find_discharges, find_operations

    facts = load_obligation_facts().for_language(language)
    assert facts.operations and facts.dischargers
    ir = parse_file(f"app.{language}", text, language)
    assert ir.parse_ok
    assert operation in {op.fact_id for op in find_operations(ir, facts, text=text)}
    assert discharger in {d.fact_id for d in find_discharges(ir, facts, load_facts().for_language(language), text=text)}


def test_delivery_a_java_operations_and_dischargers_resolve():
    from openultrasast.semantic.obligations.facts import load_obligation_facts

    facts = load_obligation_facts().for_language("java")
    operations = {call: fact for fact in facts.operations for call in fact.calls}
    dischargers = {call: fact for fact in facts.dischargers for call in fact.calls}
    for call in (
        "lookupCredentials",
        "lookupCredentialsInItem",
        "getCredentialsFromId",
        "testConnection",
        "verifyCredentials",
        "listPropertiesOfSecrets",
        "openConnection",
        "connect",
        "publish",
        "getItemByFullName",
        "updateByXml",
    ):
        assert "path_guard" in operations[call].requires
    assert dischargers["checkPermission"].kind == dischargers["checkAnyPermission"].kind == "path_guard"
    assert dischargers["hasPermission"].kind == "ownership_check"
