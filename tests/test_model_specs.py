"""model-grounded-detection task 1.1: the security vocabularies survive the modules that carried them.

The guard vocabulary lived in `semantic/variants.py`, whose optimisation loop this feature deletes. The
source/sink/sanitizer facts and the obligation facts live in `ruleset/` data and are retained, so the specs
*derive* from them rather than copying them — a copy would be a second place to update. What must be ported
verbatim is the guard vocabulary, because nothing else holds it.
"""

from __future__ import annotations

import ast
from pathlib import Path

SPECS = Path("src/openultrasast/model/specs.py")


def test_the_guard_vocabulary_is_preserved_verbatim() -> None:
    from openultrasast.model.specs import GUARD_KINDS

    assert GUARD_KINDS == ("null_test", "bounds_test", "allowlist_test", "auth_check", "parameterized_call", "type_change", "none")


def test_the_guard_classifier_still_recognises_each_kind() -> None:
    """The patterns classify the *fix*, first match wins — the order is part of the vocabulary."""
    from openultrasast.model.specs import classify_guard_text

    assert classify_guard_text('cur.execute("SELECT * FROM t WHERE id = %s", (uid,))') == "parameterized_call"
    assert classify_guard_text("if not current_user.is_authenticated: abort(403)") == "auth_check"
    assert classify_guard_text('if name not in ALLOWED: abort(400)') == "allowlist_test"
    assert classify_guard_text("if len(buf) > 64: return") == "bounds_test"
    assert classify_guard_text("if value is None: return") == "null_test"
    assert classify_guard_text("page = int(raw)") == "type_change"
    assert classify_guard_text("total = total + 1") == "none"


def test_the_seeded_families_and_the_named_gaps_are_both_exact() -> None:
    """What the retained fact data can seed, and what it provably cannot — Req 9.2, a gap is *named*.

    `path`, `output_encoding`, `untrusted_destination` and `prototype` have no sink in `ruleset/semantic`
    whose CWE routes to them, which is the same hole the entailment ceiling diagnosed ("closed literal sink
    table: misses per-family sinks"). Task 4.2 authors those sinks and must update this test when it does —
    the set is asserted exactly so a gap can neither appear nor close silently.
    """
    from openultrasast.model.specs import dominance_specs, taint_specs
    from openultrasast.model.taxonomy import load_families

    taxonomy = load_families()
    seeded = set()
    for language in ("python", "javascript", "java", "c"):
        seeded |= {spec.family for spec in taint_specs(language=language).values()}
        seeded |= {spec.family for spec in dominance_specs(language=language).values()}
    deferred = {"unknown", "memory"}  # the declined bucket and the deferred execution tier
    assert seeded == {"injection", "deserialization", "config_secrets", "access_control", "memory"}
    gaps = {family.id for family in taxonomy.families} - seeded - deferred
    assert gaps == {"path", "output_encoding", "untrusted_destination", "prototype"}, (
        "a family lost or gained a seed without this record being updated"
    )


def test_the_injection_taint_spec_carries_sources_sinks_and_sanitizers() -> None:
    from openultrasast.model.specs import taint_specs

    spec = taint_specs(language="python")["injection"]
    assert any("request.args" in source for source in spec.sources)
    assert any(sink in ("eval", "exec", "os.system") for sink in spec.sinks)
    assert spec.sanitizers, "a family with no sanitizer model can never distinguish a fixed twin"


def test_the_access_control_dominance_spec_carries_operations_and_dischargers() -> None:
    from openultrasast.model.specs import dominance_specs

    spec = dominance_specs(language="python")["access_control"]
    assert any("filter_by" in operation for operation in spec.operations)
    assert spec.dischargers, "an absence family with no discharger model can only ever report suspicion"


def test_specs_import_nothing_from_the_removed_packages() -> None:
    """Req 1.2: the vocabularies must not depend on the modules this feature deletes."""
    tree = ast.parse(SPECS.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    forbidden = ("learning", "improve", "variants", "mechanisms", "evolve")
    offending = [name for name in imported if any(token in name for token in forbidden)]
    assert not offending, f"model/specs.py imports removed code: {offending}"


def test_the_specs_module_exposes_no_writer() -> None:
    """Req 7.4, the verifier boundary: the models are read-only data no LLM or optimiser can rewrite."""
    tree = ast.parse(SPECS.read_text())
    writers = [
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and any(node.name.startswith(verb) for verb in ("write", "save", "dump", "store", "append", "update", "set_"))
    ]
    assert not writers, f"specs must be read-only, found writers: {writers}"
    assert "open(" not in SPECS.read_text().replace("# ", ""), "specs must not open a file for writing"
