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
    assert classify_guard_text("if name not in ALLOWED: abort(400)") == "allowlist_test"
    assert classify_guard_text("if len(buf) > 64: return") == "bounds_test"
    assert classify_guard_text("if value is None: return") == "null_test"
    assert classify_guard_text("page = int(raw)") == "type_change"
    assert classify_guard_text("total = total + 1") == "none"


def test_the_seeded_families_and_the_named_gaps_are_both_exact() -> None:
    """What the retained fact data can seed, and what it provably cannot — Req 9.2, a gap is *named*.

    Task 4.2 closed the gap this test was written to hold open: `path`, `output_encoding`,
    `untrusted_destination` and `prototype` now have sink facts routing to them by CWE. The set is still
    asserted exactly, so a family can neither lose its seed nor gain one without this record moving.
    """
    from openultrasast.model.specs import dominance_specs, taint_specs
    from openultrasast.model.taxonomy import load_families

    taxonomy = load_families()
    seeded = set()
    for language in ("python", "javascript", "java", "c"):
        seeded |= {spec.family for spec in taint_specs(language=language).values()}
        seeded |= {spec.family for spec in dominance_specs(language=language).values()}
    deferred = {"unknown", "memory"}  # the declined bucket and the deferred execution tier
    assert seeded == {
        "injection",
        "deserialization",
        "config_secrets",
        "access_control",
        "path",
        "output_encoding",
        "untrusted_destination",
        "prototype",
        "memory",
    }
    gaps = {family.id for family in taxonomy.families} - seeded - deferred
    assert gaps == set(), f"a family lost its seed: {sorted(gaps)}"


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


def test_a_sink_is_never_its_own_sanitizer() -> None:
    """A parameterized fact names a safe sink *shape*, not a cleansing call on the path.

    Two shipped facts have this shape: `parameterized_execute` ("execute with bound parameters is safe") and
    C's `literal_format` ("printf with a constant format string is safe"). Flattened into the sanitizer list
    each makes its sink its own sanitizer, so every flow through it reports as already-clean and nothing is
    ever entailed. Both were caught on the first live Joern run — the second only because the first was fixed
    as a class rather than as an instance.
    """
    from openultrasast.model.specs import taint_specs

    for language in ("python", "javascript", "java", "c"):
        for spec in taint_specs(language=language).values():
            overlap = set(spec.sinks) & set(spec.sanitizers)
            assert not overlap, f"{language}/{spec.family}: sink is its own sanitizer: {sorted(overlap)}"


def test_safe_shape_sinks_are_kept_for_the_shape_test() -> None:
    from openultrasast.model.specs import taint_specs

    spec = taint_specs(language="python")["injection"]
    assert "execute" in spec.safe_shape_sinks, "the safe-shape names must survive for a later shape test"
    assert "execute" not in spec.sanitizers
    c_memory = taint_specs(language="c").get("memory")
    assert c_memory is not None and "printf" in c_memory.safe_shape_sinks


def test_dischargers_carry_identity_tokens_but_not_the_negative_fields() -> None:
    """A discharger fact spreads across six fields and only three of them evidence a discharge.

    `identity_sources` (current_user, request.user) is how an identity constraint is actually written, and
    omitting it left the absence arbiter reporting "no guard" on handlers that plainly had one.
    `request_sources` and `permissive_values` describe the vulnerable shape rather than the fix -- including
    them would let the arbiter read a bug as its own fix. (`constraint_params` is excluded too, for a
    different reason, covered by its own test.)
    """
    from openultrasast.model.specs import dominance_specs
    from openultrasast.semantic.obligations import load_obligation_facts

    spec = dominance_specs(language="python")["access_control"]
    assert "current_user" in spec.dischargers
    assert "login_required" in spec.dischargers  # decorators still present

    facts = load_obligation_facts().for_language("python")
    negative = {p for fact in facts.dischargers for p in fact.request_sources} | {
        v for fact in facts.dischargers for v in fact.permissive_values
    }
    assert not (negative & set(spec.dischargers)), "the negative fields must never read as a discharge"


def test_constraint_params_are_not_dischargers_on_their_own() -> None:
    """A field named `user_id` is what an IDOR is MADE OF, not what fixes one.

    `filter_by(id=user_id)` with `user_id` taken off the request is the bug. The original checker only
    counted an identity constraint whose value's provenance was the authenticated context, so the parameter
    name alone evidences nothing. Treating it as a guard silenced the entire access_control family: on
    threatbyte-api-v1-delete every operation reported as guarded, and the arbiter found no bug at all.
    """
    from openultrasast.model.specs import dominance_specs
    from openultrasast.semantic.obligations import load_obligation_facts

    spec = dominance_specs(language="python")["access_control"]
    facts = load_obligation_facts().for_language("python")
    params = {p for fact in facts.dischargers for p in fact.constraint_params}
    assert params, "the fixture would be vacuous if the facts carried no constraint params"
    assert not (params & set(spec.dischargers)), f"constraint params must not discharge alone: {sorted(params & set(spec.dischargers))}"
    assert "current_user" in spec.dischargers, "identity sources still do discharge"


def test_configuration_facts_do_not_become_authorization_obligations() -> None:
    """contributor-scan 2.6. A permissive CORS origin is discharged by a VALUE, not by a guard.

    Taking every obligation fact made `app.run(...)` an operation requiring an authorization check, and put
    thirteen tokens in both the operation and the discharger list -- an obligation that is its own discharge,
    the same shape as the taint sink that used to sanitize itself.
    """
    from openultrasast.model.specs import dominance_specs

    spec = dominance_specs(language="python")["access_control"]

    assert not set(spec.operations) & set(spec.dischargers), "nothing may be both the obligation and its discharge"
    assert "app.run" not in spec.operations
    assert "CORS" not in spec.operations


def test_input_validation_does_not_discharge_an_authorization_obligation() -> None:
    """`jsonschema.validate` establishes the shape of a request, never who is making it."""
    from openultrasast.model.specs import dominance_specs

    spec = dominance_specs(language="python")["access_control"]

    assert "validate" not in spec.dischargers
    assert "parse_obj" not in spec.dischargers
    assert "token_validator" in spec.dischargers, "a real route guard must survive the filter"


def test_a_guard_discharges_only_the_obligation_it_is_a_guard_of() -> None:
    """The relation the facts state, which the flat list was throwing away.

    `filter_by` requires an identity_constraint or an ownership_check; `token_validator` is a path_guard.
    Pooled together, authenticating the caller discharged an object-level obligation, so a handler that
    authenticates and then looks the record up by a PATH parameter read as fully guarded -- VAmPI's broken
    object-level authorization, and the shape of most real IDORs.
    """
    from openultrasast.model.specs import dominance_specs

    spec = dominance_specs(language="python")["access_control"]

    assert spec.requirements["filter_by"] == ("identity_constraint", "ownership_check")
    identity = set(spec.dischargers_by_kind["identity_constraint"])
    assert "token_validator" not in identity, "authentication is not an object-level check"
    assert "token_validator" in set(spec.dischargers_by_kind["path_guard"])
    assert "['sub']" in identity or '["sub"]' in identity


def test_a_sink_is_matched_as_a_word_not_a_substring() -> None:
    """contributor-scan: `fgets` contains `gets`, and the safe API is not the dangerous one.

    The sink matcher's last clause was an unbounded `methodFullName.contains(n)`, so every bounded read in
    libpng matched the sink for the unbounded one: all 26 entailed findings on that repository were the same
    false positive, `*argv -> fgets(buf, 256, f)`. Third instance of this bug class here, after the sanitizer
    that matched `resolve` inside `resolveUrl` and the discharger that matched `user` inside `users`.

    The query is Scala, so this asserts the fact tables still carry the pair that made it visible; the
    boundary itself is exercised against a real CPG in the repository measurements.
    """
    from openultrasast.model.specs import taint_specs

    memory = taint_specs(language="c")["memory"]

    assert "gets" in memory.sinks, "the unbounded read is a sink"
    assert "fgets" in memory.sources, "the bounded read is a SOURCE of untrusted input, never a sink"
    assert "fgets" not in memory.sinks


def test_php_facts_derive_the_families_a_web_application_needs() -> None:
    """contributor-scan 5.1, toward the WordPress target.

    Written against a real PHP CPG rather than against PHP source, because the two do not look alike: a
    superglobal is an `<operator>.indexAccess` whose CODE reads `$_GET["name"]`, while a dangerous operation
    is a plain call named `mysqli_query` or `echo`. Sources therefore match on code and sinks on name.
    """
    from openultrasast.model.specs import taint_specs

    families = taint_specs(language="php")

    assert {"injection", "output_encoding", "path", "deserialization", "untrusted_destination"} <= set(families)
    injection = families["injection"]
    assert "mysqli_query" in injection.sinks, "SQL"
    assert "system" in injection.sinks, "command execution"
    assert "$_GET" in injection.sources, "a superglobal is matched on the code of an index access"
    assert "echo" in families["output_encoding"].sinks, "PHP's XSS sink is a language construct php2cpg emits as a call"


def test_no_php_sink_is_its_own_sanitizer() -> None:
    """The bug class this codebase has hit three times, asserted for the newest fact table before it can."""
    from openultrasast.model.specs import taint_specs

    for family, spec in taint_specs(language="php").items():
        assert not set(spec.sinks) & set(spec.sanitizers), f"{family}: an operation that discharges itself can never be reported"


def test_a_php_file_can_become_a_region() -> None:
    """Facts alone reach nothing: `_LANGUAGES` decides whether a file is offered to the model layer at all."""
    from openultrasast.model.regions import regions_for

    class _Target:
        path = "wp-admin/admin-ajax.php"
        language = "php"
        loc = 100
        tags: tuple[str, ...] = ()

    regions = regions_for([], [_Target()])

    assert regions, "a php file with no entry point should still yield a file-level region"
    assert regions[0].language == "php"


def test_wordpress_database_calls_are_matched_qualified() -> None:
    """contributor-scan: WordPress never calls mysqli directly, it goes through $wpdb.

    Verified against a CPG: `$wpdb->get_var(..)` is a call NAMED `get_var` whose CODE carries the qualifier.
    The qualified form is what belongs in the table -- a bare `get_var` or `query` would match any method of
    that name anywhere, which is the generic-name trap that made `query.get` match every `.get(` in a
    repository.
    """
    from openultrasast.model.specs import taint_specs

    injection = taint_specs(language="php")["injection"]

    assert "$wpdb->get_var" in injection.sinks
    assert "$wpdb->query" in injection.sinks
    assert "get_var" not in injection.sinks, "unqualified would match any method of that name"
    assert "query" not in injection.sinks
    # insert/update/delete take arrays and WordPress prepares them itself.
    assert "$wpdb->insert" not in injection.sinks


def test_a_sanitizer_that_does_not_stop_sql_injection_is_not_listed() -> None:
    """CVE-2023-23488 is a `sanitize_text_field` value concatenated into a query.

    `sanitize_text_field`, `esc_html` and `esc_attr` are real WordPress sanitizers and none of them stops SQL
    injection. Listing them -- the obvious thing to do when writing PHP facts -- would make that CVE and its
    whole class invisible, because the sanitizer list is flat across families and cannot say "escapes for
    HTML but not for SQL". Recorded as task 5.6.
    """
    from openultrasast.model.specs import taint_specs

    sanitizers = set(taint_specs(language="php")["injection"].sanitizers)

    assert "sanitize_text_field" not in sanitizers
    assert "esc_html" not in sanitizers
    assert "$wpdb->prepare" in sanitizers, "the parameterized form does stop it"
    assert "esc_sql" in sanitizers
