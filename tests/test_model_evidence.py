"""The evidence vector and its tiers, on canned rows (flow-aware-ranking phase 0)."""

from __future__ import annotations

from openultrasast.model.evidence import (
    TIER_CLEANSED,
    TIER_EXCLUDE,
    TIER_NO_SOURCE,
    TIER_OPEN,
    TIER_OPEN_PUBLIC,
    evidence_from_rows,
)

SUMMARY = {"kind": "summary", "sinks": 1, "sourceLocal": False, "sourceNear": False, "familyInRepo": True}


def _sink(code: str, *, literal: bool = False, cleansed: bool = False, arity: int = 1) -> dict[str, object]:
    return {
        "kind": "sink",
        "sink": code,
        "sinkLine": "936",
        "sinkMethod": "f",
        "sinkArity": arity,
        "sinkArg0Literal": literal,
        "cleansedOnCall": cleansed,
    }


def test_a_failed_query_is_not_a_tier() -> None:
    """No rows at all means the query did not answer. That is a degradation, never tier 0."""
    assert evidence_from_rows(None) is None
    assert evidence_from_rows([]) is None


def test_no_sink_in_scope_is_tier_zero_and_exact() -> None:
    """The only tier that excludes. A family with no sink in reach cannot produce a flow, in any language."""
    e = evidence_from_rows([{**SUMMARY, "sinks": 0}], entry=True)
    assert e is not None and e.tier == TIER_EXCLUDE


def test_no_sink_anywhere_in_the_repository_is_tier_zero_at_any_depth() -> None:
    """PMPro never calls `unserialize`: all 487 deserialization requests were asked of nothing."""
    e = evidence_from_rows([{**SUMMARY, "familyInRepo": False}, _sink("x($y)")], entry=True)
    assert e is not None and e.tier == TIER_EXCLUDE


def test_a_sink_with_no_source_is_asked_last() -> None:
    e = evidence_from_rows([SUMMARY, _sink('$wpdb->get_row("... $id")')])
    assert e is not None and e.tier == TIER_NO_SOURCE


def test_the_cve_shape_is_the_top_tier() -> None:
    """CVE-2023-23488: an entry-point method whose sink concatenates a parameter into SQL, with `esc_sql`
    present in the FUNCTION but wrapping a different statement -- so `cleansedOnCall` is false here."""
    e = evidence_from_rows(
        [SUMMARY, _sink('$wpdb->get_var("... WHERE code = \'" . $code . "\'")', cleansed=False)],
        entry=True,
    )
    assert e is not None and e.tier == TIER_OPEN
    assert len(e.open_sinks) == 1


def test_cleansing_on_the_call_itself_lowers_the_tier() -> None:
    """The fixed side of that pair wraps the value in `$wpdb->prepare`, which is an ancestor of the argument."""
    e = evidence_from_rows([SUMMARY, _sink('$wpdb->get_var($wpdb->prepare("... %s", $code))', cleansed=True)], entry=True)
    assert e is not None and e.tier == TIER_CLEANSED


def test_a_literal_argument_cannot_carry_taint() -> None:
    e = evidence_from_rows([SUMMARY, _sink('system("ls")', literal=True)], entry=True)
    assert e is not None and e.tier == TIER_CLEANSED


def test_a_bound_shape_is_the_arbiters_own_rule() -> None:
    """`execute(sql, params)` binds where `execute(sql + x)` interpolates; same rule the taint verdict uses."""
    e = evidence_from_rows([SUMMARY, _sink("cursor.execute(sql, params)", arity=2)], entry=True, bound_names=("execute",))
    assert e is not None and e.tier == TIER_CLEANSED


def test_declared_public_or_a_local_source_asks_very_first() -> None:
    public = evidence_from_rows([SUMMARY, _sink("unlink($f)")], entry=True, access_declared_public=True)
    local = evidence_from_rows([{**SUMMARY, "sourceLocal": True}, _sink("unlink($_GET['f'])")])
    assert public is not None and public.tier == TIER_OPEN_PUBLIC
    assert local is not None and local.tier == TIER_OPEN_PUBLIC


def test_a_carried_field_counts_as_a_source() -> None:
    """`_delete_files()` has no parameters; its taint arrives as `$this->attachments`. Stage one of the join
    already knows that, and the vector must not demote the region for lacking a direct source."""
    e = evidence_from_rows([SUMMARY, _sink("unlink($file)")], carried=True)
    assert e is not None and e.tier == TIER_OPEN_PUBLIC


def test_a_stringified_boolean_is_read_as_its_value_not_its_truthiness() -> None:
    """`bool("False")` is True. A serialiser that chose strings would make every open sink read as cleansed."""
    rows = [{**SUMMARY, "sourceLocal": "False", "familyInRepo": "true"}, _sink("unlink($f)")]
    rows[1]["cleansedOnCall"] = "False"
    e = evidence_from_rows(rows, entry=True)
    assert e is not None and e.tier == TIER_OPEN, "a 'False' string must not turn an open sink into a cleansed one"
