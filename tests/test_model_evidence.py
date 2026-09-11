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


def test_the_score_orders_within_a_tier_and_never_across_one() -> None:
    """Phase 2: the published weights rank pairs inside a tier. They cannot lift a pair out of tier 0 --
    a pair with no sink scores nothing whatever the weights say -- and counts are capped so a 346-sink
    file-scope region does not outrank everything by volume alone."""
    from openultrasast.model.evidence import OPEN_SINK_CAP, WEIGHTS, Evidence, SinkEvidence

    def sink(n: int, cleansed: bool = False) -> SinkEvidence:
        return SinkEvidence(code=f"q({n})", line=n, method="m", arity=1, arg0_literal=False, cleansed_on_call=cleansed)

    nothing = Evidence(sinks=(), source_local=True)
    assert nothing.tier == 0 and nothing.score == 0.0, "no sink, no score: the weights cannot manufacture a pair"

    one = Evidence(sinks=(sink(1),), source_near=True)
    local = Evidence(sinks=(sink(1),), source_local=True)
    assert local.tier > one.tier, "a local source is the higher tier, not merely the higher score"
    assert local.score == WEIGHTS["open_sink"] + WEIGHTS["source_local"]

    many = Evidence(sinks=tuple(sink(i) for i in range(50)), source_near=True)
    assert many.tier == one.tier
    assert many.score == WEIGHTS["open_sink"] * OPEN_SINK_CAP + WEIGHTS["source_near"], "capped: volume stops counting"

    cleansed = Evidence(sinks=(sink(1), sink(2, cleansed=True)), source_near=True)
    assert cleansed.score < one.score, "a cleansed sink beside an open one counts against the pair"
    assert sorted([many, one, local], key=lambda e: e.order_key, reverse=True) == [local, many, one]


def test_the_query_may_answer_carried_itself() -> None:
    """Stage one of the two-stage join, reported by the query as `carried`. When present it is the answer;
    when absent the caller's value stands, and absent-and-unknown stays None rather than becoming False."""
    from openultrasast.model.evidence import TIER_OPEN, TIER_OPEN_PUBLIC, evidence_from_rows

    sink = {
        "kind": "sink",
        "sink": "unlink($f)",
        "sinkLine": "259",
        "sinkMethod": "_delete_files",
        "sinkArity": 1,
        "sinkArg0Literal": False,
        "cleansedOnCall": False,
    }
    said = evidence_from_rows([{"kind": "summary", "sinks": 1, "sourceNear": True, "carried": True, "familyInRepo": True}, sink])
    assert said is not None and said.carried is True and said.tier == TIER_OPEN_PUBLIC
    silent = evidence_from_rows([{"kind": "summary", "sinks": 1, "sourceNear": True, "familyInRepo": True}, sink])
    assert silent is not None and silent.carried is None and silent.tier == TIER_OPEN
    told = evidence_from_rows([{"kind": "summary", "sinks": 1, "sourceNear": True, "familyInRepo": True}, sink], carried=True)
    assert told is not None and told.carried is True
