"""access-control-prover task 7.3: authority abstract values and promoted implication facts (offline).

Exact, finite and unknown authorities per the design's "Abstract evidence domain" section (Req 2.1, 2.2,
2.5, 2.7, 11.1), the promoted implication facts that carry one authority implying another with the
supporting fact id retained (Req 2.8), and the satisfy query stated in the EvidenceRelation algebra
from task 7.1: sufficient authority is MUST, insufficient is NO, undecidable is UNKNOWN, and a finite set
with one satisfying alternative is MAY.
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from openultrasast.semantic.obligations.abstract_domain import AuthorityImplication, AuthorityRef


def _authority_fixtures() -> tuple[AuthorityRef, ...]:
    from openultrasast.semantic.obligations.abstract_domain import UNKNOWN_AUTHORITY, parse_authority

    return (
        parse_authority("admin"),
        parse_authority("staff"),
        parse_authority("guest"),
        parse_authority(["admin", "guest"]),
        parse_authority(["staff", "owner"]),
        UNKNOWN_AUTHORITY,
    )


def _implication_fixtures() -> tuple[AuthorityImplication, ...]:
    from openultrasast.semantic.obligations.abstract_domain import AuthorityImplication

    # owner -> staff -> authenticated, plus admin -> owner: a chain promotion must be able to walk.
    return (
        AuthorityImplication(id="admin-covers-owner", authority="admin", implies="owner"),
        AuthorityImplication(id="owner-covers-staff", authority="owner", implies="staff"),
        AuthorityImplication(id="staff-covers-authenticated", authority="staff", implies="authenticated"),
    )


_IMPLICATION_TOML = """version = "1"
language = "python"

[[operation]]
id = "orm-read"
kind = "protected_read"
calls = ["filter_by"]
requires = ["identity_constraint"]
sensitivity = "high"

[[implication]]
id = "admin-covers-owner"
authority = "admin"
implies = "owner"

[[implication]]
id = "owner-covers-staff"
authority = "owner"
implies = "staff"
"""


def test_parse_authority_single_name_is_exact() -> None:
    from openultrasast.semantic.obligations.abstract_domain import AuthorityRef, parse_authority

    authority = parse_authority("admin")
    assert authority == AuthorityRef(values=("admin",))
    assert authority.values == ("admin",)
    assert authority.is_unknown is False


def test_parse_authority_name_collection_is_a_finite_set() -> None:
    from openultrasast.semantic.obligations.abstract_domain import AuthorityRef, parse_authority

    authority = parse_authority(["owner", "admin", "owner"])
    assert authority == AuthorityRef(values=("admin", "owner"))


def test_parse_authority_without_a_binding_is_unknown() -> None:
    from openultrasast.semantic.obligations.abstract_domain import UNKNOWN_AUTHORITY, parse_authority

    authority = parse_authority(None)
    assert authority == UNKNOWN_AUTHORITY
    assert authority.is_unknown is True
    assert authority.values == ()


def test_authority_grades_distinguish_exact_finite_and_unknown() -> None:
    # Req 11.1: authority compatibility distinguishes definite, possible, absent and unknown evidence.
    from openultrasast.semantic.obligations.abstract_domain import UNKNOWN_AUTHORITY, parse_authority

    exact = parse_authority("admin")
    finite = parse_authority(["admin", "owner"])
    grades = {exact, finite, UNKNOWN_AUTHORITY}
    assert len(grades) == 3
    assert (len(exact.values), exact.is_unknown) == (1, False)
    assert (len(finite.values), finite.is_unknown) == (2, False)
    assert UNKNOWN_AUTHORITY.values == () and UNKNOWN_AUTHORITY.is_unknown


def test_authority_values_are_normalized_deterministically() -> None:
    from openultrasast.semantic.obligations.abstract_domain import AuthorityRef

    forward = AuthorityRef(values=("owner", "admin", "owner"))
    backward = AuthorityRef(values=("admin", "owner"))
    assert forward == backward
    assert hash(forward) == hash(backward)
    assert len({forward, backward}) == 1


def test_authority_ref_fails_loud_on_misshapen_values() -> None:
    from openultrasast.semantic.obligations.abstract_domain import AuthorityRef

    with pytest.raises(ValueError, match="at least one"):
        AuthorityRef(values=())
    with pytest.raises(ValueError, match="unknown authority"):
        AuthorityRef(values=("admin",), is_unknown=True)
    with pytest.raises(ValueError, match="misshapen"):
        AuthorityRef(values=("admin", ""))
    with pytest.raises(ValueError, match="misshapen"):
        AuthorityRef(values=("",))


def test_parse_authority_rejects_misshapen_bindings() -> None:
    from openultrasast.semantic.obligations.abstract_domain import parse_authority

    with pytest.raises(ValueError):
        parse_authority("")
    with pytest.raises(ValueError):
        parse_authority(())
    with pytest.raises(ValueError):
        parse_authority(["admin", ""])


def test_join_authorities_keeps_identical_exact_authorities_exact() -> None:
    from openultrasast.semantic.obligations.abstract_domain import join_authorities, parse_authority

    authority = parse_authority("admin")
    assert join_authorities(authority, parse_authority("admin")) == authority


def test_join_authorities_merges_different_authorities_into_a_finite_set() -> None:
    from openultrasast.semantic.obligations.abstract_domain import join_authorities, parse_authority

    joined = join_authorities(parse_authority("admin"), parse_authority("owner"))
    assert joined == parse_authority(["admin", "owner"])


def test_join_authorities_unions_finite_sets_to_their_superset() -> None:
    from openultrasast.semantic.obligations.abstract_domain import join_authorities, parse_authority

    subset = parse_authority(["admin"])
    superset = parse_authority(["admin", "owner"])
    assert join_authorities(subset, superset) == superset
    assert join_authorities(superset, subset) == superset
    assert join_authorities(parse_authority(["admin"]), parse_authority(["staff"])) == parse_authority(["admin", "staff"])


def test_join_authorities_unknown_absorbs_every_fixture() -> None:
    # Req 11.1: an unresolvable authority stays unresolvable; joining cannot manufacture precision.
    from openultrasast.semantic.obligations.abstract_domain import UNKNOWN_AUTHORITY, join_authorities

    for other in _authority_fixtures():
        assert join_authorities(other, UNKNOWN_AUTHORITY) == UNKNOWN_AUTHORITY, other
        assert join_authorities(UNKNOWN_AUTHORITY, other) == UNKNOWN_AUTHORITY, other


def test_join_authorities_is_commutative_and_idempotent_over_fixtures() -> None:
    from openultrasast.semantic.obligations.abstract_domain import join_authorities

    fixtures = _authority_fixtures()
    for left, right in itertools.product(fixtures, repeat=2):
        assert join_authorities(left, right) == join_authorities(right, left), (left, right)
    for authority in fixtures:
        assert join_authorities(authority, authority) == authority, authority


def test_sufficient_exact_authority_satisfies_the_required_authority() -> None:
    # Req 2.5, 11.1: a witness holding exactly the required authority is a definite match.
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, authority_satisfies, parse_authority

    assert authority_satisfies(parse_authority("admin"), parse_authority("admin")) is EvidenceRelation.MUST


def test_sufficient_authority_via_promoted_implication_satisfies() -> None:
    # Req 2.8: one authority implying another discharges the requirement, from promoted facts only.
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, authority_satisfies, parse_authority

    implications = _implication_fixtures()
    assert authority_satisfies(parse_authority("staff"), parse_authority("authenticated"), implications) is EvidenceRelation.MUST
    assert authority_satisfies(parse_authority("admin"), parse_authority("staff"), implications) is EvidenceRelation.MUST


def test_transitive_implication_chain_satisfies_across_every_hop() -> None:
    # Req 2.8: admin -> owner -> staff -> authenticated must hold end to end.
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, authority_satisfies, parse_authority

    assert authority_satisfies(parse_authority("admin"), parse_authority("authenticated"), _implication_fixtures()) is EvidenceRelation.MUST


def test_cyclic_implications_terminate() -> None:
    from openultrasast.semantic.obligations.abstract_domain import (
        AuthorityImplication,
        EvidenceRelation,
        authority_satisfies,
        parse_authority,
    )

    ring = (
        AuthorityImplication(id="billing-covers-audit", authority="billing", implies="audit"),
        AuthorityImplication(id="audit-covers-billing", authority="audit", implies="billing"),
    )
    assert authority_satisfies(parse_authority("billing"), parse_authority("audit"), ring) is EvidenceRelation.MUST
    assert authority_satisfies(parse_authority("billing"), parse_authority("admin"), ring) is EvidenceRelation.NO


def test_implication_applies_only_when_promoted() -> None:
    # Req 2.8: the engine bakes in no implication vocabulary; without the promoted fact it is NO.
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, authority_satisfies, parse_authority

    assert authority_satisfies(parse_authority("staff"), parse_authority("authenticated"), ()) is EvidenceRelation.NO


def test_insufficient_authority_is_definitely_insufficient() -> None:
    # Req 2.5: an insufficient authority must not discharge the operation; the relation is NO.
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, authority_satisfies, parse_authority

    assert authority_satisfies(parse_authority("guest"), parse_authority("admin"), _implication_fixtures()) is EvidenceRelation.NO


def test_unknown_held_authority_cannot_be_decided() -> None:
    # Req 2.7, 11.1: undecidable authority compatibility is UNKNOWN, never a broad match or a rejection.
    from openultrasast.semantic.obligations.abstract_domain import (
        UNKNOWN_AUTHORITY,
        EvidenceRelation,
        authority_satisfies,
        parse_authority,
    )

    assert authority_satisfies(UNKNOWN_AUTHORITY, parse_authority("admin"), _implication_fixtures()) is EvidenceRelation.UNKNOWN


def test_unknown_required_authority_cannot_be_decided() -> None:
    # Req 2.7: an unresolvable requirement is UNKNOWN, so the pair cannot become a final verdict.
    from openultrasast.semantic.obligations.abstract_domain import (
        UNKNOWN_AUTHORITY,
        EvidenceRelation,
        authority_satisfies,
        parse_authority,
    )

    assert authority_satisfies(parse_authority("admin"), UNKNOWN_AUTHORITY, _implication_fixtures()) is EvidenceRelation.UNKNOWN


def test_finite_authority_with_one_satisfying_alternative_is_possible() -> None:
    # Req 11.1: one satisfying and one failing alternative join to MAY, never to MUST or NO.
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, authority_satisfies, parse_authority

    relation = authority_satisfies(parse_authority(["admin", "guest"]), parse_authority("admin"), _implication_fixtures())
    assert relation is EvidenceRelation.MAY


def test_finite_authority_with_all_alternatives_satisfying_is_definite() -> None:
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, authority_satisfies, parse_authority

    relation = authority_satisfies(parse_authority(["admin", "owner"]), parse_authority("staff"), _implication_fixtures())
    assert relation is EvidenceRelation.MUST


def test_widened_required_authority_stays_possible_not_definite() -> None:
    # Req 2.7, 11.1: a requirement only imprecisely resolved to {authenticated, guest} is MAY, not MUST.
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, authority_satisfies, parse_authority

    relation = authority_satisfies(parse_authority("admin"), parse_authority(["authenticated", "guest"]), _implication_fixtures())
    assert relation is EvidenceRelation.MAY


def test_authority_satisfies_folds_single_pairs_with_join_alternatives() -> None:
    # The 7.1 law: the aggregate is exactly join_alternatives over every held x required singleton pair.
    from openultrasast.semantic.obligations.abstract_domain import (
        EvidenceRelation,
        authority_satisfies,
        join_alternatives,
        parse_authority,
    )

    implications = _implication_fixtures()
    for held, required in itertools.product(_authority_fixtures(), repeat=2):
        aggregated = authority_satisfies(held, required, implications)
        if held.is_unknown or required.is_unknown:
            assert aggregated is EvidenceRelation.UNKNOWN, (held, required)
            continue
        folded: EvidenceRelation | None = None
        for held_name in held.values:
            for required_name in required.values:
                single = authority_satisfies(parse_authority(held_name), parse_authority(required_name), implications)
                folded = single if folded is None else join_alternatives(folded, single)
        assert folded == aggregated, (held, required)


def test_widening_either_authority_never_gains_definiteness() -> None:
    # Req 11.1, 11.6: coarsening a value moves the relation up the precision order or leaves it.
    from openultrasast.semantic.obligations.abstract_domain import at_least_as_precise, authority_satisfies, join_authorities

    implications = _implication_fixtures()
    fixtures = _authority_fixtures()
    for held, required, extra in itertools.product(fixtures, repeat=3):
        base = authority_satisfies(held, required, implications)
        wider_held = authority_satisfies(join_authorities(held, extra), required, implications)
        assert at_least_as_precise(base, wider_held), (held, extra, required)
        wider_required = authority_satisfies(held, join_authorities(required, extra), implications)
        assert at_least_as_precise(base, wider_required), (held, required, extra)


def test_supporting_implications_retain_the_fact_ids_used() -> None:
    # Req 2.8: the implications used on the satisfying path are retained with their supporting fact ids.
    from openultrasast.semantic.obligations.abstract_domain import authority_satisfies, parse_authority, supporting_implications

    implications = _implication_fixtures()
    used = supporting_implications(parse_authority("admin"), parse_authority("authenticated"), implications)
    assert [implication.id for implication in used] == [
        "admin-covers-owner",
        "owner-covers-staff",
        "staff-covers-authenticated",
    ]
    assert authority_satisfies(parse_authority("admin"), parse_authority("authenticated"), implications).value == "must"


def test_supporting_implications_are_empty_for_identity_and_for_failure() -> None:
    from openultrasast.semantic.obligations.abstract_domain import (
        UNKNOWN_AUTHORITY,
        parse_authority,
        supporting_implications,
    )

    implications = _implication_fixtures()
    assert supporting_implications(parse_authority("admin"), parse_authority("admin"), implications) == ()
    assert supporting_implications(parse_authority("guest"), parse_authority("admin"), implications) == ()
    assert supporting_implications(UNKNOWN_AUTHORITY, parse_authority("admin"), implications) == ()


def test_supporting_implications_deduplicate_stably() -> None:
    from openultrasast.semantic.obligations.abstract_domain import parse_authority, supporting_implications

    implications = _implication_fixtures()
    assert supporting_implications(parse_authority("owner"), parse_authority("staff"), implications + implications) == (implications[1],)


def test_implication_facts_load_and_retain_supporting_ids(tmp_path: Path) -> None:
    # Req 2.8: implications come from promoted fact rows, keep the row id for the trace, and stay
    # AuthorityImplication values so the checker can feed them straight into the satisfy algebra.
    from openultrasast.semantic.obligations.abstract_domain import AuthorityImplication
    from openultrasast.semantic.obligations.facts import ImplicationFact, load_obligation_facts

    (tmp_path / "python.toml").write_text(_IMPLICATION_TOML)
    facts = load_obligation_facts(tmp_path)
    assert facts.implications == (
        ImplicationFact(id="admin-covers-owner", authority="admin", implies="owner", language="python"),
        ImplicationFact(id="owner-covers-staff", authority="owner", implies="staff", language="python"),
    )
    assert all(isinstance(implication, AuthorityImplication) for implication in facts.implications)


def test_implication_facts_default_to_empty(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.facts import load_obligation_facts

    (tmp_path / "python.toml").write_text(
        'version = "1"\nlanguage = "python"\n\n[[operation]]\nid = "orm-read"\nkind = "protected_read"\n'
        'calls = ["filter_by"]\nrequires = ["identity_constraint"]\nsensitivity = "high"\n'
    )
    assert load_obligation_facts(tmp_path).implications == ()


def test_implication_facts_filter_by_language(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.facts import load_obligation_facts

    (tmp_path / "python.toml").write_text(_IMPLICATION_TOML)
    (tmp_path / "ruby.toml").write_text(
        'version = "1"\nlanguage = "ruby"\n\n[[implication]]\nid = "ruby-maintainer-covers-reporter"\n'
        'authority = "maintainer"\nimplies = "reporter"\n'
    )
    all_languages = load_obligation_facts(tmp_path)
    assert {implication.id for implication in all_languages.implications} == {
        "admin-covers-owner",
        "owner-covers-staff",
        "ruby-maintainer-covers-reporter",
    }
    python = all_languages.for_language("python")
    assert [implication.id for implication in python.implications] == ["admin-covers-owner", "owner-covers-staff"]
    assert all_languages.for_language("ruby").implications != python.implications


def test_implication_fact_rejects_unknown_fields(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.facts import ObligationFactsError, load_obligation_facts

    (tmp_path / "python.toml").write_text(_IMPLICATION_TOML + "weight = 3\n")
    with pytest.raises(ObligationFactsError, match="weight"):
        load_obligation_facts(tmp_path)


def test_implication_fact_rejects_missing_or_misshapen_names(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.facts import ObligationFactsError, load_obligation_facts

    (tmp_path / "python.toml").write_text('version = "1"\nlanguage = "python"\n\n[[implication]]\nid = "broken"\nimplies = "owner"\n')
    with pytest.raises(ObligationFactsError, match="authority"):
        load_obligation_facts(tmp_path)
    (tmp_path / "python.toml").write_text('version = "1"\nlanguage = "python"\n\n[[implication]]\nid = "broken"\nauthority = "admin"\n')
    with pytest.raises(ObligationFactsError, match="implies"):
        load_obligation_facts(tmp_path)
    (tmp_path / "python.toml").write_text(
        'version = "1"\nlanguage = "python"\n\n[[implication]]\nid = "broken"\nauthority = "admin"\nimplies = ""\n'
    )
    with pytest.raises(ObligationFactsError, match="implies"):
        load_obligation_facts(tmp_path)


def test_sufficient_insufficient_and_unknown_fixtures_produce_the_specified_relations() -> None:
    # The task's three fixture grades: sufficient -> MUST, insufficient -> NO, unknown -> UNKNOWN.
    from openultrasast.semantic.obligations.abstract_domain import (
        UNKNOWN_AUTHORITY,
        EvidenceRelation,
        authority_satisfies,
        parse_authority,
    )

    implications = _implication_fixtures()
    sufficient = (
        (parse_authority("admin"), parse_authority("admin")),
        (parse_authority("staff"), parse_authority("authenticated")),
        (parse_authority(["admin", "owner"]), parse_authority("staff")),
    )
    for held, required in sufficient:
        assert authority_satisfies(held, required, implications) is EvidenceRelation.MUST, (held, required)
    insufficient = (
        (parse_authority("guest"), parse_authority("admin")),
        (parse_authority("staff"), parse_authority("authenticated"), ()),
    )
    for fixture in insufficient:
        held, required, *rest = fixture
        assert authority_satisfies(held, required, *rest) is EvidenceRelation.NO, fixture
    assert authority_satisfies(UNKNOWN_AUTHORITY, parse_authority("admin"), implications) is EvidenceRelation.UNKNOWN
    assert authority_satisfies(parse_authority("admin"), UNKNOWN_AUTHORITY, implications) is EvidenceRelation.UNKNOWN
