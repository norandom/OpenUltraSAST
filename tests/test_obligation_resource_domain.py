"""access-control-prover task 7.2: resource abstract values and operation-fact sufficiency fields (offline).

Exact resources, finite alias sets, request-global scope and unknown resources per the design's "Abstract
evidence domain" section (Req 2.1, 2.5, 2.6, 2.7, 11.1), plus the additive operation-fact field that declares
a request-global witness kind sufficient at request scope (Req 2.6).
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest


def _resource_fixtures():
    from openultrasast.semantic.obligations.abstract_domain import (
        REQUEST_GLOBAL_RESOURCE,
        UNKNOWN_RESOURCE,
        ResourceRef,
    )

    return (
        ResourceRef(kind="exact", values=("book",)),
        ResourceRef(kind="exact", values=("volume",)),
        ResourceRef(kind="aliases", values=("book", "volume")),
        ResourceRef(kind="aliases", values=("volume", "shelf")),
        REQUEST_GLOBAL_RESOURCE,
        UNKNOWN_RESOURCE,
    )


_OPERATION_TOML = """version = "1"
language = "python"

[[operation]]
id = "orm-read"
kind = "protected_read"
calls = ["filter_by"]
requires = ["identity_constraint"]
sensitivity = "high"
request_global_kinds = ["path_guard"]
"""


def test_parse_resource_single_token_is_exact() -> None:
    from openultrasast.semantic.obligations.abstract_domain import ResourceRef, parse_resource

    binding = parse_resource("book")
    assert binding == ResourceRef(kind="exact", values=("book",))
    assert binding.kind == "exact"
    assert binding.values == ("book",)


def test_parse_resource_token_collection_is_a_finite_alias_set() -> None:
    from openultrasast.semantic.obligations.abstract_domain import ResourceRef, parse_resource

    binding = parse_resource(["volume", "book", "volume"])
    assert binding == ResourceRef(kind="aliases", values=("book", "volume"))


def test_parse_resource_without_a_binding_is_unknown() -> None:
    from openultrasast.semantic.obligations.abstract_domain import UNKNOWN_RESOURCE, parse_resource

    binding = parse_resource(None)
    assert binding == UNKNOWN_RESOURCE
    assert binding.kind == "unknown"
    assert binding.values == ()


def test_request_global_resource_binds_the_whole_request() -> None:
    from openultrasast.semantic.obligations.abstract_domain import REQUEST_GLOBAL_RESOURCE

    assert REQUEST_GLOBAL_RESOURCE.kind == "request_global"
    assert REQUEST_GLOBAL_RESOURCE.values == ()


def test_resource_kinds_distinguish_exact_alias_global_and_unknown() -> None:
    # Req 2.7, 11.1: the four grades stay distinct; an unknown binding never collapses onto a concrete one.
    from openultrasast.semantic.obligations.abstract_domain import (
        REQUEST_GLOBAL_RESOURCE,
        UNKNOWN_RESOURCE,
        parse_resource,
    )

    grades = {parse_resource("book"), parse_resource(["book"]), REQUEST_GLOBAL_RESOURCE, UNKNOWN_RESOURCE}
    assert {resource.kind for resource in grades} == {"exact", "aliases", "request_global", "unknown"}


def test_alias_values_are_normalized_deterministically() -> None:
    from openultrasast.semantic.obligations.abstract_domain import ResourceRef

    forward = ResourceRef(kind="aliases", values=("volume", "book", "volume"))
    backward = ResourceRef(kind="aliases", values=("book", "volume"))
    assert forward == backward
    assert hash(forward) == hash(backward)
    assert len({forward, backward}) == 1


def test_resource_ref_fails_loud_on_misshapen_kinds_and_arities() -> None:
    from openultrasast.semantic.obligations.abstract_domain import ResourceRef

    with pytest.raises(ValueError, match="sometimes"):
        ResourceRef(kind="sometimes", values=("book",))
    with pytest.raises(ValueError, match="exact"):
        ResourceRef(kind="exact")
    with pytest.raises(ValueError, match="exact"):
        ResourceRef(kind="exact", values=("book", "volume"))
    with pytest.raises(ValueError, match="alias"):
        ResourceRef(kind="aliases", values=())
    with pytest.raises(ValueError, match="request_global"):
        ResourceRef(kind="request_global", values=("book",))


def test_parse_resource_rejects_misshapen_bindings() -> None:
    from openultrasast.semantic.obligations.abstract_domain import parse_resource

    with pytest.raises(ValueError):
        parse_resource("")
    with pytest.raises(ValueError):
        parse_resource(())
    with pytest.raises(ValueError):
        parse_resource(["book", ""])


def test_join_resources_keeps_identical_exact_tokens_exact() -> None:
    from openultrasast.semantic.obligations.abstract_domain import ResourceRef, join_resources

    binding = ResourceRef(kind="exact", values=("book",))
    assert join_resources(binding, ResourceRef(kind="exact", values=("book",))) == binding


def test_join_resources_merges_different_exact_tokens_into_an_alias_set() -> None:
    # Req 2.5: a different resource never collapses onto one exact binding; it widens to the finite alias set.
    from openultrasast.semantic.obligations.abstract_domain import ResourceRef, join_resources

    joined = join_resources(
        ResourceRef(kind="exact", values=("book",)),
        ResourceRef(kind="exact", values=("volume",)),
    )
    assert joined == ResourceRef(kind="aliases", values=("book", "volume"))


def test_join_resources_adds_exact_tokens_into_alias_sets() -> None:
    from openultrasast.semantic.obligations.abstract_domain import ResourceRef, join_resources

    joined = join_resources(
        ResourceRef(kind="exact", values=("shelf",)),
        ResourceRef(kind="aliases", values=("book", "volume")),
    )
    assert joined == ResourceRef(kind="aliases", values=("book", "shelf", "volume"))


def test_join_resources_unions_alias_sets_to_their_superset() -> None:
    from openultrasast.semantic.obligations.abstract_domain import ResourceRef, join_resources

    subset = ResourceRef(kind="aliases", values=("book",))
    superset = ResourceRef(kind="aliases", values=("book", "volume"))
    assert join_resources(subset, superset) == superset
    assert join_resources(superset, subset) == superset
    disjoint = join_resources(subset, ResourceRef(kind="aliases", values=("volume",)))
    assert disjoint == ResourceRef(kind="aliases", values=("book", "volume"))


def test_join_resources_request_global_absorbs_concrete_bindings() -> None:
    # Req 2.6: request-global scope already covers every resource in the request.
    from openultrasast.semantic.obligations.abstract_domain import (
        REQUEST_GLOBAL_RESOURCE,
        ResourceRef,
        join_resources,
    )

    for concrete in (
        ResourceRef(kind="exact", values=("book",)),
        ResourceRef(kind="aliases", values=("book", "volume")),
    ):
        assert join_resources(concrete, REQUEST_GLOBAL_RESOURCE) == REQUEST_GLOBAL_RESOURCE
        assert join_resources(REQUEST_GLOBAL_RESOURCE, concrete) == REQUEST_GLOBAL_RESOURCE
    assert join_resources(REQUEST_GLOBAL_RESOURCE, REQUEST_GLOBAL_RESOURCE) == REQUEST_GLOBAL_RESOURCE


def test_join_resources_unknown_absorbs_every_fixture() -> None:
    # Req 2.7, 11.1: an unresolvable binding stays unresolvable; joining cannot manufacture precision.
    from openultrasast.semantic.obligations.abstract_domain import UNKNOWN_RESOURCE, join_resources

    for other in _resource_fixtures():
        assert join_resources(other, UNKNOWN_RESOURCE) == UNKNOWN_RESOURCE, other
        assert join_resources(UNKNOWN_RESOURCE, other) == UNKNOWN_RESOURCE, other


def test_join_resources_is_commutative_and_idempotent_over_fixtures() -> None:
    from openultrasast.semantic.obligations.abstract_domain import join_resources

    fixtures = _resource_fixtures()
    for left, right in itertools.product(fixtures, repeat=2):
        assert join_resources(left, right) == join_resources(right, left), (left, right)
    for resource in fixtures:
        assert join_resources(resource, resource) == resource, resource


def test_operation_fact_declares_request_global_sufficient_kinds(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.facts import load_obligation_facts

    (tmp_path / "python.toml").write_text(_OPERATION_TOML)
    (row,) = load_obligation_facts(tmp_path).operations
    assert row.request_global_kinds == ("path_guard",)


def test_operation_fact_without_sufficiency_declares_none(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.facts import load_obligation_facts

    (tmp_path / "python.toml").write_text(_OPERATION_TOML.replace('request_global_kinds = ["path_guard"]\n', ""))
    (row,) = load_obligation_facts(tmp_path).operations
    assert row.request_global_kinds == ()


def test_operation_fact_rejects_unknown_request_global_kind(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.facts import ObligationFactsError, load_obligation_facts

    (tmp_path / "python.toml").write_text(_OPERATION_TOML.replace('["path_guard"]', '["vibes"]'))
    with pytest.raises(ObligationFactsError, match="vibes"):
        load_obligation_facts(tmp_path)
