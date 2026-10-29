"""Witness kind, scope, resource and authority matching (tasks 10.2-10.3, Reqs 2.1, 2.2, 2.5-2.8, 11.1).

A witness governs an obligation only when every required dimension is MUST. This module
matches the kind, scope, resource and authority dimensions; dominance (task 10.1) joins
through the same algebra. Definite mismatches are NO, unresolved compatibility is UNKNOWN
(never a broad match, never a definite rejection), per Req 2.7. Authority implications come
only from promoted knowledge and their fact identifiers are preserved as evidence (Req 2.8).
"""

from .abstract_domain import (
    AuthorityImplication,
    AuthorityRef,
    EvidenceRelation,
    ResourceRef,
    WitnessMatch,
    authority_satisfies,
    conjoin_dimensions,
    parse_resource,
    supporting_implications,
)
from .facts import OperationFact
from .operations import Discharge, Operation

_WHOLE_HANDLER_SCOPES = frozenset({"decorator", "router"})


def match_witness(
    witness: Discharge,
    operation: Operation,
    fact: OperationFact | None = None,
    *,
    required_authority: AuthorityRef | None = None,
    implications: tuple[AuthorityImplication, ...] = (),
) -> WitnessMatch:
    """Match one witness against one operation on kind, scope, resource and authority."""
    if witness.kind not in operation.requires:
        return _match(EvidenceRelation.NO, EvidenceRelation.NO, EvidenceRelation.UNKNOWN, witness, operation, ())
    if _out_of_scope(witness, operation):
        return _match(EvidenceRelation.NO, EvidenceRelation.NO, EvidenceRelation.UNKNOWN, witness, operation, ())
    resource_relation = _resource_relation(witness, operation, fact)
    authority_relation, implication_ids = _authority_relation(witness, required_authority, implications)
    relation = conjoin_dimensions(
        (EvidenceRelation.MUST, resource_relation, authority_relation),
    )
    return _match(relation, resource_relation, authority_relation, witness, operation, implication_ids)


def _out_of_scope(witness: Discharge, operation: Operation) -> bool:
    same_function = (witness.path, witness.function) == (operation.path, operation.function)
    if witness.scope in _WHOLE_HANDLER_SCOPES:
        return not same_function
    if witness.scope == "hop":
        return False
    return not same_function


def _resource_relation(witness: Discharge, operation: Operation, fact: OperationFact | None) -> EvidenceRelation:
    witness_resource = witness.resource
    if witness_resource is None:
        return EvidenceRelation.UNKNOWN
    if witness_resource.kind == "request_global":
        if fact is not None and witness.kind in fact.request_global_kinds:
            return EvidenceRelation.MUST
        return EvidenceRelation.UNKNOWN
    operation_resource = parse_resource(operation.resource)
    if operation_resource.kind == "unknown":
        return EvidenceRelation.UNKNOWN
    if witness_resource.kind == "unknown":
        return EvidenceRelation.UNKNOWN
    if witness_resource.kind == "exact":
        return _exact_relation(witness_resource, operation_resource)
    return _alias_relation(witness_resource, operation_resource)


def _exact_relation(witness_resource: ResourceRef, operation_resource: ResourceRef) -> EvidenceRelation:
    if operation_resource.kind == "exact":
        if witness_resource.values == operation_resource.values:
            return EvidenceRelation.MUST
        return EvidenceRelation.NO
    return _alias_relation(witness_resource, operation_resource)


def _alias_relation(witness_resource: ResourceRef, operation_resource: ResourceRef) -> EvidenceRelation:
    if set(witness_resource.values) & set(operation_resource.values):
        return EvidenceRelation.MAY
    if witness_resource.kind == "exact" and operation_resource.kind == "exact":
        return EvidenceRelation.NO
    return EvidenceRelation.UNKNOWN


def _authority_relation(
    witness: Discharge,
    required_authority: AuthorityRef | None,
    implications: tuple[AuthorityImplication, ...],
) -> tuple[EvidenceRelation, tuple[str, ...]]:
    """Decide the authority dimension (Req 2.5-2.8); preserve implication fact ids."""
    if required_authority is None:
        return EvidenceRelation.MUST, ()
    held_authority = witness.authority
    if held_authority is None or held_authority.is_unknown or required_authority.is_unknown:
        return EvidenceRelation.UNKNOWN, ()
    relation = authority_satisfies(held_authority, required_authority, implications)
    used_ids = tuple(
        f"implication:{implication.id}" for implication in supporting_implications(held_authority, required_authority, implications)
    )
    return relation, used_ids


def _match(
    relation: EvidenceRelation,
    resource_relation: EvidenceRelation,
    authority_relation: EvidenceRelation,
    witness: Discharge,
    operation: Operation,
    implication_ids: tuple[str, ...],
) -> WitnessMatch:
    evidence = (
        f"witness:{witness.fact_id}",
        f"operation:{operation.fact_id}",
        f"resource:{operation.resource or 'unknown'}",
        *implication_ids,
    )
    return WitnessMatch(
        relation=relation,
        resource_relation=resource_relation,
        authority_relation=authority_relation,
        evidence=evidence,
    )
