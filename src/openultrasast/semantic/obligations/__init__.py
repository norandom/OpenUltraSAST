"""Absence bugs as obligations (authorization-obligations spec).

An operation carries an obligation (a protected read or write, a privileged action, a security-relevant setting) that
must be discharged on the way to it (a path guard, an identity constraint bound from the authenticated context, an
ownership check, a non-permissive value, validated input). Facts are closed data; shapes are learned from trusted pairs;
findings never claim a proof rung.
"""

from .facts import (
    DISCHARGER_KINDS,
    OPERATION_KINDS,
    PROVENANCE_KINDS,
    DischargerFact,
    ObligationFacts,
    ObligationFactsError,
    OperationFact,
    load_obligation_facts,
)

__all__ = [
    "DISCHARGER_KINDS",
    "OPERATION_KINDS",
    "PROVENANCE_KINDS",
    "DischargerFact",
    "ObligationFacts",
    "ObligationFactsError",
    "OperationFact",
    "load_obligation_facts",
]
