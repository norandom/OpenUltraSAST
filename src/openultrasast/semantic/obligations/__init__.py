"""Absence bugs as obligations (authorization-obligations spec).

An operation carries an obligation (a protected read or write, a privileged action, a security-relevant setting) that
must be discharged on the way to it (a path guard, an identity constraint bound from the authenticated context, an
ownership check, a non-permissive value, validated input). Facts are closed data; shapes are learned from trusted pairs;
findings never claim a proof rung.
"""

from .check import ObligationFinding, ObligationResult, check_obligations, findings_to_static
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
from .shapes import ObligationShape, derive_obligation, explain_skip, obligation_mechanisms

__all__ = [
    "DISCHARGER_KINDS",
    "OPERATION_KINDS",
    "PROVENANCE_KINDS",
    "DischargerFact",
    "ObligationFacts",
    "ObligationFactsError",
    "ObligationFinding",
    "ObligationResult",
    "ObligationShape",
    "OperationFact",
    "check_obligations",
    "derive_obligation",
    "explain_skip",
    "findings_to_static",
    "load_obligation_facts",
    "obligation_mechanisms",
]
