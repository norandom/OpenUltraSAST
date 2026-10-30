"""Detection core: the shared security-trace contract package.

Owns contracts only -- no analysis logic. Arms implement the trace contract;
runners and consumers adopt coverage, budget, provenance, and admission contracts.
"""

from openultrasast.core.budget import Budget, BudgetGateFailure, Complexity, check_budget, derive_budget
from openultrasast.core.coverage import Coverage, InstrumentFailure, ResolutionOutcome, check_reads
from openultrasast.core.provenance import ProvenanceMismatch, stamp, verify_stamp
from openultrasast.core.trace import Guard, Hop, TraceRecord, Witness
from openultrasast.core.verdict import BoundedSilence, Judgment, ProvenClaim, as_clean

__all__ = [
    "BoundedSilence",
    "Budget",
    "BudgetGateFailure",
    "Complexity",
    "Coverage",
    "Guard",
    "Hop",
    "InstrumentFailure",
    "Judgment",
    "ProvenClaim",
    "ProvenanceMismatch",
    "ResolutionOutcome",
    "TraceRecord",
    "Witness",
    "as_clean",
    "check_budget",
    "check_reads",
    "derive_budget",
    "stamp",
    "verify_stamp",
]
