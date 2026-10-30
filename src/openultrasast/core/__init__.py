"""Detection core: the shared security-trace contract package.

Owns contracts only -- no analysis logic. Arms implement the trace contract;
runners and consumers adopt coverage, budget, provenance, and admission contracts.
"""

from openultrasast.core.admission import (
    REPORT_SCHEMA_KEYS,
    AdmissionManifest,
    AdmissionManifestError,
    validate_admission_manifest,
    validate_report_schema,
)
from openultrasast.core.budget import Budget, BudgetGateFailure, Complexity, check_budget, derive_budget
from openultrasast.core.consumer import PushRequest, PushVerdict, consume_verdict
from openultrasast.core.coverage import Coverage, InstrumentFailure, ResolutionOutcome, check_reads
from openultrasast.core.factpack import FactPack, FactPackError, admit_fact_pack, verify_fact_pack
from openultrasast.core.probes import (
    FittedComponentBlocked,
    ProbeResult,
    ShortcutDetected,
    assert_no_shortcut,
    require_admission_evidence,
    reversed_pair_probe,
)
from openultrasast.core.provenance import ProvenanceMismatch, stamp, verify_stamp
from openultrasast.core.trace import Guard, Hop, TraceRecord, Witness
from openultrasast.core.verdict import BoundedSilence, Judgment, ProvenClaim, as_clean

__all__ = [
    "REPORT_SCHEMA_KEYS",
    "AdmissionManifest",
    "AdmissionManifestError",
    "BoundedSilence",
    "Budget",
    "BudgetGateFailure",
    "Complexity",
    "Coverage",
    "FactPack",
    "FactPackError",
    "FittedComponentBlocked",
    "Guard",
    "Hop",
    "InstrumentFailure",
    "Judgment",
    "ProbeResult",
    "ProvenClaim",
    "ProvenanceMismatch",
    "PushRequest",
    "PushVerdict",
    "ResolutionOutcome",
    "ShortcutDetected",
    "TraceRecord",
    "Witness",
    "admit_fact_pack",
    "as_clean",
    "assert_no_shortcut",
    "check_budget",
    "check_reads",
    "consume_verdict",
    "derive_budget",
    "require_admission_evidence",
    "reversed_pair_probe",
    "stamp",
    "validate_admission_manifest",
    "validate_report_schema",
    "verify_fact_pack",
    "verify_stamp",
]
