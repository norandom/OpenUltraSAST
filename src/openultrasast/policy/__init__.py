"""Central CWE severity/scope policy (vendored verycode-policies)."""

from .verycode import (
    CWE_SCORE_TSV,
    CwePolicy,
    PolicyError,
    assert_rules_resolve,
    load_policy,
    resolve_severity,
)

__all__ = [
    "CWE_SCORE_TSV",
    "CwePolicy",
    "PolicyError",
    "assert_rules_resolve",
    "load_policy",
    "resolve_severity",
]
