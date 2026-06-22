from types import SimpleNamespace

import pytest

from openultrasast.findings import PATTERN_RULES
from openultrasast.policy import (
    CwePolicy,
    PolicyError,
    assert_rules_resolve,
    load_policy,
    resolve_severity,
)


def test_load_policy_parses_severity_and_scope() -> None:
    policy = load_policy()

    assert policy["CWE-121"] == CwePolicy("Buffer Overflow", 5, True, False)
    assert policy["CWE-89"].severity == 4
    assert policy["CWE-78"].static is True
    assert len(policy) > 150  # ~167 CWEs vendored from verycode-policies


def test_resolve_severity_is_policy_governed_and_identical_for_same_cwe() -> None:
    policy = load_policy()

    # Two different rules that map to the same CWE must get the same severity.
    assert resolve_severity(policy, "CWE-78") == resolve_severity(policy, "CWE-78") == 5
    # Unmapped CWE resolves to 0 (report-only, never scored).
    assert resolve_severity(policy, "CWE-99999") == 0


def test_builtin_rules_all_resolve_in_policy() -> None:
    # The fail-loud invariant must pass for the shipped ruleset (CWE-120 remapped to CWE-121).
    assert_rules_resolve(PATTERN_RULES, load_policy())


def test_assert_rules_resolve_fails_loud_on_unmapped_enabled_rule() -> None:
    policy = load_policy()
    bad_enabled = SimpleNamespace(rule_id="bad", cwe="CWE-99999", status="enabled")
    bad_disabled = SimpleNamespace(rule_id="bad-off", cwe="CWE-99999", status="disabled")

    with pytest.raises(PolicyError, match="bad"):
        assert_rules_resolve([bad_enabled], policy)

    # A disabled rule with an unmapped CWE does not abort the scan.
    assert_rules_resolve([bad_disabled], policy)
