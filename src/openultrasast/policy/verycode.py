from __future__ import annotations

import csv
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

CWE_SCORE_TSV = Path(__file__).with_name("CWE_Score.tsv")


class PolicyError(ValueError):
    """Raised when an enabled rule references a CWE the policy does not govern."""


@dataclass(frozen=True)
class CwePolicy:
    """Authoritative governance for one CWE.

    ``severity`` (0-5) is upstream-governed and overrides any rule-local string.
    ``static`` gates SAST scope; ``dynamic``-only CWEs are report-only for a
    static tool and are never scored.
    """

    flaw_category: str
    severity: int
    static: bool
    dynamic: bool


def load_policy(tsv: Path = CWE_SCORE_TSV) -> dict[str, CwePolicy]:
    """Load the vendored CWE policy keyed by ``"CWE-NNN"``.

    The source TSV uses CRLF line endings and a ``"Flaw Severity "`` header with a
    trailing space, so columns are read positionally and every cell is stripped.
    """
    policy: dict[str, CwePolicy] = {}
    with tsv.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle, delimiter="\t")
        rows = list(reader)
    for row in rows[1:]:
        if len(row) < 5:
            continue
        cwe_id = row[1].strip()
        if not cwe_id.isdigit():
            continue
        severity = _parse_severity(row[3])
        policy[f"CWE-{cwe_id}"] = CwePolicy(
            flaw_category=row[0].strip(),
            severity=severity,
            static=_flag(row[4]),
            dynamic=_flag(row[5]) if len(row) > 5 else False,
        )
    return policy


def resolve_severity(
    policy: Mapping[str, CwePolicy],
    cwe: str,
    target: object = None,
    ranking: object = None,
) -> int:
    """Resolve a finding's severity exclusively from policy, keyed on its CWE.

    Policy always wins; any legacy rule-local severity string is discarded. An
    unmapped or non-static CWE resolves to 0 (report-only, not scored).
    """
    pol = policy.get(cwe)
    if pol is None or not pol.static:
        return 0
    return pol.severity


def assert_rules_resolve(rules: Iterable[object], policy: Mapping[str, CwePolicy]) -> None:
    """Fail loud if any enabled rule's CWE is unmapped in the policy.

    Rules expose ``cwe`` and (optionally) ``status``; only ``enabled`` rules are
    checked. Raises :class:`PolicyError` before any scan work proceeds.
    """
    unmapped: list[str] = []
    for rule in rules:
        if getattr(rule, "status", "enabled") != "enabled":
            continue
        cwe = getattr(rule, "cwe", None)
        if not isinstance(cwe, str) or cwe not in policy:
            rule_id = getattr(rule, "rule_id", "<unknown>")
            unmapped.append(f"{rule_id} -> {cwe}")
    if unmapped:
        raise PolicyError("enabled rules reference CWEs absent from the policy: " + ", ".join(sorted(unmapped)))


def _parse_severity(value: str) -> int:
    try:
        severity = int(value.strip())
    except ValueError:
        return 0
    return min(5, max(0, severity))


def _flag(value: str) -> bool:
    return value.strip().upper() == "X"
