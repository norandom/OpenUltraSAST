"""Bounded-lever edit model + validator for the self-improvement loop (tasks 7.1, 7.2).

The loop may only adjust governance *data* through two bounded levers and never the
two authorities a human/upstream owns: detection **pattern text** and the 0-5 CWE
**severity**. Edits are typed so pattern/severity changes are structurally
impossible; the validator additionally enforces status/bounds/staging/resolution.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from ..policy import CwePolicy
from ..ruleset import PatternRule
from ..ruleset.store import VALID_STATUS

# The only levers the loop may pull (mirrors the design's journal._VALID_LEVERS).
VALID_LEVERS = frozenset({"rule", "policy", "mechanisms"})
_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")
MECHANISM_ACTIONS = frozenset({"admit", "retract"})
# Policy constants the loop may tune; the 0-5 severity is intentionally absent.
TUNABLE_POLICY_CONSTANTS = frozenset({"K", "MIN_SCORE"})


class StrictValidationError(ValueError):
    """Raised when a proposed loop edit violates the bounded-lever contract."""

    def __init__(self, message: str, *, kind: str = "rule_change") -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class RuleStatusEdit:
    """A `rule`-lever edit: change a rule's status / evidence floor / precision estimate."""

    rule_id: str
    from_status: str
    to_status: str
    rationale: str = ""
    lever: str = "rule"

    def key(self) -> str:
        return f"rule:{self.rule_id}:{self.from_status}->{self.to_status}"


@dataclass(frozen=True)
class PolicyConstantEdit:
    """A `policy`-lever edit: tune a score constant (K / MIN_SCORE). Never severity."""

    name: str
    from_value: float
    to_value: float
    rationale: str = ""
    lever: str = "policy"

    def key(self) -> str:
        return f"policy:{self.name}:{self.from_value}->{self.to_value}"


@dataclass(frozen=True)
class MechanismEdit:
    """A `mechanisms`-lever edit (corpus-seeded-mechanisms Req 5): admit or retract one exporter record by id.

    The loop never writes a shape; it may only move a record the exporter derived from a trusted pair into or out of
    the scan-time store. Free text is confined to ``rationale``.
    """

    action: str  # admit | retract
    mechanism_id: str
    source: str = "loo"  # loo | export
    rationale: str = ""
    lever: str = "mechanisms"

    def key(self) -> str:
        return f"mechanisms:{self.action}:{self.mechanism_id}"


@dataclass(frozen=True)
class StoreSnapshot:
    """Bytes of the scan-time mechanism store before a round; ``restore`` is the byte-for-byte revert."""

    path: Path
    content: bytes | None  # None when the file did not exist

    def restore(self) -> None:
        if self.content is None:
            if self.path.exists():
                self.path.unlink()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(self.content)


@dataclass(frozen=True)
class EvolveBounds:
    k_range: tuple[float, float] = (20.0, 200.0)
    min_score_range: tuple[int, int] = (0, 100)


class EvolveValidator:
    """Enforces the bounded-lever safety contract; raises StrictValidationError on any breach."""

    def __init__(self, bounds: EvolveBounds | None = None) -> None:
        self._bounds = bounds or EvolveBounds()

    def validate(self, edit: object, ruleset_by_id: Mapping[str, PatternRule], policy: Mapping[str, CwePolicy]) -> None:
        if isinstance(edit, RuleStatusEdit):
            self._validate_rule(edit, ruleset_by_id, policy)
        elif isinstance(edit, PolicyConstantEdit):
            self._validate_policy(edit)
        elif isinstance(edit, MechanismEdit):
            raise StrictValidationError("mechanism edits need the exporter candidate set: use validate_mechanism", kind="mechanism_change")
        else:
            raise StrictValidationError(f"unknown edit type {type(edit).__name__}", kind="rule_change")

    def validate_mechanism(self, edit: MechanismEdit, candidates: Mapping[str, object]) -> None:
        """Req 5.2: only records the exporter derived from trusted pairs, with a closed guard and identifier-only shape text."""
        from ..semantic.variants import GUARD_KINDS, SOURCE_KINDS

        if edit.action not in MECHANISM_ACTIONS:
            raise StrictValidationError(f"mechanism edit action {edit.action!r} is not admit or retract", kind="mechanism_change")
        record = candidates.get(edit.mechanism_id)
        if record is None:
            raise StrictValidationError(
                f"unknown mechanism {edit.mechanism_id!r}: not in the exporter candidate set", kind="mechanism_change"
            )
        if getattr(record, "origin", "") != "corpus":
            raise StrictValidationError(
                f"{edit.mechanism_id}: origin {getattr(record, 'origin', '')!r} is not corpus (only exporter records)",
                kind="mechanism_change",
            )
        shape = getattr(record, "shape", None)
        if not isinstance(shape, dict):
            raise StrictValidationError(f"{edit.mechanism_id}: record carries no shape", kind="mechanism_change")
        if str(shape.get("guard")) not in GUARD_KINDS or str(getattr(record, "guard", "")) not in GUARD_KINDS:
            raise StrictValidationError(
                f"{edit.mechanism_id}: guard {shape.get('guard')!r} is not a closed guard kind", kind="mechanism_change"
            )
        for field_name in ("sink_name", "language", "mechanism"):
            value = str(shape.get(field_name, ""))
            if not _IDENTIFIER.match(value.replace("-", "_")):
                raise StrictValidationError(f"{edit.mechanism_id}: {field_name} {value!r} is not an identifier", kind="mechanism_change")
        kinds = shape.get("source_kinds") or []
        if not isinstance(kinds, list) or any(str(kind) not in SOURCE_KINDS for kind in kinds):
            raise StrictValidationError(f"{edit.mechanism_id}: source kinds {kinds!r} are not closed kinds", kind="mechanism_change")

    def _validate_rule(self, edit: RuleStatusEdit, ruleset_by_id: Mapping[str, PatternRule], policy: Mapping[str, CwePolicy]) -> None:
        if edit.to_status not in VALID_STATUS:
            raise StrictValidationError(f"invalid status {edit.to_status!r} for {edit.rule_id}")
        rule = ruleset_by_id.get(edit.rule_id)
        if rule is None:
            raise StrictValidationError(f"edit targets unknown rule_id {edit.rule_id!r} (loop cannot add rules)")
        if edit.from_status == "enabled" and edit.to_status == "disabled":
            raise StrictValidationError(f"{edit.rule_id}: enabled->disabled jump is forbidden; stage via shadow first")
        if rule.cwe not in policy:
            raise StrictValidationError(f"{edit.rule_id}: CWE {rule.cwe} does not resolve in the policy")

    def _validate_policy(self, edit: PolicyConstantEdit) -> None:
        if edit.name not in TUNABLE_POLICY_CONSTANTS:
            raise StrictValidationError(
                f"policy constant {edit.name!r} is not loop-tunable (severity is upstream-owned)", kind="policy_change"
            )
        if edit.name == "K" and not (self._bounds.k_range[0] <= edit.to_value <= self._bounds.k_range[1]):
            raise StrictValidationError(f"K={edit.to_value} out of bounds {self._bounds.k_range}", kind="policy_change")
        if edit.name == "MIN_SCORE" and not (self._bounds.min_score_range[0] <= edit.to_value <= self._bounds.min_score_range[1]):
            raise StrictValidationError(f"MIN_SCORE={edit.to_value} out of bounds {self._bounds.min_score_range}", kind="policy_change")


def apply_mechanism_edits(edits: Sequence[MechanismEdit], candidates: object, scan_store: Path) -> StoreSnapshot:
    """Apply admit/retract edits to the scan-time store; returns the snapshot whose ``restore`` reverts byte for byte.

    Admission appends the exporter record unchanged; retraction appends a tombstone row (``retracted = true``) so the
    log stays append-only and ``MechanismStore.load`` folds the record away.
    """
    snapshot = StoreSnapshot(path=scan_store, content=scan_store.read_bytes() if scan_store.exists() else None)
    by_id = {record.id: record for record in candidates.load()}  # type: ignore[attr-defined]
    scan_store.parent.mkdir(parents=True, exist_ok=True)
    with scan_store.open("a") as handle:
        for edit in edits:
            record = by_id[edit.mechanism_id]
            payload = asdict(record)
            if edit.action == "retract":
                payload["retracted"] = True
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return snapshot


def edits_to_ledger(edits: list[RuleStatusEdit], base: Mapping[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    """Overlay rule-status edits onto a copy of the base ledger."""
    ledger: dict[str, dict[str, object]] = {key: dict(value) for key, value in base.items()}
    for edit in edits:
        entry = dict(ledger.get(edit.rule_id, {}))
        entry["status"] = edit.to_status
        ledger[edit.rule_id] = entry
    return ledger


__all__ = [
    "EvolveBounds",
    "EvolveValidator",
    "MECHANISM_ACTIONS",
    "MechanismEdit",
    "StoreSnapshot",
    "apply_mechanism_edits",
    "PolicyConstantEdit",
    "RuleStatusEdit",
    "StrictValidationError",
    "TUNABLE_POLICY_CONSTANTS",
    "VALID_LEVERS",
    "edits_to_ledger",
]
