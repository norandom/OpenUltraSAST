"""The declared advisory scope of the pre-push safety net (task 15.2): one packaged record.

``advisory-scope.json`` names the families whose claims are intended to be admitted as alerts and every
family that is not, with the reason and what a contributor is therefore not told. Like the eligibility
registry it is a shipped release input: never repository configuration, never a model response. The
scope is provisional until the M4 evaluation qualifies a capability, so the rendered line states that
limit instead of letting a listed family read as checked and found fine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from openultrasast.model.taxonomy import FAMILY_IDS

_DEFAULT = Path(__file__).with_name("advisory-scope.json")
_LIMIT = 64 * 1024
_SCHEMA_VERSION = 1
_TOP_KEYS = frozenset({"schema_version", "status", "basis", "scope", "exclusions"})
_ENTRY_KEYS = frozenset({"family", "label", "reason"})
_EXCLUSION_KEYS = _ENTRY_KEYS | {"not_told"}
# Families come from the closed vocabulary and are unique, so labels of this size keep the line bounded.
_MAX_LABEL = 48
_UNAVAILABLE = "advisory_scope_invalid_or_unavailable"
_PROVISIONAL_LINE = (
    "Scope: provisional, not yet in effect: no family is qualified for alerts yet. "
    "Intended v1 advisory scope: {scope}. "
    "Not reported as defects: {excluded}, or any other family outside the scope. "
    "Listing a family does not mean the repository was found free of defects in it."
)
_UNKNOWN_LINE = (
    "Scope: unknown. The shipped scope record could not be read, so which families this tool can and cannot "
    "report is unknown; that missing limit is itself a limit of this run."
)


@dataclass(frozen=True)
class FamilyScope:
    """One family of the record: intended for admission, or excluded from it with what is not told."""

    family: str
    label: str
    reason: str
    not_told: str | None = None

    def to_payload(self) -> dict[str, str]:
        payload = {"family": self.family, "label": self.label, "reason": self.reason}
        if self.not_told is not None:
            payload["not_told"] = self.not_told
        return payload


@dataclass(frozen=True)
class AdvisoryScope:
    """A validated provisional scope, or the closed `unavailable` result with one reason code."""

    status: str
    basis: str = ""
    scope: tuple[FamilyScope, ...] = ()
    exclusions: tuple[FamilyScope, ...] = ()
    reason: str = ""

    def to_payload(self) -> dict[str, object]:
        """The artifact field: the record itself, or the unavailable status with its reason."""
        if self.status != "provisional":
            return {"status": self.status, "reason": self.reason}
        return {
            "schema_version": _SCHEMA_VERSION,
            "status": self.status,
            "basis": self.basis,
            "scope": [entry.to_payload() for entry in self.scope],
            "exclusions": [entry.to_payload() for entry in self.exclusions],
        }

    def render(self) -> str:
        """The one limit line for the terminal: fixed phrases and the record's labels, nothing else."""
        if self.status != "provisional":
            # Anything but a validated provisional record leaves the limits unknown; never a claim.
            return _UNKNOWN_LINE
        return _PROVISIONAL_LINE.format(scope=_labels(self.scope), excluded=_labels(self.exclusions))


def _labels(entries: tuple[FamilyScope, ...]) -> str:
    return ", ".join(entry.label for entry in entries)


def _text(value: object, *, limit: int | None = None) -> str:
    # Exact type and printable ASCII: a bool is not a name, and no control character can add a line or an escape.
    if type(value) is not str or not value.strip() or not value.isascii() or not value.isprintable():
        raise ValueError("advisory_scope_text_invalid")
    if limit is not None and len(value) > limit:
        raise ValueError("advisory_scope_label_too_long")
    return value


def _entry(raw: object, *, excluded: bool) -> FamilyScope:
    if type(raw) is not dict or set(raw) != (_EXCLUSION_KEYS if excluded else _ENTRY_KEYS):
        raise ValueError("advisory_scope_entry_invalid")
    family = _text(raw["family"], limit=_MAX_LABEL)
    if family not in FAMILY_IDS:
        raise ValueError("advisory_scope_family_unknown")
    return FamilyScope(
        family,
        _text(raw["label"], limit=_MAX_LABEL),
        _text(raw["reason"]),
        _text(raw["not_told"]) if excluded else None,
    )


def _validate(data: object) -> AdvisoryScope:
    if type(data) is not dict or set(data) != _TOP_KEYS:
        raise ValueError("advisory_scope_shape_invalid")
    version, status, scope, exclusions = (data[key] for key in ("schema_version", "status", "scope", "exclusions"))
    if type(version) is not int or version != _SCHEMA_VERSION or status != "provisional":
        raise ValueError("advisory_scope_version_or_status_unsupported")
    if type(scope) is not list or type(exclusions) is not list or not scope or not exclusions:
        raise ValueError("advisory_scope_families_invalid")
    intended = tuple(_entry(item, excluded=False) for item in scope)
    leave_out = tuple(_entry(item, excluded=True) for item in exclusions)
    families = [entry.family for entry in (*intended, *leave_out)]
    if len(set(families)) != len(families):
        # One rule for a family named twice and for one listed on both sides: the sides stay disjoint.
        raise ValueError("advisory_scope_family_repeated")
    return AdvisoryScope("provisional", _text(data["basis"]), intended, leave_out)


def load_advisory_scope(path: Path | None = None) -> AdvisoryScope:
    """The shipped scope record, or a closed `unavailable` scope: this never raises into the hook."""
    try:
        with (path or _DEFAULT).open("rb") as stream:
            content = stream.read(_LIMIT + 1)
        if len(content) > _LIMIT:
            raise ValueError("advisory_scope_size_limit")
        return _validate(json.loads(content))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return AdvisoryScope("unavailable", reason=_UNAVAILABLE)
