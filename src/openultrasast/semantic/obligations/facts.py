"""Closed obligation facts: which operations carry an obligation and what discharges it (Req 1).

Facts live in ``ruleset/obligations/<language>.toml``, beside (never inside) the flow facts directory, so
``semantic.facts.load_facts`` never sees them. Every kind is checked against a closed set; an unknown kind or field is a
data bug and fails loud. Nothing detects an obligation that is not named here.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

OPERATION_KINDS = ("protected_read", "protected_write", "privileged_action", "security_setting")
DISCHARGER_KINDS = ("path_guard", "identity_constraint", "ownership_check", "non_permissive_value", "validated_input")
PROVENANCE_KINDS = ("authenticated_context", "request_input", "constant", "unknown")
SENSITIVITIES = ("low", "medium", "high")
DEFAULT_OBLIGATION_FACTS_DIR = Path(__file__).resolve().parents[2] / "ruleset" / "obligations"
_LANGUAGE_ALIASES = {"c_cpp": "c", "cpp": "c", "python_web": "python", "node": "javascript", "ts": "typescript"}

_OPERATION_FIELDS = frozenset({"id", "kind", "calls", "resource_arg", "requires", "sensitivity"})
_DISCHARGER_FIELDS = frozenset(
    {"id", "kind", "calls", "decorators", "identity_sources", "constraint_params", "request_sources", "permissive_values"}
)


class ObligationFactsError(ValueError):
    """Raised when an obligation facts file names a kind or a field outside the closed sets."""


@dataclass(frozen=True)
class OperationFact:
    id: str
    kind: str  # OPERATION_KINDS
    language: str
    calls: tuple[str, ...]  # trailing-name matches, same rule as sink facts
    resource_arg: int | None  # argument or receiver position naming the resource (model, table, path); None = receiver
    requires: tuple[str, ...]  # DISCHARGER_KINDS that discharge this operation
    sensitivity: str  # SENSITIVITIES


@dataclass(frozen=True)
class DischargerFact:
    id: str
    kind: str  # DISCHARGER_KINDS
    language: str
    calls: tuple[str, ...] = ()  # guard calls, validators, setters
    decorators: tuple[str, ...] = ()  # decorator names that guard a whole handler
    identity_sources: tuple[str, ...] = ()  # text patterns whose value comes from the authenticated context
    constraint_params: tuple[str, ...] = ()  # keyword or field names that constrain an operation by identity
    request_sources: tuple[str, ...] = ()  # text patterns whose value comes from the request (identity that discharges nothing)
    permissive_values: tuple[str, ...] = ()  # literal values that leave a security setting open (non_permissive_value facts)


@dataclass(frozen=True)
class ObligationFacts:
    version: str
    operations: tuple[OperationFact, ...]
    dischargers: tuple[DischargerFact, ...]

    def for_language(self, language: str) -> ObligationFacts:
        key = _LANGUAGE_ALIASES.get(language, language)
        return ObligationFacts(
            version=self.version,
            operations=tuple(item for item in self.operations if item.language == key),
            dischargers=tuple(item for item in self.dischargers if item.language == key),
        )


def load_obligation_facts(directory: Path | None = None) -> ObligationFacts:
    root = directory if directory is not None else DEFAULT_OBLIGATION_FACTS_DIR
    if not root.is_dir():
        raise ObligationFactsError(f"obligation facts directory missing: {root}")
    operations: list[OperationFact] = []
    dischargers: list[DischargerFact] = []
    versions: list[str] = []
    for path in sorted(root.glob("*.toml")):
        try:
            payload = tomllib.loads(path.read_text())
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ObligationFactsError(f"invalid obligation facts file {path}: {exc}") from exc
        language = str(payload.get("language") or path.stem)
        versions.append(str(payload.get("version", "1")))
        for row in _rows(payload.get("operation"), path):
            _only_fields(row, _OPERATION_FIELDS, path)
            kind = str(row.get("kind", ""))
            if kind not in OPERATION_KINDS:
                raise ObligationFactsError(f"{path}: operation {row.get('id')!r} has unknown kind {kind!r}")
            requires = _strings(row.get("requires"), "requires", path)
            for item in requires:
                if item not in DISCHARGER_KINDS:
                    raise ObligationFactsError(f"{path}: operation {row.get('id')!r} requires unknown discharger kind {item!r}")
            sensitivity = str(row.get("sensitivity", "medium"))
            if sensitivity not in SENSITIVITIES:
                raise ObligationFactsError(f"{path}: operation {row.get('id')!r} has unknown sensitivity {sensitivity!r}")
            resource_arg = row.get("resource_arg")
            if resource_arg is not None and not isinstance(resource_arg, int):
                raise ObligationFactsError(f"{path}: operation {row.get('id')!r} resource_arg must be an integer")
            operations.append(
                OperationFact(
                    id=str(row["id"]),
                    kind=kind,
                    language=language,
                    calls=_strings(row.get("calls"), "calls", path),
                    resource_arg=resource_arg,
                    requires=requires,
                    sensitivity=sensitivity,
                )
            )
        for row in _rows(payload.get("discharger"), path):
            _only_fields(row, _DISCHARGER_FIELDS, path)
            kind = str(row.get("kind", ""))
            if kind not in DISCHARGER_KINDS:
                raise ObligationFactsError(f"{path}: discharger {row.get('id')!r} has unknown kind {kind!r}")
            dischargers.append(
                DischargerFact(
                    id=str(row["id"]),
                    kind=kind,
                    language=language,
                    calls=_strings(row.get("calls"), "calls", path),
                    decorators=_strings(row.get("decorators"), "decorators", path),
                    identity_sources=_strings(row.get("identity_sources"), "identity_sources", path),
                    constraint_params=_strings(row.get("constraint_params"), "constraint_params", path),
                    request_sources=_strings(row.get("request_sources"), "request_sources", path),
                    permissive_values=_strings(row.get("permissive_values"), "permissive_values", path),
                )
            )
    return ObligationFacts(version=versions[0] if versions else "1", operations=tuple(operations), dischargers=tuple(dischargers))


def _rows(value: object, path: Path) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ObligationFactsError(f"{path}: fact tables must be arrays of tables")
    return [dict(item) for item in value]


def _only_fields(row: dict[str, object], allowed: frozenset[str], path: Path) -> None:
    extra = sorted(set(row) - allowed)
    if extra:
        raise ObligationFactsError(f"{path}: row {row.get('id')!r} has unknown field {extra[0]!r}")
    if "id" not in row:
        raise ObligationFactsError(f"{path}: every fact row needs an id")


def _strings(value: object, field: str, path: Path) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ObligationFactsError(f"{path} has invalid {field} list")
    return tuple(str(item) for item in value)
