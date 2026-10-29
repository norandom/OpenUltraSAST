"""Closed obligation facts: which operations carry an obligation and what discharges it (Req 1).

Facts live in ``ruleset/obligations/<language>.toml``, beside (never inside) the flow facts directory, so
``semantic.facts.load_facts`` never sees them. Every kind is checked against a closed set; an unknown kind or field is a
data bug and fails loud. Nothing detects an obligation that is not named here.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from ...source import canonical_language
from ..facts import _ruleset_state
from .abstract_domain import AuthorityImplication

OPERATION_KINDS = ("protected_read", "protected_write", "privileged_action", "security_setting")
DISCHARGER_KINDS = ("path_guard", "identity_constraint", "ownership_check", "non_permissive_value", "validated_input")
PROVENANCE_KINDS = ("authenticated_context", "request_input", "constant", "unknown")
SENSITIVITIES = ("low", "medium", "high")
DEFAULT_OBLIGATION_FACTS_DIR = Path(__file__).resolve().parents[2] / "ruleset" / "obligations"

_OPERATION_FIELDS = frozenset(
    {
        "id",
        "kind",
        "calls",
        "resource_arg",
        "requires",
        "sensitivity",
        "query_document_arg",
        "handlers",
        "framework",
        "request_global_kinds",
    }
)
_DISCHARGER_FIELDS = frozenset(
    {"id", "kind", "calls", "decorators", "identity_sources", "constraint_params", "request_sources", "permissive_values"}
)
_IMPLICATION_FIELDS = frozenset({"id", "authority", "implies"})


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
    # A call whose NAME is shared with something ordinary, obligated only in the argument shape of a data
    # operation. `find` is the commonest collection read there is and also `Array.prototype.find` and jQuery's
    # `.find`, so the name alone cannot carry the obligation: measured on one plugin's assets, 83 of 88 `find`
    # calls were a selector or a predicate. The position is 1-based over the real arguments; the arbiter that
    # can see argument shapes decides it, and a language whose calls are unambiguous never sets this.
    query_document_arg: int | None = None
    handlers: tuple[str, ...] = ()
    framework: str | None = None
    # Requirement 2.6 (access-control-prover): discharger kinds a request-global witness may discharge for
    # this operation at request scope, without resource equality. Declared by the fact, never inferred.
    request_global_kinds: tuple[str, ...] = ()


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
class ImplicationFact(AuthorityImplication):
    """One promoted ``[[implication]]`` row: ``authority`` also covers ``implies`` (Req 2.8).

    Extends the abstract domain's ``AuthorityImplication`` with the loader's language scope, so loaded
    facts feed ``authority_satisfies`` directly while filtering per language like every other fact row.
    """

    language: str = ""


@dataclass(frozen=True)
class ObligationFacts:
    version: str
    operations: tuple[OperationFact, ...]
    dischargers: tuple[DischargerFact, ...]
    # Requirement 2.8 (access-control-prover): promoted authority implications, each retaining the
    # supporting fact row id so the trace can name the implication used. Default-empty; older data loads unchanged.
    implications: tuple[ImplicationFact, ...] = ()

    def for_language(self, language: str) -> ObligationFacts:
        key = canonical_language(language)
        if key == "cpp":
            key = "c"
        return ObligationFacts(
            version=self.version,
            operations=tuple(item for item in self.operations if item.language == key),
            dischargers=tuple(item for item in self.dischargers if item.language == key),
            implications=tuple(item for item in self.implications if item.language == key),
        )


def _load_obligation_facts_uncached(directory: Path | None = None) -> ObligationFacts:
    root = directory if directory is not None else DEFAULT_OBLIGATION_FACTS_DIR
    if not root.is_dir():
        raise ObligationFactsError(f"obligation facts directory missing: {root}")
    operations: list[OperationFact] = []
    dischargers: list[DischargerFact] = []
    implications: list[ImplicationFact] = []
    versions: list[str] = []
    for path in sorted(root.glob("*.toml")):
        try:
            payload = tomllib.loads(path.read_text())
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ObligationFactsError(f"invalid obligation facts file {path}: {exc}") from exc
        language = str(payload.get("language") or path.stem)
        versions.append(str(payload.get("version", "1")))
        for row in _rows(payload.get("operation"), path):
            operations.append(_operation_fact(row, path, language))
        for row in _rows(payload.get("implication"), path):
            implications.append(_implication_fact(row, path, language))
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
    return ObligationFacts(
        version=versions[0] if versions else "1",
        operations=tuple(operations),
        dischargers=tuple(dischargers),
        implications=tuple(implications),
    )


def _operation_fact(row: dict[str, object], path: Path, language: str) -> OperationFact:
    """Validate one operation row against the closed sets and parse it; any unknown kind or field fails loud."""
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
    request_global_kinds = _strings(row.get("request_global_kinds"), "request_global_kinds", path)
    for item in request_global_kinds:
        if item not in DISCHARGER_KINDS:
            raise ObligationFactsError(f"{path}: operation {row.get('id')!r} request_global_kinds names unknown discharger kind {item!r}")
    handler_patterns, handler_framework = _handler_shape(row, path)
    return OperationFact(
        id=str(row["id"]),
        kind=kind,
        language=language,
        calls=_strings(row.get("calls"), "calls", path),
        resource_arg=_optional_int(row, "resource_arg", path, positive=False),
        requires=requires,
        sensitivity=sensitivity,
        query_document_arg=_optional_int(row, "query_document_arg", path, positive=True),
        handlers=handler_patterns,
        framework=handler_framework,
        request_global_kinds=request_global_kinds,
    )


def _implication_fact(row: dict[str, object], path: Path, language: str) -> ImplicationFact:
    """Validate one implication row against the closed fields; both names must be non-empty strings."""
    _only_fields(row, _IMPLICATION_FIELDS, path)
    return ImplicationFact(
        id=str(row["id"]),
        authority=_implication_name(row, "authority", path),
        implies=_implication_name(row, "implies", path),
        language=language,
    )


def _implication_name(row: dict[str, object], field: str, path: Path) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value:
        raise ObligationFactsError(f"{path}: implication {row.get('id')!r} needs a non-empty {field}")
    return value


def _optional_int(row: dict[str, object], field: str, path: Path, *, positive: bool) -> int | None:
    value = row.get(field)
    if value is None:
        return None
    if not isinstance(value, int) or (positive and value < 1):
        requirement = "a positive integer" if positive else "an integer"
        raise ObligationFactsError(f"{path}: operation {row.get('id')!r} {field} must be {requirement}")
    return value


def _handler_shape(row: dict[str, object], path: Path) -> tuple[tuple[str, ...], str | None]:
    handler_patterns = _strings(row.get("handlers"), "handlers", path)
    framework = row.get("framework")
    if framework is not None and (not isinstance(framework, str) or not framework):
        raise ObligationFactsError("invalid operation framework")
    if handler_patterns and framework is None:
        raise ObligationFactsError("handler operation needs a framework")
    for pattern in handler_patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ObligationFactsError(type(exc).__name__) from exc
    return handler_patterns, framework


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


# Parsed once per ruleset state; see `semantic.facts.load_facts` for the measurement and the key.
_OBLIGATION_MEMO: dict[tuple[object, ...], ObligationFacts] = {}


def load_obligation_facts(directory: Path | None = None) -> ObligationFacts:
    root = directory if directory is not None else DEFAULT_OBLIGATION_FACTS_DIR
    if not root.is_dir():
        return _load_obligation_facts_uncached(directory)
    key = _ruleset_state(root, "*.toml")
    if key not in _OBLIGATION_MEMO:
        _OBLIGATION_MEMO[key] = _load_obligation_facts_uncached(directory)
    return _OBLIGATION_MEMO[key]
