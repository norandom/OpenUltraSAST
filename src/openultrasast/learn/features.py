"""Feature records per candidate, from the signals every instrument emitted (learned-decision-engine design section 1).

The plane task ``features`` (:mod:`..plane.tasks.features`) reads a case's delivered artifacts.

A candidate is ``(path, function, family)`` of one repository and pin: a function where at least one instrument
emitted a signal of that family. The key stays in the record's envelope (``candidate`` is ``path::function``); the
features never see it (:mod:`.schema`). Each instrument contributes a :class:`Part` -- its state, its values and its
version -- and :func:`record` assembles and validates the record: an instrument that did not run leaves ``null``,
never a zero.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..model.taxonomy import load_families
from ..preprocess import build_file_target, detect_language
from ..ruleset import PatternRule
from ..source import _COMMENT_PREFIXES, DECLARATION, MODULE_FUNCTION, _declared_name, function_span
from ..source import enclosing_at as enclosing
from ..source import product_paths as product_files
from .roles import CWE_OPERATION, SOURCE_KIND, VERSION, Function, RoleSet, body_roles, functions_of, origin_of
from .schema import (
    BY_NAME,
    LANGUAGES,
    MECHANISMS,
    RULE_TAG_MECHANISM,
    RUNGS,
    SCHEMA_VERSION,
    FeatureRecordError,
    feature_set_digest,
    features_for,
    instruments_for,
    validate_record,
)

ENGINE_RULE_PREFIX = "engine:"
UNKNOWN_FAMILY = "unknown"
_STEPS = re.compile(r"(\d+) steps")
_WITNESS = re.compile(r"^(?P<source>.+?) -> (?P<sink>.+?)(?: in \S+)? \(line")
_CALL = re.compile(r"(?<![A-Za-z0-9_$])([A-Za-z_]\w*)\s*\(")


@dataclass(frozen=True)
class Part:
    """One instrument's contribution to a record: its state, its feature values (only when ``ran``), its version."""

    state: str
    values: Mapping[str, Any] = field(default_factory=dict)
    version: str | None = None


NONE = Part("none")
NOT_APPLICABLE = Part("not_applicable")


def _clip(name: str, value: Any) -> Any:
    spec = BY_NAME[name]
    if value is None or spec.type != "int" or isinstance(value, bool):
        return value
    return max(0, min(int(value), spec.cap or 0))


def record(
    candidate: str,
    family: str,
    language: str,
    profile: str,
    parts: Mapping[str, Part],
    *,
    unit: str = "pin",
    base: str | None = None,
) -> dict[str, Any]:
    """The validated record of one candidate. ``language`` sets the one-hot; an instrument absent from ``parts`` is
    ``none``; a value for a feature of another instrument, or outside the profile, is refused."""
    closed = language if language in LANGUAGES else "other"
    parts = {**parts, "language": Part("ran", {f"lang.{name}": name == closed for name in LANGUAGES})}
    wanted = instruments_for(profile)
    stray = sorted(set(parts) - set(wanted))
    if stray:
        raise FeatureRecordError(f"parts for instruments outside the {profile} profile: {stray}")
    x: dict[str, Any] = {}
    for spec in features_for(profile):
        part = parts.get(spec.instrument, NONE)
        x[spec.name] = _clip(spec.name, part.values.get(spec.name)) if part.state == "ran" else None
    for name in wanted:
        part = parts.get(name, NONE)
        foreign = sorted(k for k in part.values if k not in BY_NAME or BY_NAME[k].instrument != name)
        if foreign:
            raise FeatureRecordError(f"instrument {name} supplied features it does not own: {foreign}")
    instruments = {name: {"state": parts.get(name, NONE).state, "version": parts.get(name, NONE).version} for name in wanted}
    out: dict[str, Any] = {
        "candidate": candidate, "family": family, "language": closed, "profile": profile, "schema_version": SCHEMA_VERSION,
        "feature_set_digest": feature_set_digest(), "unit": unit, "x": x, "instruments": instruments,
    }  # fmt: skip
    if base is not None:
        out["base"] = base
    return validate_record(out)


# --- per-instrument parts --------------------------------------------------------------------------------------------


def ruleset_digest(rules: Iterable[PatternRule]) -> str:
    """sha256 of the rules as data: the quick instrument's version."""
    canonical = json.dumps([asdict(rule) for rule in rules], sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_prior(item: object) -> bool:
    return bool(getattr(item, "framework", None) or getattr(item, "library", None))


def quick_part(hits: Sequence[tuple[str, str]], rules: Mapping[str, PatternRule], version: str | None = None) -> Part:
    """``hits`` are ``(rule_id, status)`` of the quick rules that fired in the candidate's function. Rule ids reach
    the record only as mechanism buckets and the prior count."""
    mechanisms = dict.fromkeys(MECHANISMS, 0)
    enabled = shadow = priors = 0
    precision: float | None = None
    for rule_id, status in hits:
        if status == "enabled":
            enabled += 1
        else:
            shadow += 1
        rule = rules.get(rule_id)
        if rule is None:
            mechanisms["other"] += 1
            continue
        for mechanism in sorted({RULE_TAG_MECHANISM.get(tag, "other") for tag in rule.tags} or {"other"}):
            mechanisms[mechanism] += 1
        precision = rule.precision_estimate if precision is None else max(precision, rule.precision_estimate)
        priors += 1 if _is_prior(rule) else 0
    values: dict[str, Any] = {"qr.enabled_hits": enabled, "qr.shadow_hits": shadow, "qr.prior_hits": priors}
    values.update({f"qr.mechanism.{m}": n for m, n in mechanisms.items()})
    values["qr.max_precision_estimate"] = None if precision is None else round(min(max(precision, 0.0), 1.0), 6)
    return Part("ran", values, version)


@dataclass(frozen=True)
class Vocabulary:
    """The semantic entries of one language, to name a witness's sink operation and source kind and their origin."""

    sinks: Mapping[str, tuple[str, str]]  # call -> (operation, origin)
    sources: tuple[tuple[str, str, str], ...]  # (pattern, kind, origin)

    @classmethod
    def load(cls, language: str, facts: Any = None) -> Vocabulary:
        """The entries of ``language`` in ``facts`` (default: the bundled facts; a per-repository
        :func:`.roles.vocabulary_overlay` names each inferred entry's origin in its id)."""
        from ..semantic.facts import FactLoadError, load_facts

        try:
            scoped = (facts if facts is not None else load_facts()).for_language(language)
        except FactLoadError:
            return cls({}, ())
        sinks: dict[str, tuple[str, str]] = {}
        for sink in scoped.sinks:
            for call in sink.calls:
                sinks.setdefault(call, (CWE_OPERATION.get(sink.cwe, "other"), origin_of(sink.id, _is_prior(sink))))
        sources = tuple(
            (
                pattern,
                "inferred_role" if origin_of(src.id, False) != "language" else SOURCE_KIND.get(src.id, "other"),
                origin_of(src.id, _is_prior(src)),
            )
            for src in scoped.sources
            for pattern in src.patterns
        )
        return cls(sinks, sources)

    def sink(self, text: str) -> tuple[str, str] | None:
        name = text.strip()
        for call in sorted(self.sinks, key=len, reverse=True):
            if name == call or name.endswith(("." + call, "->" + call, "::" + call)) or name.startswith(call + "("):
                return self.sinks[call]
        return None

    def source(self, text: str) -> tuple[str, str] | None:
        for pattern, kind, origin in sorted(self.sources, key=lambda s: len(s[0]), reverse=True):
            if pattern in text:
                return kind, origin
        return None


def engine_part(
    findings: Sequence[Mapping[str, Any]],
    *,
    completion: float | None,
    degraded: bool,
    vocabulary: Vocabulary | None = None,
    unstable: bool | None = None,
    version: str | None = None,
) -> Part:
    """The engine's findings in the candidate's function (``rung`` and ``witness`` when the producer kept them)."""
    rungs = [str(f["rung"]) for f in findings if str(f.get("rung")) in RUNGS]
    steps = [int(m.group(1)) for f in findings if (m := _STEPS.search(str(f.get("witness") or "")))]
    sink = source = None
    for finding in findings:
        match = _WITNESS.match(str(finding.get("witness") or ""))
        if match and vocabulary is not None:
            sink = sink or vocabulary.sink(match.group("sink"))
            source = source or vocabulary.source(match.group("source"))
    values = {
        "eng.findings": len(findings), "eng.rung_max": max(rungs, key=RUNGS.index) if rungs else None,
        "eng.witness_steps_min": min(steps) if steps else None, "eng.sink_kind": sink[0] if sink else None,
        "eng.sink_origin": sink[1] if sink else None, "eng.source_kind": source[0] if source else None,
        "eng.source_origin": source[1] if source else None, "eng.sanitizer_on_path": None,
        "eng.completion": None if completion is None else round(min(max(completion, 0.0), 1.0), 6), "eng.degraded": degraded,
        "eng.unstable": unstable,
    }  # fmt: skip
    return Part("ran", values, version)


def facts_part(callers: Sequence[Mapping[str, Any]], function: str, version: str | None = None) -> Part:
    """``callers`` are the repo-facts call sites of the candidate's function in other files."""
    files = {str(site.get("path")) for site in callers}
    return Part(
        "ran",
        {"facts.callers": len(callers), "facts.caller_files": len(files), "facts.is_global": function == MODULE_FUNCTION},
        version,
    )


def source_part(lines: Sequence[str] | None, language: str, function: str) -> Part:
    """The function's span; ``none`` without the file or a declaration pattern for its language (C, say: no coverage,
    not a failure), ``failed`` when a covered file does not declare the function."""
    if lines is None or (function != MODULE_FUNCTION and language not in DECLARATION):
        return NONE
    span = function_span(lines, language, function)
    return Part("ran", {"facts.function_lines": span}) if span is not None else Part("failed")


def verify_part(passes: Mapping[str, Sequence[Mapping[str, Any]]], candidate: str, line: int | None, version: str | None = None) -> Part:
    """Pass verdicts of one candidate from the passes' ``units.jsonl``: asked in a pass when a unit's candidates list
    it, flagged when that unit's ``flagged`` names it. ``none`` when no pass asked it."""
    flags: dict[str, bool | None] = {}
    turns: list[float] = []
    offsets: list[int] = []
    for label in ("a", "b", "c"):
        asked = [u for u in passes.get(label) or () if any(f"{c[0]}::{c[1]}" == candidate for c in u.get("candidates") or ())]
        if not asked:
            flags[label] = None
            continue
        flagged = [f for u in asked for f in u.get("flagged") or () if f.get("candidate") == candidate]
        flags[label] = bool(flagged)
        turns.extend(float(u["turns"]) for u in asked if isinstance(u.get("turns"), (int, float)))
        for finding in flagged:
            reported = str(finding.get("reported_at") or "").rpartition(":")[2]
            if line is not None and reported.isdigit():
                offsets.append(abs(int(reported) - line))
    if flags["a"] is None and flags["b"] is None:
        return NONE
    values = {
        "verify.flag_a": flags["a"], "verify.flag_b": flags["b"], "verify.flag_c": flags["c"],
        "verify.votes": sum(1 for v in flags.values() if v), "verify.turns_mean": round(sum(turns) / len(turns), 3) if turns else None,
        "verify.site_offset": min(offsets) if offsets else None,
    }  # fmt: skip
    return Part("ran", values, version)


def agree_part(final: str | None) -> Part:
    return Part("ran", {"agree.final": final}) if final else NONE


def roles_part(function: Function | None, roles: RoleSet | None, language: str) -> Part:
    """The deterministic roles of the candidate's function (language-level entries plus wrapper inference; priors
    off): ``none`` when inference did not run or cannot read the language's declarations, ``failed`` when the
    function's body could not be found."""
    if roles is None or "inferred_wrapper" not in roles.sources or language not in DECLARATION:
        return NONE
    if function is None:
        return Part("failed", version=VERSION)
    confidence, source = body_roles(function, roles, language)
    return Part("ran", {"roles.sink_confidence": confidence, "roles.source_in_function": source}, VERSION)


def model_sinks_part(roles: RoleSet | None, path: str, function: str, version: str | None = None) -> Part:
    """The model's role classification of the candidate's function: flagged when the model named a sink in it. A
    file with a chunk the model did not classify is ``failed`` unless the function was flagged -- never "no sink"."""
    if roles is None or "model_role" not in roles.sources:
        return NONE
    named = [r for r in roles.roles if r.origin == "model_role" and r.kind == "sink" and r.path == path and r.function == function]
    if not named and path in roles.unclassified:
        return Part("failed", version=version)
    operation = sorted(r.operation for r in named)[0] if named else None
    return Part("ran", {"ms.flagged": bool(named), "ms.operation": operation}, version)


def function_of(lines: Sequence[str] | None, path: str, language: str, function: str) -> Function | None:
    """The declared function ``function`` of a file (its parameters and body), ``None`` when it is not declared."""
    if not lines or function == MODULE_FUNCTION:
        return None
    return next((f for f in functions_of(path, lines, language) if f.name == function), None)


# --- the host path ---------------------------------------------------------------------------------------------------


class SourceIndex:
    """A checkout's product files read once: lines per path, the enclosing function of a line, and the name-level
    caller graph (the repo-facts patterns) for the entry-point distance."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._lines: dict[str, list[str] | None] = {}
        self._callers: dict[str, set[str]] | None = None
        self._files: list[str] | None = None

    def files(self) -> list[str]:
        if self._files is None:
            self._files = [p.relative_to(self.root).as_posix() for p in product_files(self.root)]
        return self._files

    def lines(self, path: str) -> list[str] | None:
        if path not in self._lines:
            file = self.root / path
            self._lines[path] = file.read_text(encoding="utf-8", errors="replace").splitlines() if file.is_file() else None
        return self._lines[path]

    def function_at(self, path: str, line: int | None, fallback: str | None = None) -> str:
        lines = self.lines(path)
        language = detect_language(Path(path))
        if lines and language in DECLARATION and line and 0 < line <= len(lines):
            return enclosing(lines, line - 1, language)
        return fallback or MODULE_FUNCTION

    def callers(self) -> dict[str, set[str]]:
        """Function name -> the names of the functions that call it anywhere in the product files."""
        if self._callers is None:
            declared: dict[str, set[str]] = {}
            files = self.files()
            for path in files:
                language = detect_language(Path(path))
                pattern = DECLARATION.get(language)
                if pattern is not None:
                    declared.setdefault(language, set()).update(
                        n for line in self.lines(path) or () if (n := _declared_name(pattern, line))
                    )
            graph: dict[str, set[str]] = {}
            for path in files:
                language = detect_language(Path(path))
                names, lines = declared.get(language, set()), self.lines(path) or []
                for index, line in enumerate(lines):
                    if line.lstrip().startswith(_COMMENT_PREFIXES):
                        continue
                    for match in _CALL.finditer(line):
                        if match.group(1) in names:
                            graph.setdefault(match.group(1), set()).add(enclosing(lines, index, language))
            self._callers = graph
        return self._callers


def entry_distance(function: str, entries: set[str], callers: Mapping[str, set[str]], cap: int = 6) -> int:
    """Caller-graph hops from an entry point to ``function``; ``cap`` means not reached within ``cap - 1`` hops."""
    frontier, seen = {function}, {function}
    for hops in range(cap):
        if frontier & entries:
            return hops
        frontier = {c for name in frontier for c in callers.get(name, ()) if c not in seen}
        seen |= frontier
        if not frontier:
            break
    return cap


def entry_names(root: Path, paths: Iterable[str]) -> tuple[set[str], set[str]]:
    """(entry function names, paths with a file-level entry) by :func:`..mapping.analyze_entry_points`."""
    from ..mapping import analyze_entry_points

    targets = [build_file_target(root, root / p) for p in sorted(set(paths)) if (root / p).is_file()]
    records = analyze_entry_points(root, targets)
    return {r.function_name for r in records if r.function_name}, {r.path for r in records}


def _family_of(rule: PatternRule | None) -> str:
    if rule is None:
        return UNKNOWN_FAMILY
    family = load_families().family_of_cwe(rule.cwe)
    return family.id if family is not None else UNKNOWN_FAMILY


def _signals(
    index: SourceIndex, findings: Sequence[Any], engine_result: Mapping[str, Any] | None, rules: Mapping[str, PatternRule]
) -> tuple[dict[tuple[str, str, str], list[tuple[str, str]]], dict[tuple[str, str, str], list[Mapping[str, Any]]]]:
    quick: dict[tuple[str, str, str], list[tuple[str, str]]] = {}
    for finding in findings:
        rule_id = str(finding.finding_id).split(":", 1)[0]
        function = index.function_at(finding.path, finding.line, finding.function_name)
        quick.setdefault((finding.path, function, _family_of(rules.get(rule_id))), []).append((rule_id, str(finding.status)))
    engine: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for finding in (engine_result or {}).get("findings") or []:
        path, _, rest = str(finding.get("site") or "").partition(":")
        line_text, _, function_name = rest.partition(":")
        line = int(line_text) if line_text.isdigit() else None
        function = index.function_at(path, line, function_name or None)
        engine.setdefault((path, function, str(finding.get("family") or UNKNOWN_FAMILY)), []).append(finding)
    return quick, engine


def _callers_of(index: SourceIndex, callers: Mapping[str, set[str]], path: str, function: str) -> list[dict[str, Any]]:
    """The call sites of ``function`` in other product files, as repo-facts records them (capped at 40)."""
    if function == MODULE_FUNCTION or function not in callers:
        return []
    sites: list[dict[str, Any]] = []
    pattern = re.compile(r"(?<![A-Za-z0-9_$])" + re.escape(function) + r"\s*\(")
    for other in index.files():
        if other == path or detect_language(Path(other)) != detect_language(Path(path)):
            continue
        for number, line in enumerate(index.lines(other) or (), start=1):
            if pattern.search(line) and not line.lstrip().startswith(_COMMENT_PREFIXES):
                sites.append({"path": other, "line": number})
                if len(sites) >= 40:
                    return sites
    return sites


__all__ = [
    "CWE_OPERATION", "NONE", "NOT_APPLICABLE", "SOURCE_KIND", "Part", "SourceIndex", "Vocabulary", "agree_part",
    "function_of", "model_sinks_part", "roles_part",
    "engine_part", "entry_distance", "entry_names", "facts_part", "function_span", "quick_part", "record",
    "ruleset_digest", "source_part", "verify_part",
]  # fmt: skip
