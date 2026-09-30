"""Feature records per candidate, from the signals every instrument emitted (learned-decision-engine design section 1).

No model. The same per-instrument builders serve two callers:

- the plane task ``features`` (:mod:`..plane.tasks.features`), which reads a case's delivered artifacts;
- the host: :func:`build_for_scan` over a checkout's quick findings and an engine result, for ``scan`` and
  ``pre-push`` (a whole-repository scan, or a base..head delta with :class:`Delta`).

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
from ..plane.tasks.repo_facts import _COMMENT_PREFIXES, DECLARATION, GLOBAL, _declared_name, enclosing, product_files
from ..preprocess import build_file_target, detect_language
from ..ruleset import DEFAULT_RULESET_DIR, PatternRule, load_ruleset
from .roles import CWE_OPERATION, SOURCE_KIND, VERSION, Function, RoleSet, body_roles, functions_of, infer_for_checkout, origin_of
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


def language_of(path: str) -> str:
    """The closed language of a path (its extension), ``other`` outside :data:`.schema.LANGUAGES`."""
    language = detect_language(Path(path))
    return language if language in LANGUAGES else "other"


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
    return Part("ran", {"facts.callers": len(callers), "facts.caller_files": len(files), "facts.is_global": function == GLOBAL}, version)


def function_span(lines: Sequence[str], language: str, function: str) -> int | None:
    """Lines of the first declaration of ``function`` up to the next declaration (Python: up to the next line indented
    no deeper), ``None`` when the file does not declare it. ``<global>`` counts the whole file."""
    if function == GLOBAL:
        return len(lines)
    pattern = DECLARATION.get(language)
    if pattern is None:
        return None
    start = next((i for i, line in enumerate(lines) if _declared_name(pattern, line) == function), None)
    if start is None:
        return None
    indent = len(lines[start]) - len(lines[start].lstrip(" \t"))
    for end in range(start + 1, len(lines)):
        line = lines[end]
        if language == "python":
            if line.strip() and not line.lstrip().startswith("#") and len(line) - len(line.lstrip(" \t")) <= indent:
                return end - start
        elif _declared_name(pattern, line):
            return end - start
    return len(lines) - start


def source_part(lines: Sequence[str] | None, language: str, function: str) -> Part:
    if lines is None:
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
    off): ``none`` when inference did not run, ``failed`` when the function's body could not be found."""
    if roles is None or "inferred_wrapper" not in roles.sources:
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
    if not lines or function == GLOBAL:
        return None
    return next((f for f in functions_of(path, lines, language) if f.name == function), None)


# --- the host path ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Delta:
    """A base..head delta: the base checkout, the head-side changed line ranges per path (``git diff -U0``), and the
    base's quick findings and engine result, whose signals decide novelty."""

    root: Path
    changed: Mapping[str, Sequence[tuple[int, int]]]
    findings: Sequence[Any] = ()
    engine_result: Mapping[str, Any] | None = None
    pin: str | None = None


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
        return fallback or GLOBAL

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


def _engine_state(result: Mapping[str, Any] | None) -> str:
    if result is None:
        return "none"
    return "ran" if int(result.get("questions") or 0) > 0 else "failed"


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


def _changed_in(index: SourceIndex, changed: Mapping[str, Sequence[tuple[int, int]]]) -> dict[tuple[str, str], int]:
    """(path, function) -> changed lines inside it, by the head's enclosing declarations."""
    counts: dict[tuple[str, str], int] = {}
    for path, ranges in changed.items():
        for lo, hi in ranges:
            for line in range(int(lo), int(hi) + 1):
                key = (path, index.function_at(path, line))
                counts[key] = counts.get(key, 0) + 1
    return counts


def _body_calls(lines: Sequence[str] | None, language: str, function: str) -> set[str]:
    if not lines:
        return set()
    return {m.group(1) for i, line in enumerate(lines) if enclosing(lines, i, language) == function for m in _CALL.finditer(line)}


def build_for_scan(
    root: Path,
    findings: Sequence[Any],
    engine_result: Mapping[str, Any] | None,
    *,
    base: Delta | None = None,
    rules: Sequence[PatternRule] | None = None,
    quick_languages: Iterable[str] | None = None,
    engine_languages: Iterable[str] | None = None,
    roles: RoleSet | None | bool = True,
) -> list[dict[str, Any]]:
    """``static`` records for a checkout: one per (path, function, family) with a quick or engine signal. ``findings``
    are the quick findings (enabled and shadow alike), ``engine_result`` the engine's record (``findings`` with
    ``site``/``family``/``rung``/``witness``, ``questions``, ``completed``, ``degradations``; ``None`` when the engine
    did not run, ``questions == 0`` is ``failed``). With ``base`` only functions enclosing a changed line are
    candidates, and ``delta.*`` compares their signals with the base's. ``roles``: ``True`` infers wrapper roles over
    the checkout (priors off), a :class:`.roles.RoleSet` is used as given, ``False``/``None`` leaves ``roles`` ``none``."""
    from ..plane.tasks.alerts import covers
    from ..plane.tasks.alerts import engine_languages as engine_covered
    from ..plane.tasks.alerts import quick_languages as quick_covered
    from ..semantic.facts import FactLoadError, load_facts

    root = Path(root)
    loaded = tuple(rules) if rules is not None else load_ruleset(DEFAULT_RULESET_DIR)
    by_id = {rule.rule_id: rule for rule in loaded}
    quick_langs = set(quick_languages if quick_languages is not None else quick_covered())
    engine_langs = set(engine_languages if engine_languages is not None else engine_covered())
    index = SourceIndex(root)
    quick, engine = _signals(index, findings, engine_result, by_id)
    keys = sorted(set(quick) | set(engine))
    changed: dict[tuple[str, str], int] = {}
    base_quick: dict[tuple[str, str, str], list[tuple[str, str]]] = {}
    base_engine: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    base_index: SourceIndex | None = None
    if base is not None:
        changed = _changed_in(index, base.changed)
        keys = [k for k in keys if (k[0], k[1]) in changed]
        base_index = SourceIndex(base.root)
        base_quick, base_engine = _signals(base_index, base.findings, base.engine_result, by_id)
    entries, file_entries = entry_names(root, {k[0] for k in keys}) if keys else (set(), set())
    callers = index.callers() if keys else {}
    quick_version = ruleset_digest(loaded)
    engine_state = _engine_state(engine_result)
    completed, questions = (engine_result or {}).get("completed"), (engine_result or {}).get("questions")
    completion = int(completed) / int(questions) if isinstance(completed, int) and isinstance(questions, int) and questions else None
    degraded = bool((engine_result or {}).get("degradations"))
    vocabularies: dict[str, Vocabulary] = {}
    inferred = (infer_for_checkout(root) if keys else RoleSet(sources=("inferred_wrapper",))) if roles is True else roles or None
    try:
        sanitizer_calls = {language: {c for s in load_facts().for_language(language).sanitizers for c in s.calls} for language in LANGUAGES}
    except FactLoadError:
        sanitizer_calls = {}
    out: list[dict[str, Any]] = []
    for key in keys:
        path, function, family = key
        language = detect_language(Path(path))
        parts: dict[str, Part] = {}
        parts["quick"] = quick_part(quick.get(key, []), by_id, quick_version) if covers(quick_langs, language) else NONE
        if language in engine_langs and engine_state != "none":
            vocabulary = vocabularies.setdefault(language, Vocabulary.load(language))
            parts["engine"] = (
                engine_part(engine.get(key, []), completion=completion, degraded=degraded, vocabulary=vocabulary)
                if engine_state == "ran" else Part("failed")
            )  # fmt: skip
        lines = index.lines(path)
        parts["source"] = source_part(lines, language, function)
        parts["roles"] = roles_part(function_of(lines, path, language, function), inferred, language)
        distance = 0 if function == GLOBAL and path in file_entries else entry_distance(function, entries, callers)
        parts["entry_points"] = Part("ran", {"facts.entry_distance": distance})
        parts["facts"] = facts_part(_callers_of(index, callers, path, function), function)
        if base is None or base_index is None:
            parts["delta"] = NOT_APPLICABLE
        else:
            head_n = len(quick.get(key, [])) + len(engine.get(key, []))
            base_n = len(base_quick.get(key, [])) + len(base_engine.get(key, []))
            novelty = "new" if base_n == 0 else "worsened" if head_n > base_n else "unchanged"
            known = sanitizer_calls.get(language, set())
            removed = bool((_body_calls(base_index.lines(path), language, function) - _body_calls(lines, language, function)) & known)
            values = {"delta.novelty": novelty, "delta.changed_lines": changed.get((path, function), 0), "delta.sanitizer_removed": removed}
            parts["delta"] = Part("ran", values)
        unit, pin = ("delta", base.pin) if base is not None else ("pin", None)
        out.append(record(f"{path}::{function}", family, language, "static", parts, unit=unit, base=pin))
    return out


def _callers_of(index: SourceIndex, callers: Mapping[str, set[str]], path: str, function: str) -> list[dict[str, Any]]:
    """The call sites of ``function`` in other product files, as repo-facts records them (capped at 40)."""
    if function == GLOBAL or function not in callers:
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
    "CWE_OPERATION", "NONE", "NOT_APPLICABLE", "SOURCE_KIND", "Delta", "Part", "SourceIndex", "Vocabulary", "agree_part",
    "function_of", "model_sinks_part", "roles_part",
    "build_for_scan", "engine_part", "entry_distance", "entry_names", "facts_part", "function_span", "language_of", "quick_part", "record",
    "ruleset_digest", "source_part", "verify_part",
]  # fmt: skip
