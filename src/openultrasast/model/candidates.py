"""What a detector is asked to judge, enumerated deterministically (constrained-detector, Req 1).

The detector stops searching. Measured on 2026-09-06, 120 runs of the unconstrained loop over the same twelve pairs
produced 120 distinct tool-call trajectories, and outcome disagreement tracked trajectory divergence rather than
judgement: the model was spending its budget guessing grep patterns to find sinks the semantic IR already knows.

So something deterministic decides what the model looks at, and that enumerator becomes a hard ceiling on recall.
Which is why it was measured before any of this was built: the pattern ruleset finds a candidate inside the labeled
function for **12.1%** of the corpus — below the 64.9% the unconstrained loop already reaches — while the IR's call
sites and bindings reach **96.6%**, a median of ten sites per function. The ruleset is never the generator here.

Ordering is `(path, line, name)` and the bound is a constant, so the batches the judgment step forms, and therefore
the sequence of model calls, are determined by the input alone.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .taxonomy import FamilyTaxonomy

CandidateKind = Literal["call", "bind", "operation", "config"]

# What can carry each family's bug. An injection lives at a call; an access-control bug is the *absence* of a guard
# around an operation, so its candidate is the operation and what the model needs is the guards in scope.
FAMILY_SHAPE: dict[str, tuple[CandidateKind, ...]] = {
    "injection": ("call",),
    "path": ("call",),
    "deserialization": ("call",),
    "untrusted_destination": ("call",),
    "output_encoding": ("call",),
    "memory": ("call",),
    "prototype": ("call", "bind"),
    "access_control": ("operation",),
    # A permissive default is as often an argument to a call — `cors({origin: "*"})`, `app.use(session({secure:
    # false}))` — as it is a binding. Measured: with bindings alone the shape missed `createApplication` and
    # `getAllowedHosts`, whose whole bug is inside a call argument.
    "config_secrets": ("call", "bind", "config"),
    "unknown": ("call", "bind"),
}

# The p90 of the measured distribution is 22 sites per labeled function, so two batches cover all but the tail.
MAX_CANDIDATES_PER_CALL = 12
_MAX_TEXT = 400
_LANGUAGE = {"python": "python", "javascript": "javascript", "typescript": "typescript", "c_cpp": "c", "java": "java"}


@dataclass(frozen=True)
class Candidate:
    """One site the model will be asked a single bounded question about."""

    path: str
    line: int
    kind: CandidateKind
    name: str
    text: str
    function: str
    arg_texts: tuple[str, ...] = ()
    arg_names: tuple[tuple[str, ...], ...] = ()
    # What the IR resolved for the arguments, nearest binding first. This is the work the model used to do by
    # grepping, and the reason it no longer has to.
    binding_chain: tuple[str, ...] = ()
    guards: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return f"{self.path}:{self.line}:{self.name}"

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "line": self.line,
            "function": self.function,
            "text": self.text,
            "arguments": list(self.arg_texts),
            "binding_chain": list(self.binding_chain),
            "guards": list(self.guards),
        }


@dataclass(frozen=True)
class CandidateSet:
    """The sites to judge, what was dropped past the bound, and why there is nothing when there is nothing."""

    candidates: tuple[Candidate, ...] = ()
    discarded: int = 0
    reason: str = ""  # "", unsupported_language, no_candidate
    function_found: bool = True


def enumerate_candidates(
    root: Path,
    region: object,
    family: str,
    *,
    taxonomy: object,
    limit: int = MAX_CANDIDATES_PER_CALL,
) -> CandidateSet:
    """Every site in the region that could carry ``family``'s bug, ordered and bounded."""
    del taxonomy  # the family id is the key; the taxonomy validates it elsewhere
    from ..semantic.ir import parse_file

    path = str(getattr(region, "path", "") or "")
    wanted = str(getattr(region, "function", "") or "")
    target = root / path
    if not target.is_file():
        return CandidateSet(reason="unsupported_language", function_found=False)
    text = target.read_text(errors="ignore")
    ir = parse_file(path, text, _language_of(path))
    if not ir.parse_ok:
        return CandidateSet(reason="unsupported_language", function_found=False)
    functions = [item for item in ir.functions if item.name != "<module>" and (not wanted or item.name == wanted)]
    if wanted and not functions:
        return CandidateSet(reason="no_candidate", function_found=False)
    kinds = FAMILY_SHAPE.get(family, ("call", "bind"))
    lines = text.splitlines()
    found: list[Candidate] = []
    for function in functions:
        guards = _guards(ir, function, text, path) if "operation" in kinds else ()
        found.extend(_from_function(path, function, kinds, lines, guards))
    found.sort(key=lambda item: (item.path, item.line, item.name))
    # One question per site: a chained expression reaches the IR as several calls at the same line and name — one
    # bare, one carrying the arguments — and asking twice would spend budget and double-count the answer. Keep the
    # richest, because `filter_by(user_id=owner)` and a bare `filter_by` are the same site and only one of them
    # says what the constraint was.
    best: dict[str, Candidate] = {}
    for item in found:
        current = best.get(item.id)
        if current is None or (len(item.arg_texts), len(item.binding_chain)) > (len(current.arg_texts), len(current.binding_chain)):
            best[item.id] = item
    found = sorted(best.values(), key=lambda item: (item.path, item.line, item.name))
    if not found:
        return CandidateSet(reason="no_candidate")
    return CandidateSet(candidates=tuple(found[:limit]), discarded=max(len(found) - limit, 0))


def _from_function(path: str, function: object, kinds: Sequence[str], lines: Sequence[str], guards: tuple[str, ...]):  # type: ignore[no-untyped-def]
    binds = tuple(getattr(function, "binds", ()) or ())
    name = str(getattr(function, "name", ""))
    out: list[Candidate] = []
    if "call" in kinds or "operation" in kinds:
        kind: CandidateKind = "operation" if "operation" in kinds else "call"
        for site in getattr(function, "calls", ()) or ():
            out.append(
                Candidate(
                    path=path,
                    line=site.line,
                    kind=kind,
                    name=site.name,
                    text=_line_text(lines, site.line),
                    function=name,
                    arg_texts=tuple(site.arg_texts),
                    arg_names=tuple(tuple(names) for names in site.arg_names),
                    binding_chain=_chain(binds, [n for names in site.arg_names for n in names], site.line),
                    guards=guards,
                )
            )
    if "bind" in kinds or "config" in kinds:
        for bind in binds:
            if "config" in kinds and "bind" not in kinds and not bind.is_constant:
                continue
            out.append(
                Candidate(
                    path=path,
                    line=bind.line,
                    kind="config" if (bind.is_constant and "config" in kinds) else "bind",
                    name=bind.name,
                    text=_line_text(lines, bind.line),
                    function=name,
                    arg_texts=(bind.value_text[:_MAX_TEXT],),
                    arg_names=(tuple(bind.names),),
                    binding_chain=_chain(binds, list(bind.names), bind.line),
                    guards=guards,
                )
            )
    return out


def _chain(binds: Sequence[object], names: Sequence[str], before: int, depth: int = 4) -> tuple[str, ...]:
    """Walk the bindings backwards from the names an argument mentions, nearest first.

    This is exactly the work the unconstrained loop was doing with `grep_repo`, and it is deterministic."""
    chain: list[str] = []
    seen: set[str] = set()
    wanted = [name for name in names if name]
    for _ in range(depth):
        step = None
        for bind in sorted(binds, key=lambda item: -int(getattr(item, "line", 0))):
            line = int(getattr(bind, "line", 0))
            bound = str(getattr(bind, "name", ""))
            if line >= before or bound not in wanted or bound in seen:
                continue
            step = bind
            break
        if step is None:
            break
        seen.add(str(step.name))  # type: ignore[attr-defined]
        chain.append(f"{step.name} = {str(step.value_text)[:_MAX_TEXT]}")  # type: ignore[attr-defined]
        before = int(step.line)  # type: ignore[attr-defined]
        wanted = [name for name in getattr(step, "names", ()) or () if name]
        if not wanted:
            break
    return tuple(chain)


def _guards(ir: object, function: object, text: str, path: str) -> tuple[str, ...]:
    """Decorators and in-body witnesses that discharge an obligation on this function, by identifier only."""
    try:
        from ..semantic.facts import load_facts
        from ..semantic.obligations import load_obligation_facts
        from ..semantic.obligations.operations import find_discharges
    except ImportError:  # pragma: no cover - the obligations facts are shipped, this is belt and braces
        return ()
    name = str(getattr(function, "name", ""))
    try:
        witnesses = find_discharges(ir, load_obligation_facts(), load_facts(), text=text)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 - a missing fact file must not stop enumeration
        return ()
    del path
    return tuple(sorted({item.detail or item.fact_id for item in witnesses if item.function == name}))


def _line_text(lines: Sequence[str], line: int) -> str:
    return lines[line - 1].strip()[:_MAX_TEXT] if 0 < line <= len(lines) else ""


def _language_of(path: str) -> str:
    from ..preprocess import detect_language

    return _LANGUAGE.get(detect_language(Path(path)), detect_language(Path(path)))


@dataclass(frozen=True)
class CandidateReport:
    """The ceiling: what a candidate-driven detector could find before any model is asked anything.

    This is the number that decides whether the design continues. A generator that cannot put a candidate inside
    the labeled function can never find that pair's bug however good the judgement is, so the ceiling is published
    as the limit on recall rather than discovered later as a disappointment (Req 1.3)."""

    generator: str = "ir"
    per_family: dict[str, dict[str, object]] = field(default_factory=dict)
    per_slice: dict[str, dict[str, object]] = field(default_factory=dict)
    gaps: tuple[tuple[str, str, str], ...] = ()  # (slice, pair, reason)

    def to_dict(self) -> dict[str, object]:
        return {
            "generator": self.generator,
            "per_family": {name: dict(block) for name, block in sorted(self.per_family.items())},
            "per_slice": {name: dict(block) for name, block in sorted(self.per_slice.items())},
            "gaps": [list(row) for row in self.gaps],
        }


def ceiling(cases: Sequence[object], *, taxonomy: FamilyTaxonomy, generator: str = "ir") -> CandidateReport:
    """Per family and per slice, the fraction of labeled functions a generator can put a candidate inside.

    ``generator`` is ``ir`` or ``ruleset``. The ruleset arm exists so the comparison that rejected it — 12.1%
    against 96.6% on the web slices — stays a measurement rather than a remembered number."""
    import tempfile

    from ..pairs import _materialize_side, _overlay_scan, _quick_scan

    families: dict[str, dict[str, int]] = {}
    slices: dict[str, dict[str, int]] = {}
    gaps: list[tuple[str, str, str]] = []
    sites: dict[str, list[int]] = {}
    for case in cases:
        family = labeled_family(case, taxonomy)
        slice_name = str(getattr(case, "slice", "") or "")
        region_path = str(getattr(case, "relpath", "") or "")
        with tempfile.TemporaryDirectory(prefix="ousast-ceiling-") as scratch:
            root = _materialize_side(Path(scratch) / "vuln", case, side="vuln")  # type: ignore[arg-type]
            if generator == "ruleset":
                ranges = _overlay_scan(root).ranges
                spans = labeled_spans(case, ranges)
                found = [
                    finding
                    for finding in _quick_scan(root)
                    if finding.line is not None and any(path == finding.path and start <= finding.line <= end for path, start, end in spans)
                ]
                count, reason = len(found), ("" if found else "no_candidate")
            else:
                labeled = [str(getattr(row, "function", "") or "") for row in getattr(case, "expected", ()) or ()]
                result = enumerate_candidates(
                    root,
                    Region(region_path, next((name for name in labeled if name), None)),
                    family,
                    taxonomy=taxonomy,
                    limit=10**6,  # the ceiling is about coverage, never about the batch bound
                )
                count, reason = len(result.candidates), result.reason
        for bucket, key in ((families, family), (slices, slice_name)):
            block = bucket.setdefault(key, {"pairs": 0, "with_candidate": 0})
            block["pairs"] += 1
            block["with_candidate"] += 1 if count else 0
        if count:
            sites.setdefault(family, []).append(count)
        else:
            gaps.append((slice_name, str(getattr(case, "name", "")), reason or "no_candidate"))
    per_family: dict[str, dict[str, object]] = {}
    per_slice: dict[str, dict[str, object]] = {}
    for bucket, out in ((families, per_family), (slices, per_slice)):
        for key, block in bucket.items():
            pairs = block["pairs"]
            row: dict[str, object] = {
                "pairs": pairs,
                "with_candidate": block["with_candidate"],
                "ceiling": (block["with_candidate"] / pairs) if pairs else 0.0,
            }
            if bucket is families:
                row["sites"] = _distribution(sites.get(key, []))
            out[key] = row
    return CandidateReport(generator=generator, per_family=per_family, per_slice=per_slice, gaps=tuple(sorted(gaps)))


def _distribution(counts: list[int]) -> dict[str, int]:
    if not counts:
        return {"min": 0, "median": 0, "p90": 0, "max": 0}
    counts = sorted(counts)
    return {
        "min": counts[0],
        "median": counts[len(counts) // 2],
        "p90": counts[min(int(len(counts) * 0.9), len(counts) - 1)],
        "max": counts[-1],
    }


def labeled_family(case: object, taxonomy: FamilyTaxonomy | None = None) -> str:
    """The family a pair belongs to, derived deterministically: declared label, else obligation, else mechanism,
    else CWE. ``unknown`` when none of those resolve.

    The deleted ``learning/classify.py`` had exactly this chain and only asked an LLM when every link failed —
    which, for a labeled corpus, was never. Group 1 first reduced this to the declared label alone, which
    silently emptied every family whose pairs are labeled by CWE rather than by name; the chain is restored
    here because it was never the noisy part.
    """
    from .taxonomy import load_families

    families: FamilyTaxonomy = taxonomy if taxonomy is not None else load_families()
    declared: list[str] = []
    derived: list[str] = []
    for row in getattr(case, "expected", ()) or ():
        label = getattr(row, "family", None)
        if label and any(family.id == label for family in families.families):
            declared.append(str(label))
            continue
        if getattr(row, "obligation", None):
            derived.append("access_control")
        mechanism = getattr(row, "mechanism", None)
        by_mechanism = families.family_of_mechanism(str(mechanism)) if mechanism else None
        if by_mechanism is not None and by_mechanism.id != "unknown":
            derived.append(by_mechanism.id)
            continue
        by_cwe = families.family_of_cwe(str(getattr(row, "cwe", "") or ""))
        if by_cwe is not None and by_cwe.id != "unknown":
            derived.append(by_cwe.id)
    for family in declared or derived:
        return family
    return "unknown"


def labeled_spans(
    case: object, ranges: Mapping[str, Sequence[tuple[str, int, int]]], *, function: str = ""
) -> tuple[tuple[str, int, int], ...]:
    """The (path, start, end) spans of the labeled functions; ``function`` overrides the label for the fixed side.

    Re-homed from the deleted ``learning/scoring.py`` — the enumerator's ceiling needs it to know which region a
    candidate had to fall inside, and it carries none of the K-run machinery that surrounded it.
    """
    wanted = {function} if function else {str(getattr(row, "function", "") or "") for row in getattr(case, "expected", ()) or ()}
    wanted.discard("")
    found: list[tuple[str, int, int]] = []
    for path, entries in ranges.items():
        for name, start, end in entries:
            if name in wanted:
                found.append((path, start, end))
    return tuple(found)


@dataclass(frozen=True)
class Region:
    """The two fields ``enumerate_candidates`` reads: where to look, and which function bounds the search.

    Public since the detector module that used to own this type was removed with the noise architecture — the
    enumerator still needs a name for its input, and callers still need one to construct.
    """

    path: str
    function: str | None


__all__ = [
    "FAMILY_SHAPE",
    "ceiling",
    "MAX_CANDIDATES_PER_CALL",
    "Candidate",
    "CandidateKind",
    "CandidateReport",
    "CandidateSet",
    "Region",
    "enumerate_candidates",
    "labeled_family",
    "labeled_spans",
]
