"""Leave-one-out: the pair corpus's own detection rate (corpus-seeded-mechanisms, Req 4).

For every scorable pair, a temporary mechanism store is seeded from every *other* trusted pair, both excerpts are
materialized and searched for variants, and the pair is scored with the pair rules: detected when a hit lies inside the
labeled function and names the labeled mechanism (or sink), silent when the fixed side yields no hit. Only ``seeded`` and
``reviewed`` pairs teach; ``advisory`` and ``title`` pairs are scored as held-out targets but never seed. Reported, never
gated.
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..pairs import GATING_TIERS, PairCase, _materialize, _targets
from .facts import FactLoadError, SemanticFacts, load_facts
from .functions import named_function_ranges, spans_named
from .mechanisms import Mechanism, MechanismStore, append_from_pair, corpus_mechanisms
from .seed import Lesson, _parse_language, pair_lessons
from .variant_search import search_tree
from .variants import Shape, trailing_name


@dataclass(frozen=True)
class LooOutcome:
    pair: str
    slice: str
    provenance: str
    mechanisms: tuple[str, ...]  # labeled mechanism ids of the held-out pair
    detected: bool
    silent: bool
    found_by: tuple[tuple[str, tuple[str, ...]], ...]  # (mechanism record id, pairs that taught it) for detecting hits
    hits_vuln: int
    hits_fixed: int
    teaches: bool  # the pair contributed at least one shape when others were held out
    leaked_by: tuple[str, ...] = ()  # mechanism record ids that hit the fixed side
    degradations: tuple[dict[str, object], ...] = ()  # from variant search on either side

    def to_dict(self) -> dict[str, object]:
        return {
            "pair": self.pair,
            "slice": self.slice,
            "provenance": self.provenance,
            "mechanisms": list(self.mechanisms),
            "detected": self.detected,
            "silent": self.silent,
            "found_by": [{"mechanism_id": mechanism_id, "pairs": list(pairs)} for mechanism_id, pairs in self.found_by],
            "hits_vuln": self.hits_vuln,
            "hits_fixed": self.hits_fixed,
            "teaches": self.teaches,
            "leaked_by": list(self.leaked_by),
        }


@dataclass(frozen=True)
class LooResult:
    outcomes: tuple[LooOutcome, ...]
    per_slice: dict[str, dict[str, float]]
    per_profile: dict[str, dict[str, float]]
    per_mechanism: dict[str, dict[str, float]]
    skipped: tuple[tuple[str, str], ...] = ()
    teaching_pairs: int = 0
    degradations: tuple[dict[str, object], ...] = field(default=())

    def to_dict(self) -> dict[str, object]:
        return {
            "per_slice": self.per_slice,
            "per_profile": self.per_profile,
            "per_mechanism": self.per_mechanism,
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
            "skipped": [{"pair": pair, "reason": reason} for pair, reason in self.skipped],
            "teaching_pairs": self.teaching_pairs,
            "degradations": list(self.degradations),
        }


def evaluate_loo(cases: Sequence[PairCase], *, facts: SemanticFacts | None = None) -> LooResult:
    loaded = facts if facts is not None else _facts()
    targets: list[PairCase] = []
    skipped: list[tuple[str, str]] = []
    for case in cases:
        if case.known_limit:
            skipped.append((case.name, f"known_limit:{case.known_limit}"))
        elif not case.vuln_file.is_file() or not case.fixed_file.is_file():
            skipped.append((case.name, "pointer_pair_not_cached" if not case.vendored else "excerpt_missing"))
        else:
            targets.append(case)
    lessons = {case.name: pair_lessons(case, loaded) for case in targets if case.review_tier in GATING_TIERS}
    outcomes = [_hold_out(case, targets, lessons, loaded) for case in targets]
    return LooResult(
        outcomes=tuple(outcomes),
        per_slice=_group(outcomes, lambda item: (item.slice,)),
        per_profile=_group(outcomes, lambda item: (item.provenance,)),
        per_mechanism=_group(outcomes, lambda item: item.mechanisms),
        skipped=tuple(skipped),
        teaching_pairs=sum(1 for shapes in lessons.values() if shapes),
        degradations=_unique_degradations(outcomes),
    )


def _unique_degradations(outcomes: Sequence[LooOutcome]) -> tuple[dict[str, object], ...]:
    seen: set[str] = set()
    unique: list[dict[str, object]] = []
    for outcome in outcomes:
        for item in outcome.degradations:
            key = repr(sorted(item.items()))
            if key not in seen:
                seen.add(key)
                unique.append(item)
    return tuple(unique)


def _hold_out(case: PairCase, targets: Sequence[PairCase], lessons: dict[str, list[Lesson]], facts: SemanticFacts) -> LooOutcome:
    with tempfile.TemporaryDirectory(prefix="ousast-loo-") as scratch:
        root = Path(scratch)
        store = MechanismStore(root / "mechanisms.jsonl")
        for teacher in targets:
            if teacher.name == case.name:
                continue
            for lesson in lessons.get(teacher.name, ()):
                append_from_pair(
                    store,
                    lesson.shape,
                    summary=lesson.summary,
                    cwe=lesson.cwe,
                    pair=teacher.name,
                    provenance=teacher.provenance,
                    tier=teacher.review_tier,
                )
        scored = score_pair_with_store(case, store, facts, root=root)
    return LooOutcome(**{**scored.__dict__, "teaches": bool(lessons.get(case.name))})


def score_pair_with_store(case: PairCase, store: MechanismStore, facts: SemanticFacts, *, root: Path | None = None) -> LooOutcome:
    """Search both sides of one pair with a fixed store and score it with the pair rules (shared by LOO and the lever)."""
    labeled_mechanisms = tuple(sorted({row.mechanism for row in case.expected if row.mechanism}))
    records = {record.id: record for record in corpus_mechanisms(store.load())}
    with tempfile.TemporaryDirectory(prefix="ousast-loo-pair-") as scratch:
        base = root if root is not None else Path(scratch)
        vuln_root = _materialize(base / "vuln", case.vuln_file, case.relpath)
        fix_root = _materialize(base / "fixed", case.fixed_file, case.relpath)
        vuln_search = search_tree(vuln_root, _targets(vuln_root), store, facts, max_mechanisms=len(records) or 1)
        fix_search = search_tree(fix_root, _targets(fix_root), store, facts, max_mechanisms=len(records) or 1)
        vuln_hits, fix_hits = vuln_search.hits, fix_search.hits
    text = case.vuln_file.read_text(errors="ignore")
    ranges = named_function_ranges(case.relpath, text, _parse_language(case)) or ()
    found: list[tuple[str, tuple[str, ...]]] = []
    for hit in vuln_hits:
        record = records.get(hit.mechanism_id)
        if record is None or not _inside_label(case, hit.line, ranges):
            continue
        if _names_label(case, record, hit.sink_name):
            found.append((record.id, tuple(record.pairs)))
    return LooOutcome(
        pair=case.name,
        slice=case.slice,
        provenance=case.provenance,
        mechanisms=labeled_mechanisms,
        detected=bool(found),
        silent=not fix_hits,
        found_by=tuple(found),
        hits_vuln=len(vuln_hits),
        hits_fixed=len(fix_hits),
        teaches=False,
        leaked_by=tuple(sorted({hit.mechanism_id for hit in fix_hits})),
        degradations=tuple(vuln_search.degradations) + tuple(fix_search.degradations),
    )


def _inside_label(case: PairCase, line: int, ranges: Sequence[tuple[str, int, int]]) -> bool:
    functions = {row.function for row in case.expected if row.function}
    if not functions:
        return True
    return any(start <= line <= end for function in functions for start, end in spans_named(ranges, function))


def _names_label(case: PairCase, record: Mechanism, sink_name: str) -> bool:
    """The hit names the pair's labeled mechanism, or its labeled sink when the row carries one."""
    shape = Shape.from_dict(record.shape or {})
    for row in case.expected:
        if row.mechanism and row.mechanism == shape.mechanism:
            return True
        if row.sink and trailing_name(row.sink) == sink_name:
            return True
    return False


def _group(outcomes: Sequence[LooOutcome], keys: object) -> dict[str, dict[str, float]]:
    buckets: dict[str, list[LooOutcome]] = {}
    for outcome in outcomes:
        for key in keys(outcome):  # type: ignore[operator]
            buckets.setdefault(str(key), []).append(outcome)
    return {name: _metrics(items) for name, items in sorted(buckets.items())}


def _metrics(outcomes: Sequence[LooOutcome]) -> dict[str, float]:
    pairs = len(outcomes)
    detected = sum(1 for item in outcomes if item.detected)
    silent = sum(1 for item in outcomes if item.silent)
    recall = detected / pairs if pairs else 0.0
    silence = silent / pairs if pairs else 0.0
    return {
        "pairs": pairs,
        "detected": detected,
        "silent": silent,
        "recall": recall,
        "silence": silence,
        "youden": recall + silence - 1.0 if pairs else 0.0,
        "teaching": sum(1 for item in outcomes if item.teaches),
    }


def _facts() -> SemanticFacts:
    try:
        return load_facts()
    except FactLoadError:
        return SemanticFacts(version="", sources=(), sinks=(), sanitizers=())
