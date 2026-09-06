"""Leave-one-out: the pair corpus's own detection rate (corpus-seeded-mechanisms, Req 4).

For every scorable pair, a temporary mechanism store is seeded from every *other* trusted pair, both excerpts are
materialized and searched for variants, and the pair is scored with the pair rules: detected when a hit lies inside the
labeled function and names the labeled mechanism (or sink), silent when the fixed side yields no hit. Only ``seeded`` and
``reviewed`` pairs teach; ``advisory`` and ``title`` pairs are scored as held-out targets but never seed. Reported, never
gated.

Obligation-labeled rows (authorization-obligations, Req 7.4) run the obligation checker on both sides with the held-out
store's obligation shapes: detected when a finding tagged with the labeled obligation lies inside the labeled function *and*
carries a ``known_fix`` supplied by the store (the checker's own facts-only finding is not the corpus teaching), silent when
the fixed side carries no such finding; ``found_by`` names the shape record and the pairs that taught it.
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..findings import StaticFinding
from ..pairs import PairCase, _materialize, _targets
from .facts import FactLoadError, SemanticFacts, load_facts
from .functions import named_function_ranges, spans_named
from .mechanisms import Mechanism, MechanismStore, append_from_pair, corpus_mechanisms
from .obligations import check_obligations, findings_to_static, load_obligation_facts, obligation_mechanisms
from .obligations.dominance import OrderDominance
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
    obligations: tuple[str, ...] = ()  # labeled obligation kinds of the held-out pair (Req 7.4)

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
            "obligations": list(self.obligations),
        }


@dataclass(frozen=True)
class LooResult:
    outcomes: tuple[LooOutcome, ...]
    per_slice: dict[str, dict[str, float]]
    per_profile: dict[str, dict[str, float]]
    per_mechanism: dict[str, dict[str, float]]
    skipped: tuple[tuple[str, str], ...] = ()
    per_obligation_kind: dict[str, dict[str, float]] = field(default_factory=dict)
    teaching_pairs: int = 0
    degradations: tuple[dict[str, object], ...] = field(default=())

    def to_dict(self) -> dict[str, object]:
        return {
            "per_slice": self.per_slice,
            "per_profile": self.per_profile,
            "per_mechanism": self.per_mechanism,
            "per_obligation_kind": self.per_obligation_kind,
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
        if case.unscorable or case.known_limit:
            # `PairCase.unscorable` verbatim when the loader computed one: one spelling per corpus fact, and it
            # already carries the `known_limit:` prefix when the limit is a maintainer's own word rather than one
            # of the vocabulary's. A case built by hand may carry only the declaration.
            skipped.append((case.name, case.unscorable or f"known_limit:{case.known_limit}"))
        elif not case.vuln_file.is_file() or not case.fixed_file.is_file():
            skipped.append((case.name, "pointer_pair_not_cached" if not case.vendored else "excerpt_missing"))
        else:
            targets.append(case)
    from ..learning.split import GATING_TIERS, holdout_names, is_teacher, refuse_if_holdout

    # learning-harness Req 5.1: every pair is still scored, but only a train-split teacher may seed a store.
    lessons = {case.name: pair_lessons(case, loaded) for case in targets if is_teacher(case)}
    outcomes = [_hold_out(case, targets, lessons, loaded) for case in targets]
    # Req 5.2: the holdout pairs kept out of the teaching set are named, not silently dropped. Non-teachers held
    # back for their tier or their unscorable reason are already in `skipped` with that reason.
    excluded = [case.name for case in targets if case.name not in lessons]
    refusal = refuse_if_holdout(excluded, targets)
    refusals = (refusal.degradation(),) if refusal is not None else ()
    withheld = tuple(
        (case.name, "tier" if case.review_tier not in GATING_TIERS else "unscorable")
        for case in targets
        if case.name in set(excluded) - set(holdout_names(targets))
    )
    skipped.extend((name, f"not_a_teacher:{why}") for name, why in withheld)
    return LooResult(
        outcomes=tuple(outcomes),
        per_slice=_group(outcomes, lambda item: (item.slice,)),
        per_profile=_group(outcomes, lambda item: (item.provenance,)),
        per_mechanism=_group(outcomes, lambda item: item.mechanisms),
        per_obligation_kind=_group(outcomes, lambda item: item.obligations),
        skipped=tuple(skipped),
        teaching_pairs=sum(1 for shapes in lessons.values() if shapes),
        degradations=(*refusals, *_unique_degradations(outcomes)),
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
    labeled_obligations = tuple(sorted({str(row.obligation) for row in case.expected if getattr(row, "obligation", None)}))
    loaded = store.load()
    records = {record.id: record for record in corpus_mechanisms(loaded)}
    obligation_vuln: list[StaticFinding] = []
    obligation_fix: list[StaticFinding] = []
    with tempfile.TemporaryDirectory(prefix="ousast-loo-pair-") as scratch:
        base = root if root is not None else Path(scratch)
        vuln_root = _materialize(base / "vuln", case.vuln_file, case.relpath)
        fix_root = _materialize(base / "fixed", case.fixed_file, case.relpath)
        vuln_search = search_tree(vuln_root, _targets(vuln_root), store, facts, max_mechanisms=len(records) or 1)
        fix_search = search_tree(fix_root, _targets(fix_root), store, facts, max_mechanisms=len(records) or 1)
        vuln_hits, fix_hits = vuln_search.hits, fix_search.hits
        if labeled_obligations:
            shapes = obligation_mechanisms(loaded)
            obligation_vuln = _obligation_findings(vuln_root, shapes)
            obligation_fix = _obligation_findings(fix_root, shapes)
    text = case.vuln_file.read_text(errors="ignore")
    ranges = named_function_ranges(case.relpath, text, _parse_language(case)) or ()
    found: list[tuple[str, tuple[str, ...]]] = []
    for finding in obligation_vuln:
        record = _known_fix_record(finding, records)
        if record is None or finding.line is None or not _inside_label(case, finding.line, ranges):
            continue
        if any(f"obligation:{kind}" in finding.tags for kind in labeled_obligations):
            found.append((record.id, tuple(record.pairs)))
    obligation_leaks = tuple(
        sorted({record.id for finding in obligation_fix if (record := _known_fix_record(finding, records)) is not None})
    )
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
        silent=not fix_hits and not obligation_leaks,
        found_by=tuple(found),
        hits_vuln=len(vuln_hits) + len(obligation_vuln),
        hits_fixed=len(fix_hits) + len(obligation_fix),
        teaches=False,
        leaked_by=tuple(sorted({hit.mechanism_id for hit in fix_hits})) + obligation_leaks,
        degradations=tuple(vuln_search.degradations) + tuple(fix_search.degradations),
        obligations=labeled_obligations,
    )


def _obligation_findings(root: Path, shapes: Sequence[object]) -> list[StaticFinding]:
    """Function-local obligation findings for one materialized side, with the held-out store's obligation shapes as known fixes."""
    from ..config import ObligationsConfig
    from ..mapping import analyze_entry_points
    from .ir import parse_file

    targets = _targets(root)
    irs: dict[str, tuple[object, str]] = {}
    texts: dict[str, str] = {}
    for target in targets:
        try:
            text = (root / target.path).read_text(errors="ignore")
        except OSError:
            continue
        texts[target.path] = text
        irs[target.path] = (parse_file(target.path, text, target.language), text)
    result = check_obligations(
        irs=irs,  # type: ignore[arg-type]
        entries=analyze_entry_points(root, targets),
        facts=load_obligation_facts(),
        flow_facts=_facts(),
        policy=None,
        paths=(),
        dominance=OrderDominance(texts=texts),
        store_shapes=shapes,
        min_siblings=ObligationsConfig().min_siblings,
    )
    return findings_to_static(result)


def _known_fix_record(finding: StaticFinding, records: dict[str, Mechanism]) -> Mechanism | None:
    for tag in finding.tags:
        if tag.startswith("mechanism:"):
            return records.get(tag.split(":", 1)[1])
    return None


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
