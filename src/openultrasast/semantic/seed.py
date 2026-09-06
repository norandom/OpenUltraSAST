"""Export trusted pairs as mechanism records (corpus-seeded-mechanisms, Req 1).

Only ``seeded`` and ``reviewed`` pairs seed; ``advisory`` and ``title`` pairs, ``known_limit`` pairs, pointer pairs
without a cached excerpt, and excerpts that fail to parse are skipped with a reason. Runs offline over the vendored
catalog; nothing here fetches, and no code text enters the store.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..pairs import GATING_TIERS, PairCase
from ..preprocess import LANGUAGE_BY_EXTENSION
from .facts import FactLoadError, SemanticFacts, load_facts
from .ir import FileIR, parse_file
from .mechanisms import MechanismStore, append_from_pair
from .obligations.facts import ObligationFacts, load_obligation_facts
from .obligations.shapes import ABSENCE_MECHANISMS, ObligationShape, derive_obligation, explain_skip
from .variants import Shape, derive_shape

LANGUAGE_UNSUPPORTED = "variants_language_unsupported"


@dataclass(frozen=True)
class ExportReport:
    seeded: int  # pairs that produced at least one record
    records: int  # distinct records written (deduped by shape)
    skipped: tuple[tuple[str, str], ...] = ()  # (pair, reason)
    degradations: tuple[dict[str, object], ...] = ()
    seeded_pairs: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict[str, object]:
        return {
            "seeded": self.seeded,
            "records": self.records,
            "skipped": [{"pair": pair, "reason": reason} for pair, reason in self.skipped],
            "degradations": list(self.degradations),
            "seeded_pairs": list(self.seeded_pairs),
        }


def export_mechanisms(cases: Sequence[PairCase], store: MechanismStore, *, facts: SemanticFacts | None = None) -> ExportReport:
    """Derive one shape per labeled expected row of every trusted pair and append it to ``store`` (deduped by shape)."""
    loaded = facts if facts is not None else _facts()
    skipped: list[tuple[str, str]] = []
    degradations: list[dict[str, object]] = []
    seeded: list[str] = []
    record_ids: set[str] = set()
    unsupported_languages: set[str] = set()
    for case in cases:  # catalog order; the store lists pairs in the order they taught
        reason = _skip_reason(case)
        if reason is not None:
            skipped.append((case.name, reason))
            continue
        vuln_text = _read(case.vuln_file)
        fixed_text = _read(case.fixed_file)
        language = _parse_language(case)
        vuln_ir = parse_file(case.relpath, vuln_text, language)
        fixed_ir = parse_file(case.relpath, fixed_text, language)
        if not vuln_ir.parse_ok or not fixed_ir.parse_ok:
            bad = vuln_ir if not vuln_ir.parse_ok else fixed_ir
            if bad.reason == "language_unsupported":
                skipped.append((case.name, LANGUAGE_UNSUPPORTED))
                if language not in unsupported_languages:
                    unsupported_languages.add(language)
                    degradations.append({"stage": "mechanisms", "reason": LANGUAGE_UNSUPPORTED, "language": language})
            else:
                skipped.append((case.name, "parse_failed"))
            continue
        if not any(row.function and row.mechanism for row in case.expected):
            skipped.append((case.name, "no_labeled_function"))
            continue
        lessons = pair_lessons(case, loaded, vuln_ir=vuln_ir, fixed_ir=fixed_ir, vuln_text=vuln_text, fixed_text=fixed_text)
        for lesson in lessons:
            record = append_from_pair(
                store,
                lesson.shape,
                summary=lesson.summary,
                cwe=lesson.cwe,
                pair=case.name,
                provenance=case.provenance,
                tier=case.review_tier,
            )
            record_ids.add(record.id)
        if lessons:
            seeded.append(case.name)
        else:
            skipped.append((case.name, _skip_detail(case, vuln_ir, fixed_ir, vuln_text, fixed_text, loaded)))
    return ExportReport(
        seeded=len(seeded),
        records=len(record_ids),
        skipped=tuple(skipped),
        degradations=tuple(degradations),
        seeded_pairs=tuple(seeded),
    )


@dataclass(frozen=True)
class Lesson:
    """One shape a trusted pair teaches, with the CWE and a text-free summary (a sink shape or an obligation shape)."""

    shape: Shape | ObligationShape
    cwe: str
    summary: str


def pair_lessons(
    case: PairCase,
    facts: SemanticFacts,
    *,
    vuln_ir: FileIR | None = None,
    fixed_ir: FileIR | None = None,
    vuln_text: str | None = None,
    fixed_text: str | None = None,
) -> list[Lesson]:
    """Shapes derived from every labeled row of a pair (shared by the exporter and leave-one-out). Empty when a side fails to parse."""
    vuln_text = vuln_text if vuln_text is not None else _read(case.vuln_file)
    fixed_text = fixed_text if fixed_text is not None else _read(case.fixed_file)
    language = _parse_language(case)
    vuln_ir = vuln_ir if vuln_ir is not None else parse_file(case.relpath, vuln_text, language)
    fixed_ir = fixed_ir if fixed_ir is not None else parse_file(case.relpath, fixed_text, language)
    if not vuln_ir.parse_ok or not fixed_ir.parse_ok:
        return []
    lessons: list[Lesson] = []
    for row in case.expected:
        if not row.function or not row.mechanism:
            continue
        obligation_kind = getattr(row, "obligation", None)
        if obligation_kind or row.mechanism in ABSENCE_MECHANISMS:
            obligation = derive_obligation(
                vuln_ir,
                fixed_ir,
                function=row.function,
                obligation=obligation_kind,
                mechanism=row.mechanism,
                facts=_obligation_facts(),
                flow_facts=facts,
                vuln_text=vuln_text,
                fixed_text=fixed_text,
            )
            if obligation is not None:
                summary = (
                    f"{obligation.mechanism}: {obligation.operation_kind} without {obligation.discharger_kind} ({row.cwe}); "
                    f"fix binds {obligation.provenance}"
                )
                lessons.append(Lesson(shape=obligation, cwe=row.cwe, summary=summary))
                continue
            # an absence row that teaches no obligation may still teach a sink shape (a weak literal at a sink, say)
        shape = derive_shape(
            vuln_ir,
            fixed_ir,
            function=row.function,
            sink=row.sink,
            line=row.line,
            mechanism=row.mechanism,
            facts=facts,
            vuln_text=vuln_text,
            fixed_text=fixed_text,
            cwe=row.cwe or None,
        )
        if shape is not None:
            summary = f"{shape.mechanism}: {'/'.join(shape.source_kinds)} into {shape.sink_name} ({row.cwe}); fix adds {shape.guard}"
            lessons.append(Lesson(shape=shape, cwe=row.cwe, summary=summary))
    return lessons


def _skip_detail(case: PairCase, vuln_ir: FileIR, fixed_ir: FileIR, vuln_text: str, fixed_text: str, flow_facts: SemanticFacts) -> str:
    """Why a parsing, labeled pair taught nothing: the obligation derivation's reason for absence rows, else the sink reason."""
    for row in case.expected:
        if row.function and row.mechanism and (getattr(row, "obligation", None) or row.mechanism in ABSENCE_MECHANISMS):
            return explain_skip(
                vuln_ir,
                fixed_ir,
                function=row.function,
                vuln_text=vuln_text,
                fixed_text=fixed_text,
                obligation=getattr(row, "obligation", None),
                facts=_obligation_facts(),
                flow_facts=flow_facts,
            )
    return "no_labeled_sink_call_site"


_OBLIGATION_FACTS: list[ObligationFacts] = []


def _obligation_facts() -> ObligationFacts:
    if not _OBLIGATION_FACTS:
        _OBLIGATION_FACTS.append(load_obligation_facts())
    return _OBLIGATION_FACTS[0]


def _skip_reason(case: PairCase) -> str | None:
    from ..learning.split import is_teacher

    if case.review_tier not in GATING_TIERS:
        return f"tier:{case.review_tier}"
    if case.unscorable or case.known_limit:
        # `PairCase.unscorable` verbatim when the loader computed one, the same string every other path reports:
        # `identical_twin` declared in the catalog and `identical_twin` computed from the bytes are one fact, and
        # calling either of them `split:train` is simply untrue. A case built by hand may carry only the
        # declaration (Req 5.1, 10.3).
        return case.unscorable or f"known_limit:{case.known_limit}"
    if not is_teacher(case) and case.vendored:
        return f"split:{case.split}"
    if not case.vuln_file.is_file() or not case.fixed_file.is_file():
        return "pointer_pair_not_cached" if not case.vendored else "excerpt_missing"
    return None


def _parse_language(case: PairCase) -> str:
    by_ext = LANGUAGE_BY_EXTENSION.get(case.vuln_file.suffix.lower())
    if by_ext:
        return str(by_ext)
    return {"c_cpp": "c"}.get(case.language, case.language)


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return ""


def _facts() -> SemanticFacts:
    try:
        return load_facts()
    except FactLoadError:
        return SemanticFacts(version="", sources=(), sinks=(), sanitizers=())
