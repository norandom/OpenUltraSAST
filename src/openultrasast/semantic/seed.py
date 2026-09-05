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
from .ir import parse_file
from .mechanisms import MechanismStore, append_from_pair
from .variants import derive_shape

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
        produced = 0
        for row in case.expected:
            if not row.function or not row.mechanism:
                continue
            shape = derive_shape(
                vuln_ir,
                fixed_ir,
                function=row.function,
                sink=row.sink,
                line=None if row.sink else row.line,
                mechanism=row.mechanism,
                facts=loaded,
                vuln_text=vuln_text,
                fixed_text=fixed_text,
                cwe=row.cwe or None,
            )
            if shape is None:
                continue
            record = append_from_pair(
                store,
                shape,
                summary=f"{shape.mechanism}: {'/'.join(shape.source_kinds)} into {shape.sink_name} ({row.cwe}); fix adds {shape.guard}",
                cwe=row.cwe,
                pair=case.name,
                provenance=case.provenance,
                tier=case.review_tier,
            )
            record_ids.add(record.id)
            produced += 1
        if produced:
            seeded.append(case.name)
        else:
            skipped.append((case.name, "no_labeled_sink_call_site"))
    return ExportReport(
        seeded=len(seeded),
        records=len(record_ids),
        skipped=tuple(skipped),
        degradations=tuple(degradations),
        seeded_pairs=tuple(seeded),
    )


def _skip_reason(case: PairCase) -> str | None:
    if case.review_tier not in GATING_TIERS:
        return f"tier:{case.review_tier}"
    if case.known_limit:
        return f"known_limit:{case.known_limit}"
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
