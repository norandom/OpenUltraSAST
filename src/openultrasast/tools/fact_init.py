"""Tasks 11.3 + 11.4: extraction and verified promotion of target knowledge (Reqs 2.9, 2.10).

Extraction mode of the initialization job: the legacy recognition strategies in
``mapping/legacy.py`` and the promoted fact rows in ``ruleset/obligations/*.toml``
are read -- never modified -- and returned as deterministic candidate records
carrying source, version and region evidence.

Verification and promotion (task 11.4): a proposal is verified when its evidence
is complete (source, version, region) and it does not contradict promoted
knowledge. Promotion accepts only verified proposals; contradicted or
evidence-free proposals are rejected with a reason and leave the promoted
corpus unchanged (Req 2.10).

This is a tools module, not an engine module: naming recognition targets here is
legitimate (the whole point is to extract their vocabulary into data).
"""

import hashlib
import json
import re
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

_RECOGNISER_PATTERN = re.compile(
    r"^(def (_[a-z][a-z0-9_]*_entries)\(|def (_python_registered_routes)\(|(_PHP_REGISTRATION) = )",
    re.MULTILINE,
)


@dataclass(frozen=True)
class CandidateRecord:
    """A unit of extracted target knowledge awaiting verification (Req 2.9)."""

    kind: str  # 'operation' | 'discharger' | 'implication' | 'entry-strategy'
    name: str  # fact id or recogniser function/constant name
    source: str  # file the knowledge was read from (relative-style path tail)
    version: str  # sha256[:12] of the source file's bytes
    region: str  # '<file>:<table>:<id>' or 'legacy.py:<symbol>:<start>-<end>'
    payload: tuple[tuple[str, str], ...] = ()  # sorted field pairs


def extract_fact_rows(ruleset_dir: Path) -> tuple[CandidateRecord, ...]:
    """Extract operation, discharger and implication rows as candidates."""
    records: list[CandidateRecord] = []
    for path in sorted(ruleset_dir.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        version = _digest(path)
        records.extend(_row_records(path.name, version, data))
    return tuple(records)


def extract_legacy_strategies(mapping_path: Path) -> tuple[CandidateRecord, ...]:
    """Extract the legacy recogniser inventory (symbol regions) as candidates."""
    text = mapping_path.read_text(encoding="utf-8")
    version = _digest(mapping_path)
    records = [
        CandidateRecord(
            kind="entry-strategy",
            name=symbol,
            source=mapping_path.name,
            version=version,
            region=f"legacy.py:{symbol}:{start}-{end}",
        )
        for symbol, start, end in _symbol_spans(text)
    ]
    return tuple(records)


def extract_all(repo_root: Path) -> tuple[CandidateRecord, ...]:
    """Extract every knowledge source: fact rows and legacy strategies."""
    ruleset_dir = repo_root / "src" / "openultrasast" / "ruleset" / "obligations"
    mapping_path = repo_root / "src" / "openultrasast" / "mapping" / "legacy.py"
    records = [*extract_fact_rows(ruleset_dir), *extract_legacy_strategies(mapping_path)]
    return tuple(sorted(records, key=lambda record: (record.kind, record.name, record.region)))


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def _row_records(file_name: str, version: str, data: dict) -> Iterator[CandidateRecord]:
    tables = (("operation", "operation"), ("discharger", "discharger"), ("implication", "implication"))
    for kind, table in tables:
        for row in data.get(table, []):
            row_id = str(row.get("id", row.get("kind", "")))
            yield CandidateRecord(
                kind=kind,
                name=row_id,
                source=file_name,
                version=version,
                region=f"{file_name}:{table}:{row_id}",
                payload=_payload(row),
            )


def _payload(row: dict) -> tuple[tuple[str, str], ...]:
    pairs = []
    for key, value in row.items():
        if isinstance(value, (list, tuple)):
            pairs.append((key, ",".join(str(item) for item in value)))
        else:
            pairs.append((key, str(value)))
    return tuple(sorted(pairs))


def _symbol_spans(text: str) -> Iterable[tuple[str, int, int]]:
    matches = list(_RECOGNISER_PATTERN.finditer(text))
    lines = text.splitlines()
    for index, match in enumerate(matches):
        symbol = match.group(2) or match.group(3) or match.group(4)
        start = text.count("\n", 0, match.start()) + 1
        end_line = text.count("\n", 0, matches[index + 1].start()) + 1 if index + 1 < len(matches) else len(lines)
        yield symbol, start, end_line - 1


@dataclass(frozen=True)
class PromotionResult:
    """Outcome of promoting a batch of proposals (Reqs 2.9, 2.10)."""

    accepted: tuple[CandidateRecord, ...]
    rejected: tuple[tuple[CandidateRecord, str], ...]  # (record, reason)
    promoted_after: tuple[CandidateRecord, ...]


def verify_candidate(record: CandidateRecord, promoted: tuple[CandidateRecord, ...]) -> tuple[bool, str | None]:
    """Verify one proposal against the promoted corpus.

    Evidence must be complete (source, version, region) and the proposal must not
    contradict promoted knowledge. Rejections carry a reason (Req 2.10).
    """
    if not record.source or not record.region or not re.fullmatch(r"[0-9a-f]{12}", record.version):
        return False, "missing-evidence"
    for existing in promoted:
        if existing.kind == record.kind and existing.name == record.name:
            if existing.payload != record.payload:
                return False, f"contradicts-promoted:{record.kind}:{record.name}"
            return True, None
    return True, None


def promote_proposals(candidates: tuple[CandidateRecord, ...], promoted: tuple[CandidateRecord, ...]) -> PromotionResult:
    """Promote only verified proposals; rejects never modify the corpus (Req 2.10)."""
    accepted: list[CandidateRecord] = []
    rejected: list[tuple[CandidateRecord, str]] = []
    promoted_after = list(promoted)
    for record in candidates:
        is_valid, reason = verify_candidate(record, tuple(promoted_after))
        if not is_valid or reason is not None:
            rejected.append((record, reason or "rejected"))
            continue
        accepted.append(record)
        already_promoted = any(existing.kind == record.kind and existing.name == record.name for existing in promoted_after)
        if not already_promoted:
            promoted_after.append(record)
    return PromotionResult(tuple(accepted), tuple(rejected), tuple(promoted_after))


__all__ = [
    "AcquisitionRecord",
    "AdmissionLabelsExposed",
    "CandidateRecord",
    "PromotionResult",
    "acquire",
    "development_acquisition",
    "engine_purity_of",
    "extract_all",
    "extract_fact_rows",
    "extract_legacy_strategies",
    "population_is_spent",
    "promote_proposals",
    "verify_candidate",
]


class AdmissionLabelsExposed(ValueError):
    """Raised when acquisition input carries admission evaluation labels (Req 12.2)."""


FORBIDDEN_LABEL_MARKERS: tuple[str, ...] = ("vulnerability", "fix-location", "ordinary-change")


@dataclass(frozen=True)
class AcquisitionRecord:
    """Provenance record of one acquisition pass (Req 12.1)."""

    input_revision: str
    evidence_digest: str
    accepted_names: tuple[str, ...]
    rejected_names: tuple[str, ...]
    output_digest: str


def _corpus_digest(records: tuple[CandidateRecord, ...]) -> str:
    lines = sorted(
        f"{record.kind}\x1f{record.name}\x1f{record.source}\x1f{record.version}\x1f{record.region}\x1f{record.payload}"
        for record in records
    )
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()[:12]


def acquire(
    candidates: tuple[CandidateRecord, ...],
    promoted: tuple[CandidateRecord, ...],
    *,
    input_labels: tuple[str, ...] = (),
) -> AcquisitionRecord:
    """Run one label-isolated acquisition pass (Reqs 12.1, 12.2).

    The label guard runs first: an input carrying admission evaluation labels is
    rejected before any promotion happens, leaving the promoted corpus untouched.
    """
    for label in input_labels:
        if any(marker in label for marker in FORBIDDEN_LABEL_MARKERS):
            raise AdmissionLabelsExposed(label)
    result = promote_proposals(candidates, promoted)
    return AcquisitionRecord(
        input_revision=_corpus_digest(promoted),
        evidence_digest=_corpus_digest(candidates),
        accepted_names=tuple(sorted(record.name for record in result.accepted)),
        rejected_names=tuple(sorted(record.name for record, _ in result.rejected)),
        output_digest=_corpus_digest(result.promoted_after),
    )


def population_is_spent(blind_record: AcquisitionRecord, later_output_digest: str) -> bool:
    """A changed acquisition output after labels opened spends the population (Req 12.3)."""
    return later_output_digest != blind_record.output_digest


def engine_purity_of(candidates: tuple[CandidateRecord, ...]) -> tuple[str, ...]:
    """Return candidate sources that live inside engine modules (task 11.7).

    Engine modules must stay free of target knowledge; a candidate sourced from
    ``src/openultrasast/semantic/`` would mean target vocabulary leaked into the
    engine, so the development acquisition refuses to run over such a corpus.
    """
    return tuple(sorted({record.source for record in candidates if record.source.startswith("src/openultrasast/semantic/")}))


def development_acquisition(
    repo_root: Path,
    *,
    artifact_dir: Path | None = None,
    input_labels: tuple[str, ...] = (),
) -> tuple[AcquisitionRecord, Path]:
    """Run the first label-blind development acquisition (tasks 11.7, Reqs 5.7, 12.9).

    Candidates come from extraction only (repository code and the promoted
    ruleset -- never pool labels, never generated content). The pass runs
    through the verification gate; the artifact is written only after the gate
    returns, so a label-guard rejection leaves the artifact directory empty.
    """
    candidates = extract_all(repo_root)
    impure_sources = engine_purity_of(candidates)
    if impure_sources:
        raise ValueError(f"engine modules carry target knowledge: {impure_sources}")
    promoted = extract_fact_rows(repo_root / "src" / "openultrasast" / "ruleset" / "obligations")
    record = acquire(candidates, promoted, input_labels=input_labels)
    result = promote_proposals(candidates, promoted)
    artifact_path = (artifact_dir or repo_root / ".acquisition") / (f"development-{record.output_digest[:6]}.json")
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_by": "fact_init.development_acquisition",
        "label_blind": True,
        "record": asdict(record),
        "accepted": [
            {
                "kind": candidate.kind,
                "name": candidate.name,
                "source": candidate.source,
                "version": candidate.version,
                "region": candidate.region,
            }
            for candidate in result.accepted
        ],
        "rejected": [{"name": candidate.name, "reason": reason} for candidate, reason in result.rejected],
    }
    artifact_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return record, artifact_path
