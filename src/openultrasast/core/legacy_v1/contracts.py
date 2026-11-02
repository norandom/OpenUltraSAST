"""Closed temporary owner of detection-core v1 contracts and behavior."""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class AdmissionManifestError(ValueError):
    """A legacy admission manifest was refused."""


class FactPackError(ValueError):
    """A legacy fact pack is unreviewed or inconsistent."""


class Judgment(enum.Enum):
    UNGUARDED = "unguarded"
    DISCHARGED = "discharged"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class ProvenClaim:
    trace_id: str
    witness: str
    path: str
    line: int
    family: str


@dataclass(frozen=True)
class BoundedSilence:
    path: str
    reason: str
    coverage: dict[str, Any]


@dataclass(frozen=True)
class Hop:
    function: str
    call_line: int | None
    complete: bool


@dataclass(frozen=True)
class Witness:
    kind: str
    provenance: str
    relation: str


@dataclass(frozen=True)
class Guard:
    kind: str
    effect: str


@dataclass(frozen=True)
class TraceRecord:
    entry: str
    hops: tuple[Hop, ...]
    operation_kind: str
    resource: str
    authority: str
    witnesses: tuple[Witness, ...] = ()
    guards: tuple[Guard, ...] = ()
    completeness_reasons: tuple[str, ...] = ()
    judgment: Judgment = Judgment.INDETERMINATE
    digests: dict[str, str] = field(default_factory=dict)

    def record(self) -> dict[str, Any]:
        from openultrasast.core.legacy_v1 import writer

        return writer.trace_record(self)

    def canonical(self) -> bytes:
        from openultrasast.core.legacy_v1 import writer

        return writer.trace_bytes(self)


@dataclass(frozen=True)
class PushRequest:
    base: str
    head: str
    budget_class: str


@dataclass(frozen=True)
class PushVerdict:
    claims: tuple[ProvenClaim, ...]
    silence: tuple[BoundedSilence, ...]
    digests: dict[str, str]


@dataclass(frozen=True)
class AdmissionManifest:
    produced_by: str
    reviewed: bool
    label_isolated: bool
    spent: bool
    population_role: str
    analyzer_revision: str
    fact_set_digest: str
    acquisition_record_digest: str
    configuration_digest: str
    population_digest: str
    labels: tuple[str, ...]
    families: tuple[str, ...] = ()


@dataclass(frozen=True)
class LegacyFactPack:
    family: str
    facts: tuple[dict[str, Any], ...]
    review_digest: str
    fact_set_digest: str


REPORT_SCHEMA_KEYS = frozenset(
    {
        "manifest",
        "families",
        "pairs",
        "pair_correctness",
        "fix_recall",
        "verified_location_recall",
        "flagged_ordinary_per_100",
        "precision",
        "indeterminate_rate",
        "coverage",
        "runtime",
        "instrument_failures",
        "failed_gates",
        "decision",
    }
)
_REQUIRED_MANIFEST_FIELDS = (
    "produced_by",
    "reviewed",
    "label_isolated",
    "spent",
    "population_role",
    "analyzer_revision",
    "fact_set_digest",
    "acquisition_record_digest",
    "configuration_digest",
    "population_digest",
    "labels",
)
_BENCHMARK_PRODUCER = "valid-detection-benchmark"
_FORBIDDEN_LABEL_MARKERS = ("vulnerability", "fix-location", "ordinary-change")


def as_clean(judgment: Judgment) -> Judgment:
    if judgment is Judgment.INDETERMINATE:
        raise ValueError("indeterminate never converts to a clean judgment")
    return judgment


def consume_verdict(
    request: PushRequest,
    record: TraceRecord,
    claims: Sequence[ProvenClaim],
    silence: Sequence[BoundedSilence],
) -> PushVerdict:
    del request
    for claim in claims:
        if not claim.witness or not claim.path or claim.line <= 0:
            raise ValueError(f"proven claim lacks witness or exact location: {claim}")
    for entry in silence:
        if not entry.reason:
            raise ValueError(f"bounded silence lacks a coverage reason: {entry}")
    return PushVerdict(tuple(claims), tuple(silence), dict(record.digests))


def validate_admission_manifest(
    payload: dict[str, object],
    *,
    expected_acquisition_digest: str | None = None,
) -> AdmissionManifest:
    if not all(field in payload for field in _REQUIRED_MANIFEST_FIELDS):
        raise AdmissionManifestError("malformed: missing required manifest fields")
    if payload["produced_by"] != _BENCHMARK_PRODUCER:
        raise AdmissionManifestError(f"producer: only {_BENCHMARK_PRODUCER} manifests are consumed")
    if payload["reviewed"] is not True:
        raise AdmissionManifestError("unreviewed: manifest lacks external review")
    if payload["label_isolated"] is not True:
        raise AdmissionManifestError("label-isolated: isolation attestation missing")
    raw_labels = payload["labels"]
    if not isinstance(raw_labels, (tuple, list)):
        raise AdmissionManifestError("label-exposure: manifest carries admission labels")
    if any(marker in str(label) for label in raw_labels for marker in _FORBIDDEN_LABEL_MARKERS):
        raise AdmissionManifestError("label-exposure: manifest carries admission labels")
    if expected_acquisition_digest is not None and payload["acquisition_record_digest"] != expected_acquisition_digest:
        raise AdmissionManifestError("acquisition-output-changed: digest mismatch")
    if payload["spent"] is True:
        raise AdmissionManifestError("spent: population already consumed")
    raw_families = payload.get("families", ())
    if not isinstance(raw_families, (tuple, list)):
        raise AdmissionManifestError("malformed: families must be a sequence")
    return _manifest(payload, raw_labels, raw_families)


def _manifest(payload: dict[str, object], labels: Sequence[object], families: Sequence[object]) -> AdmissionManifest:
    return AdmissionManifest(
        produced_by=str(payload["produced_by"]),
        reviewed=True,
        label_isolated=True,
        spent=False,
        population_role=str(payload["population_role"]),
        analyzer_revision=str(payload["analyzer_revision"]),
        fact_set_digest=str(payload["fact_set_digest"]),
        acquisition_record_digest=str(payload["acquisition_record_digest"]),
        configuration_digest=str(payload["configuration_digest"]),
        population_digest=str(payload["population_digest"]),
        labels=tuple(str(label) for label in labels),
        families=tuple(str(family) for family in families),
    )


def validate_report_schema(report: dict[str, Any]) -> None:
    missing = sorted(REPORT_SCHEMA_KEYS - set(report))
    if missing:
        raise AdmissionManifestError(f"report schema: missing keys {missing}")
    for rate_key in (
        "pair_correctness",
        "fix_recall",
        "verified_location_recall",
        "flagged_ordinary_per_100",
        "precision",
        "indeterminate_rate",
    ):
        if not {"n", "count", "rate", "wilson95"} <= set(report[rate_key]):
            raise AdmissionManifestError(f"report schema: {rate_key} lacks n/count/rate/wilson95")


def admit_fact_pack(family: str, facts: Sequence[Mapping[str, Any]], *, review_digest: str) -> LegacyFactPack:
    from openultrasast.core.legacy_v1 import writer

    if not review_digest:
        raise FactPackError("unreviewed fact pack refused: no review digest")
    normalized = tuple(dict(fact) for fact in facts)
    return LegacyFactPack(family, normalized, review_digest, writer.fact_pack_digest(family, normalized))


def verify_fact_pack(pack: LegacyFactPack, facts: Sequence[Mapping[str, Any]]) -> None:
    from openultrasast.core.legacy_v1 import writer

    normalized = tuple(dict(fact) for fact in facts)
    if writer.fact_pack_digest(pack.family, normalized) != pack.fact_set_digest:
        raise FactPackError(f"fact content does not match the stamped digest of pack {pack.family!r}")


def load_pack_file(path: str | Path) -> LegacyFactPack:
    from openultrasast.core.legacy_v1 import writer

    payload = writer.read_json(Path(path))
    review = payload.get("review", {})
    if not isinstance(review, dict):
        raise FactPackError(f"pack {path} lacks a verifiable review attestation")
    note = review.get("note", "")
    if not isinstance(note, str) or not note or review.get("digest") != writer.text_digest(note):
        raise FactPackError(f"pack {path} lacks a verifiable review attestation")
    facts = payload.get("facts")
    if not isinstance(facts, list) or not all(isinstance(fact, dict) for fact in facts):
        raise FactPackError(f"pack {path}: facts must be a list of objects")
    return admit_fact_pack(str(payload.get("family", "")), facts, review_digest=str(review["digest"]))


def admit_pack_file(path: str | Path, *, review_digest: str) -> LegacyFactPack:
    pack = load_pack_file(path)
    if review_digest != pack.review_digest:
        raise FactPackError(f"pack {path}: supplied review digest does not match the embedded attestation")
    return pack


__all__ = [
    "REPORT_SCHEMA_KEYS",
    "AdmissionManifest",
    "AdmissionManifestError",
    "BoundedSilence",
    "FactPackError",
    "Guard",
    "Hop",
    "Judgment",
    "LegacyFactPack",
    "ProvenClaim",
    "PushRequest",
    "PushVerdict",
    "TraceRecord",
    "Witness",
    "admit_fact_pack",
    "admit_pack_file",
    "as_clean",
    "consume_verdict",
    "load_pack_file",
    "validate_admission_manifest",
    "validate_report_schema",
    "verify_fact_pack",
]
