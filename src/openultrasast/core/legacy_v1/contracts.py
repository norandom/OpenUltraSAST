"""Closed temporary owner of detection-core v1 contracts and behavior."""

from __future__ import annotations

import enum
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class AdmissionManifestError(ValueError):
    """A legacy admission manifest was refused."""


class FactPackError(ValueError):
    """A legacy fact pack is unreviewed or inconsistent."""


class InstrumentFailure(ValueError):
    """A legacy run did not read every tracked input."""


class BudgetGateFailure(ValueError):
    """A legacy change exceeded its measured budget."""


class ProvenanceMismatch(ValueError):
    """A legacy recorded digest differs from its re-derived identity."""


class ShortcutDetected(ValueError):
    """A legacy component separates reversed surface shapes."""


class FittedComponentBlocked(ValueError):
    """A legacy fitted component lacks release evidence."""


class ResolutionOutcome(enum.Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNRESOLVED = "unresolved"


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


@dataclass(frozen=True)
class Coverage:
    entry_points: int
    frameworks_recognised: dict[str, int] = field(default_factory=dict)
    calls: int = 0
    complete: int = 0
    incomplete: int = 0
    unresolved: int = 0
    unchecked_reasons: dict[str, int] = field(default_factory=dict)

    def validate(self) -> None:
        buckets = (self.complete, self.incomplete, self.unresolved)
        if min(buckets) < 0:
            raise ValueError(f"negative resolution bucket in {buckets}")
        if sum(buckets) != self.calls:
            raise ValueError(
                f"resolution buckets ({self.complete}+{self.incomplete}+{self.unresolved}) must equal the call count ({self.calls})"
            )


@dataclass(frozen=True)
class Complexity:
    regions: int
    calls: int
    changed_bytes: int


@dataclass(frozen=True)
class Budget:
    workload_class: str
    seconds: float
    n: int
    percentile: float
    hardware: str

    def describe(self) -> str:
        return f"class={self.workload_class} n={self.n} p{int(self.percentile * 100)} hardware={self.hardware} budget={self.seconds:g}s"


@dataclass(frozen=True)
class LegacyProbeResult:
    separated: bool
    fix_score: float
    reversed_score: float


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


_STAMP_FIELDS = (
    "analyzer_revision",
    "fact_set_digest",
    "acquisition_record_digest",
    "configuration_digest",
    "population_digest",
    "input_digest",
)


def check_reads(reads: Mapping[str, int]) -> None:
    zero = sorted(path for path, size in reads.items() if size <= 0)
    if zero:
        raise InstrumentFailure(f"zero-byte read of tracked input: {', '.join(zero)}")


def _quantile(values: list[float], percentile: float) -> float:
    position = (len(values) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    weight = position - lower
    return values[lower] * (1 - weight) + values[upper] * weight


def derive_budget(samples: Sequence[tuple[Complexity, float]], *, workload_class: str, percentile: float, hardware: str) -> Budget:
    if not samples:
        raise ValueError("budget derivation needs at least one measured sample")
    if not 0.0 < percentile < 1.0:
        raise ValueError(f"percentile {percentile} outside (0, 1)")
    seconds = sorted(float(item[1]) for item in samples)
    return Budget(workload_class, _quantile(seconds, percentile), len(samples), percentile, hardware)


def check_budget(change_id: str, seconds: float, budget: Budget) -> None:
    if seconds > budget.seconds:
        raise BudgetGateFailure(f"budget:{change_id}:{seconds:g}s>{budget.seconds:g}s ({budget.describe()})")


def stamp(
    *,
    analyzer_revision: str,
    fact_set_digest: str,
    acquisition_record_digest: str,
    configuration_digest: str,
    population_digest: str,
    change_id: str,
) -> dict[str, str]:
    from openultrasast.core.legacy_v1 import writer

    return {
        "analyzer_revision": analyzer_revision,
        "fact_set_digest": fact_set_digest,
        "acquisition_record_digest": acquisition_record_digest,
        "configuration_digest": configuration_digest,
        "population_digest": population_digest,
        "input_digest": writer.input_digest(change_id, population_digest),
    }


def verify_stamp(recorded: Mapping[str, object], rederived: Mapping[str, object]) -> None:
    for field_name in _STAMP_FIELDS:
        if recorded.get(field_name) != rederived.get(field_name):
            raise ProvenanceMismatch(f"{field_name}: recorded {recorded.get(field_name)!r} != rederived {rederived.get(field_name)!r}")


def reversed_pair_probe(
    score_fn: Callable[[Mapping[str, Any]], float], fix_change: Mapping[str, Any], reversed_change: Mapping[str, Any]
) -> LegacyProbeResult:
    fix_score = float(score_fn(fix_change))
    reversed_score = float(score_fn(reversed_change))
    return LegacyProbeResult(fix_score != reversed_score, fix_score, reversed_score)


def assert_no_shortcut(
    score_fn: Callable[[Mapping[str, Any]], float], fix_change: Mapping[str, Any], reversed_change: Mapping[str, Any]
) -> None:
    result = reversed_pair_probe(score_fn, fix_change, reversed_change)
    if result.separated:
        raise ShortcutDetected(f"shape shortcut: fix={result.fix_score} vs reversed={result.reversed_score}")


def require_admission_evidence(*, holdout_passed: bool, admission_decision: str) -> None:
    if not holdout_passed:
        raise FittedComponentBlocked("fitted component lacks per-repository holdout evidence")
    if admission_decision != "GO":
        raise FittedComponentBlocked(f"fitted component admission decision is {admission_decision!r}, not GO")
