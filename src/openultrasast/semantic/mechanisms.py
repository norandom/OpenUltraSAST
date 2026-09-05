"""Append-only mechanism memory. OpenRouter embeddings rank prove budget; never demote."""

from __future__ import annotations

import hashlib
import json
import math
import os
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from ..complexity.map import Hotspot
from ..findings import StaticFinding
from ..index import CodeChunk, EmbeddingClient, VectorIndex, VectorRecord, write_vector_index
from .obligations.shapes import ObligationShape
from .overlay import OverlayRecord
from .variants import Shape

DEFAULT_MECHANISM_LOG = Path(".openultrasast/mechanisms.jsonl")


@dataclass(frozen=True)
class Mechanism:
    id: str
    summary: str
    cwe: str
    language: str
    tags: tuple[str, ...]
    keywords: tuple[str, ...]
    what_made_it_exploitable: str
    source_finding_id: str = ""
    source_repo: str = ""
    # corpus-seeded-mechanisms (additive; old rows load with these defaults)
    origin: str = "sandbox"  # "sandbox" (proven finding) | "corpus" (derived from a trusted pair)
    review_tier: str = ""
    pairs: tuple[str, ...] = ()
    shape: dict[str, object] | None = None  # Shape.to_dict(); None on sandbox rows (not searchable)
    guard: str = "none"
    retracted: bool = False  # tombstone row appended by the improve lever; load() folds the record away


class MechanismStore:
    def __init__(self, log_path: Path, cache_path: Path | None = None) -> None:
        self.log_path = log_path
        self.cache_path = cache_path if cache_path is not None else log_path.with_suffix(".index.json")

    def load(self) -> tuple[Mechanism, ...]:
        if not self.log_path.is_file():
            return ()
        by_id: dict[str, Mechanism] = {}  # append-only log; the latest row for an id is its current state
        for line in self.log_path.read_text().splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            record = _mechanism_from_payload(payload)
            if record.retracted:
                by_id.pop(record.id, None)
            else:
                by_id[record.id] = record
        return tuple(by_id.values())

    def append(self, mechanism: Mechanism) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as handle:
            handle.write(json.dumps(asdict(mechanism), sort_keys=True) + "\n")


def append_mechanism(
    store: MechanismStore,
    *,
    summary: str,
    cwe: str,
    language: str,
    tags: Sequence[str],
    what_made_it_exploitable: str,
    source_finding_id: str = "",
    source_repo: str = "",
    keywords: Sequence[str] = (),
) -> Mechanism:
    mechanism = Mechanism(
        id=str(uuid.uuid4()),
        summary=summary,
        cwe=cwe,
        language=language,
        tags=tuple(tags),
        keywords=tuple(keywords),
        what_made_it_exploitable=what_made_it_exploitable,
        source_finding_id=source_finding_id,
        source_repo=source_repo,
    )
    store.append(mechanism)
    return mechanism


_TIER_RANK = {"seeded": 1, "reviewed": 2}


def corpus_mechanism_id(shape: Shape | ObligationShape) -> str:
    """Deterministic id from the shape key, so the same shape gets the same record on every machine (lever-addressable)."""
    return "corpus:" + hashlib.sha1(shape.key().encode()).hexdigest()[:16]


def append_from_pair(
    store: MechanismStore,
    shape: Shape | ObligationShape,
    *,
    summary: str,
    cwe: str,
    pair: str,
    provenance: str,
    tier: str,
) -> Mechanism:
    """Second writer (Req 1.3, 1.4): one record per shape, ``origin = "corpus"``, provenance lists every pair that taught it."""
    mechanism_id = corpus_mechanism_id(shape)
    existing = next((item for item in store.load() if item.id == mechanism_id), None)
    pairs = tuple(existing.pairs) if existing is not None else ()
    if pair not in pairs:
        pairs = (*pairs, pair)
    if existing is not None and _TIER_RANK.get(existing.review_tier, 0) > _TIER_RANK.get(tier, 0):
        tier = existing.review_tier  # a shape keeps the strongest review it ever had
    inherited = tuple(tag for tag in (existing.tags if existing is not None else ()) if tag.startswith(("provenance:", "tier:")))
    if isinstance(shape, Shape):
        positions = ", ".join(f"arg{p} ({k})" for p, k in zip(shape.source_positions, shape.source_kinds, strict=True))
        exploitable = f"{positions} reaches {shape.sink_name}/{shape.arity}; the fix added {shape.guard}"
        keywords: tuple[str, ...] = (shape.sink_name, shape.guard, *shape.source_kinds)
        guard = shape.guard
    else:  # obligation shape: the discharger the fix carries is the 'guard' the reports show
        exploitable = f"{shape.operation_kind} reached without {shape.discharger_kind}; the fix binds {shape.provenance}"
        keywords = (shape.operation_kind, shape.discharger_kind, shape.provenance, shape.resource_class)
        guard = shape.discharger_kind
    record = Mechanism(
        id=mechanism_id,
        summary=summary,
        cwe=cwe,
        language=shape.language,
        tags=(
            shape.mechanism,
            f"mechanism:{shape.mechanism}",
            f"guard:{guard}",
            *sorted({*inherited, f"provenance:{provenance}", f"tier:{tier}"}),
        ),
        keywords=keywords,
        what_made_it_exploitable=exploitable,
        source_finding_id="",
        source_repo="",
        origin="corpus",
        review_tier=tier,
        pairs=pairs,
        shape=shape.to_dict(),
        guard=guard,
    )
    store.append(record)
    return record


def corpus_mechanisms(records: Sequence[Mechanism]) -> tuple[Mechanism, ...]:
    """Records that variant search may use: corpus origin with a shape."""
    return tuple(item for item in records if item.origin == "corpus" and item.shape is not None)


def order_promotions(
    hotspots: Sequence[Hotspot],
    records: Sequence[OverlayRecord],
    findings: Sequence[StaticFinding],
    *,
    store: MechanismStore | None = None,
    client: EmbeddingClient | None = None,
    model: str | None = None,
) -> tuple[tuple[Hotspot, ...], str | None]:
    """Heuristic order, then optional OpenRouter cosine boost. Never drops a promotion."""
    heuristic = tuple(sorted(hotspots, key=lambda item: (-item.score, item.path, item.function_name or "")))
    if store is None:
        return heuristic, None
    mechanisms = store.load()
    if not mechanisms:
        return heuristic, None
    if client is None or not model:
        return heuristic, "embeddings_unavailable"
    overlay_by_id = {record.proposal_id: record for record in records}
    finding_by_id = {finding.finding_id: finding for finding in findings}
    try:
        ranked = _rank_with_embeddings(heuristic, overlay_by_id, finding_by_id, mechanisms, store, client, model)
    except Exception:
        return heuristic, "embed_failed"
    return ranked, None


def overlay_text(record: OverlayRecord) -> str:
    parts = [record.cwe, record.reason, *record.sources, *record.sinks, *record.sanitizers]
    return " ".join(part for part in parts if part)


def mechanism_text(mechanism: Mechanism) -> str:
    return " ".join(
        part
        for part in (mechanism.summary, mechanism.what_made_it_exploitable, mechanism.cwe, *mechanism.tags, *mechanism.keywords)
        if part
    )


def _rank_with_embeddings(
    hotspots: tuple[Hotspot, ...],
    overlay_by_id: dict[str, OverlayRecord],
    finding_by_id: dict[str, StaticFinding],
    mechanisms: tuple[Mechanism, ...],
    store: MechanismStore,
    client: EmbeddingClient,
    model: str,
) -> tuple[Hotspot, ...]:
    vectors = _mechanism_vectors(mechanisms, store, client, model)
    scored: list[tuple[float, Hotspot]] = []
    for hotspot in hotspots:
        record = _overlay_for_hotspot(hotspot, overlay_by_id)
        finding = _finding_for_hotspot(hotspot, finding_by_id)
        language = record.language if record is not None else ""
        cwe = record.cwe if record is not None else ""
        tags = tuple(finding.tags) if finding is not None else ()
        filtered = [item for item in mechanisms if _hard_filter(item, language, cwe, tags)]
        boost = 0.0
        if record is not None and filtered:
            query = client.embed(model=model, inputs=[overlay_text(record)])[0]
            for mechanism in filtered:
                vector = vectors.get(mechanism.id)
                if vector is None:
                    continue
                boost = max(boost, _cosine(query, vector))
        scored.append((hotspot.score + boost, hotspot))
    scored.sort(key=lambda item: (-item[0], item[1].path, item[1].function_name or ""))
    return tuple(item[1] for item in scored)


def _mechanism_vectors(
    mechanisms: tuple[Mechanism, ...],
    store: MechanismStore,
    client: EmbeddingClient,
    model: str,
) -> dict[str, list[float]]:
    vectors: dict[str, list[float]] = {}
    missing: list[Mechanism] = []
    cached = _read_cache(store.cache_path, model)
    for mechanism in mechanisms:
        key = f"{mechanism.id}:{model}"
        if key in cached:
            vectors[mechanism.id] = cached[key]
        else:
            missing.append(mechanism)
    if missing:
        embeddings = client.embed(model=model, inputs=[mechanism_text(item) for item in missing])
        for mechanism, embedding in zip(missing, embeddings, strict=True):
            vectors[mechanism.id] = embedding
        records = [
            VectorRecord(
                chunk=CodeChunk(
                    chunk_id=f"{mechanism.id}:{model}",
                    namespace="mechanisms",
                    path=mechanism.id,
                    language=mechanism.language or "text",
                    start_line=1,
                    end_line=1,
                    text=mechanism_text(mechanism),
                    metadata={"mechanism_id": mechanism.id, "model": model, "cwe": mechanism.cwe, "language": mechanism.language},
                ),
                embedding=vectors[mechanism.id],
            )
            for mechanism in mechanisms
            if mechanism.id in vectors
        ]
        index = VectorIndex(
            store="json-local",
            embedding_model=model,
            repo_root=str(store.log_path.parent),
            repo_commit=None,
            records=records,
        )
        write_vector_index(index, store.cache_path)
    return vectors


def _read_cache(path: Path, model: str) -> dict[str, list[float]]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    if str(payload.get("embedding_model")) != model:
        return {}
    cached: dict[str, list[float]] = {}
    for item in payload.get("records", []):
        chunk = item.get("chunk", {})
        metadata = chunk.get("metadata", {})
        mechanism_id = str(metadata.get("mechanism_id", ""))
        if mechanism_id:
            cached[f"{mechanism_id}:{model}"] = [float(value) for value in item.get("embedding", [])]
    return cached


def _hard_filter(mechanism: Mechanism, language: str, cwe: str, tags: Sequence[str]) -> bool:
    if mechanism.language and language and mechanism.language != language:
        return False
    if mechanism.cwe and cwe and mechanism.cwe != cwe:
        return False
    tag_ok = not mechanism.tags or not tags or bool(set(mechanism.tags) & set(tags))
    return tag_ok


def _overlay_for_hotspot(hotspot: Hotspot, overlay_by_id: dict[str, OverlayRecord]) -> OverlayRecord | None:
    for finding_id in hotspot.inventory_finding_ids:
        record = overlay_by_id.get(finding_id)
        if record is not None:
            return record
    return None


def _finding_for_hotspot(hotspot: Hotspot, finding_by_id: dict[str, StaticFinding]) -> StaticFinding | None:
    for finding_id in hotspot.inventory_finding_ids:
        finding = finding_by_id.get(finding_id)
        if finding is not None:
            return finding
    return None


def _cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        return 0.0
    numerator = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return numerator / (left_norm * right_norm)


def _mechanism_from_payload(payload: dict[str, object]) -> Mechanism:
    tags = payload.get("tags") or []
    keywords = payload.get("keywords") or []
    pairs = payload.get("pairs") or []
    shape = payload.get("shape")
    if not isinstance(tags, list) or not isinstance(keywords, list) or not isinstance(pairs, list):
        raise ValueError("mechanism tags, keywords and pairs must be lists")
    return Mechanism(
        id=str(payload["id"]),
        summary=str(payload.get("summary", "")),
        cwe=str(payload.get("cwe", "")),
        language=str(payload.get("language", "")),
        tags=tuple(str(item) for item in tags),
        keywords=tuple(str(item) for item in keywords),
        what_made_it_exploitable=str(payload.get("what_made_it_exploitable", "")),
        source_finding_id=str(payload.get("source_finding_id", "")),
        source_repo=str(payload.get("source_repo", "")),
        origin=str(payload.get("origin", "sandbox")),
        review_tier=str(payload.get("review_tier", "")),
        pairs=tuple(str(item) for item in pairs),
        shape=dict(shape) if isinstance(shape, dict) else None,  # validated where it is used (search_tree, the lever)
        guard=str(payload.get("guard", "none")),
        retracted=bool(payload.get("retracted", False)),
    )


def embeddings_configured(model: str | None) -> bool:
    return bool(model) and bool(os.environ.get("OPENROUTER_API_KEY"))
