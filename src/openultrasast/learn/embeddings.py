"""Code embeddings of excerpts, metered and cached by content (learned-decision-engine design 4.2, Req 3.2).

OpenRouter serves embeddings only (``openai/text-embedding-3-small``, 1,536 dimensions, $0.02 per million input
tokens; ``plane/models/openrouter-embedding.yaml``). Every call goes through
:class:`..plane.budget.MeteredEmbeddingClient`, so a ceiling stops the next batch and a call reporting no tokens is
an error, not a free call. The cache key is the excerpt's sha (the content-addressed blob ``excerpts/<sha>.txt``)
per embedding model: ``embeddings/<model-slug>/<excerpt_sha>.json`` holds ``{model, dimensions, vector (float32,
base64, little-endian), tokens, created}``. An excerpt is embedded once; a rerun makes no call.
"""

from __future__ import annotations

import base64
import json
import math
import re
import struct
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import date
from typing import Any

from ..plane.budget import EmbeddingClient
from ..plane.memory import MemoryStore
from .excerpt import excerpt_sha, normalise

DEFAULT_MODEL = "openai/text-embedding-3-small"
DEFAULT_DIMENSIONS = 1536
INPUT_PER_M = 0.02
CHARS_PER_TOKEN = 4.0  # an estimate for dry runs only; metered runs use the provider's usage


class EmbeddingError(RuntimeError):
    """A provider answer of the wrong shape: a vector count or dimension that is not what was asked."""


def model_slug(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "__", model)


def encode_vector(vector: Sequence[float]) -> str:
    return base64.b64encode(struct.pack(f"<{len(vector)}f", *vector)).decode("ascii")


def decode_vector(text: str) -> list[float]:
    data = base64.b64decode(text)
    return list(struct.unpack(f"<{len(data) // 4}f", data))


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b) or not a:
        raise EmbeddingError(f"cosine of vectors of dimension {len(a)} and {len(b)}")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return dot / norm if norm else 0.0


def estimate_tokens(text: str) -> int:
    return max(1, round(len(text) / CHARS_PER_TOKEN))


class EmbeddingCache:
    """The vectors of one embedding model in the store, by excerpt sha."""

    def __init__(self, store: MemoryStore, model: str = DEFAULT_MODEL) -> None:
        self.store, self.model = store, model
        self.prefix = f"embeddings/{model_slug(model)}"

    def get(self, sha: str) -> list[float] | None:
        data = self.store.get_blob(self.prefix, sha, verify=False)
        if data is None:
            return None
        entry = json.loads(data)
        if entry.get("model") != self.model:
            raise EmbeddingError(f"{self.prefix}/{sha}: stored for model {entry.get('model')!r}, not {self.model!r}")
        return decode_vector(str(entry["vector"]))

    def put(self, sha: str, vector: Sequence[float], *, tokens: int, created: str) -> None:
        entry = {"created": created, "dimensions": len(vector), "model": self.model, "tokens": tokens, "vector": encode_vector(vector)}
        self.store.put_blob(self.prefix, json.dumps(entry, sort_keys=True).encode("utf-8"), name=sha)

    def names(self) -> set[str]:
        return set(self.store.blob_names(self.prefix))


@dataclass
class EmbedReport:
    requested: int = 0
    cached: int = 0
    embedded: int = 0
    missing_excerpt: int = 0
    calls: int = 0
    tokens: int = 0
    estimated_tokens: int = 0
    usd: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def embed_excerpts(
    store: MemoryStore,
    shas: Iterable[str],
    client: EmbeddingClient | None,
    *,
    model: str = DEFAULT_MODEL,
    dimensions: int | None = DEFAULT_DIMENSIONS,
    batch: int = 32,
    created: str | None = None,
) -> EmbedReport:
    """Embed every excerpt in ``shas`` that has no cached vector, in batches. ``client=None`` is a dry run: it counts
    what would be embedded and estimates the tokens (characters / 4), making no call."""
    cache = EmbeddingCache(store, model)
    have = cache.names()
    report = EmbedReport()
    todo: list[tuple[str, str]] = []
    for sha in dict.fromkeys(shas):
        report.requested += 1
        if sha in have:
            report.cached += 1
            continue
        data = store.get_blob("excerpts", sha)
        if data is None:
            report.missing_excerpt += 1
            continue
        text = data.decode("utf-8")
        report.estimated_tokens += estimate_tokens(text)
        todo.append((sha, text))
    if client is None:
        report.usd = report.estimated_tokens * INPUT_PER_M / 1_000_000
        return report
    when = created or date.today().isoformat()
    tokens_before = int(getattr(client, "tokens", 0) or 0)
    for start in range(0, len(todo), batch):
        chunk = todo[start : start + batch]
        seen = int(getattr(client, "tokens", 0) or 0)
        vectors = client.embed(model=model, inputs=[text for _, text in chunk])
        report.calls += 1
        if len(vectors) != len(chunk):
            raise EmbeddingError(f"asked for {len(chunk)} embeddings, the provider returned {len(vectors)}")
        spent = int(getattr(client, "tokens", 0) or 0) - seen
        total_chars = sum(len(text) for _, text in chunk) or 1
        for (sha, text), vector in zip(chunk, vectors, strict=True):
            if dimensions is not None and len(vector) != dimensions:
                raise EmbeddingError(f"embedding of dimension {len(vector)}, declared {dimensions}: the model or route changed")
            cache.put(sha, vector, tokens=round(spent * len(text) / total_chars), created=when)
            report.embedded += 1
    report.tokens = int(getattr(client, "tokens", 0) or 0) - tokens_before
    usd = getattr(client, "usd", None)
    report.usd = float(usd) if isinstance(usd, int | float) else None
    return report


def vector_for(text: str, cache: EmbeddingCache, client: EmbeddingClient | None, *, created: str | None = None) -> list[float] | None:
    """The vector of a candidate's excerpt (cached by its sha), ``None`` without a client and no cached vector."""
    sha = excerpt_sha(text)
    found = cache.get(sha)
    if found is not None or client is None:
        return found
    seen = int(getattr(client, "tokens", 0) or 0)
    vectors = client.embed(model=cache.model, inputs=[normalise(text)])
    if len(vectors) != 1:
        raise EmbeddingError(f"asked for 1 embedding, the provider returned {len(vectors)}")
    spent = int(getattr(client, "tokens", 0) or 0) - seen
    cache.put(sha, vectors[0], tokens=spent, created=created or date.today().isoformat())
    return vectors[0]


__all__ = [
    "DEFAULT_DIMENSIONS", "DEFAULT_MODEL", "EmbedReport", "EmbeddingCache", "EmbeddingError", "cosine", "decode_vector",
    "embed_excerpts", "encode_vector", "estimate_tokens", "model_slug", "vector_for",
]  # fmt: skip
