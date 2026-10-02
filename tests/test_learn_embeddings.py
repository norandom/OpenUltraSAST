"""Metered embeddings and the cache (learned-decision-engine task 6.2). Every client is scripted: no embedding call
leaves the process."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from test_plane_memory import FakeObjects

from openultrasast.learn.embeddings import (
    EmbeddingCache,
    EmbeddingError,
    cosine,
    decode_vector,
    embed_excerpts,
    encode_vector,
    model_slug,
    vector_for,
)
from openultrasast.learn.excerpt import excerpt_sha
from openultrasast.plane.budget import BudgetExhausted, MeteredEmbeddingClient, UnmeteredUsage
from openultrasast.plane.manifests import load_manifests
from openultrasast.plane.memory import FileStore, MemoryStore, S3Store
from openultrasast.provider.openrouter import parse_embedding_payload

PRICES = {"cache_hit_per_m": 0, "input_per_m": 0.02, "output_per_m": 0}


class ScriptedEmbedder:
    """Answers each input with a 4-dimensional vector from its length; records usage like OpenRouterEmbeddingClient."""

    def __init__(self, *, dims: int = 4, tokens_per_input: int = 100, report_usage: bool = True) -> None:
        self.dims, self.tokens_per_input, self.report_usage = dims, tokens_per_input, report_usage
        self.calls: list[list[str]] = []
        self.usage: list[dict[str, object]] = []

    def embed(self, *, model: str, inputs: list[str], timeout_seconds: int = 60) -> list[list[float]]:
        self.calls.append(list(inputs))
        self.usage.append({"prompt_tokens": self.tokens_per_input * len(inputs)} if self.report_usage else {})
        return [[float(len(text) % 7 + i) for i in range(self.dims)] for text in inputs]


@pytest.fixture(params=["file", "fake-s3-select"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MemoryStore]:
    yield FileStore(tmp_path / "memory") if request.param == "file" else S3Store(FakeObjects("works"), "bucket", "p")


def _excerpts(store: MemoryStore, n: int) -> list[str]:
    return [store.put_blob("excerpts", f"    1  def f{i}():\n    2      return {i}\n".encode()) for i in range(n)]


def test_embedding_cost_is_metered_from_the_provider_usage(store: MemoryStore) -> None:
    shas = _excerpts(store, 5)
    inner = ScriptedEmbedder(dims=4)
    meter = MeteredEmbeddingClient(inner, prices=PRICES, budget_usd=1.0)
    report = embed_excerpts(store, shas, meter, dimensions=4, batch=2, created="2026-10-01")
    assert (report.embedded, report.calls, report.cached) == (5, 3, 0) and len(inner.calls) == 3
    assert report.tokens == 500 and meter.tokens == 500 and report.usd == pytest.approx(500 * 0.02 / 1e6)
    assert meter.summary()["usage"] == {"prompt_tokens": 500}


def test_cache_by_content_hash_makes_a_rerun_free(store: MemoryStore) -> None:
    shas = _excerpts(store, 3)
    inner = ScriptedEmbedder()
    embed_excerpts(store, shas, MeteredEmbeddingClient(inner, prices=PRICES), dimensions=4)
    again = MeteredEmbeddingClient(inner, prices=PRICES)
    report = embed_excerpts(store, shas + shas, again, dimensions=4)
    assert report.cached == 3 and report.embedded == 0 and len(inner.calls) == 1 and again.calls == 0 and again.usd == 0
    cache = EmbeddingCache(store)
    assert cache.prefix == "embeddings/openai__text-embedding-3-small" and cache.names() == set(shas)
    stored = json.loads(store.get_blob(cache.prefix, shas[0], verify=False) or b"{}")
    assert stored["dimensions"] == 4 and stored["model"] == "openai/text-embedding-3-small" and stored["tokens"] == 100


def test_dry_run_estimates_without_a_call(store: MemoryStore) -> None:
    shas = _excerpts(store, 2)
    report = embed_excerpts(store, [*shas, "0" * 64], None)
    assert report.embedded == 0 and report.calls == 0 and report.missing_excerpt == 1 and report.estimated_tokens > 0
    assert report.usd == pytest.approx(report.estimated_tokens * 0.02 / 1e6)


def test_ceiling_stops_the_next_call_and_a_rerun_resumes(store: MemoryStore) -> None:
    shas = _excerpts(store, 4)
    inner = ScriptedEmbedder()
    with pytest.raises(BudgetExhausted):
        embed_excerpts(store, shas, MeteredEmbeddingClient(inner, prices=PRICES, budget_calls=1), dimensions=4, batch=2)
    assert len(EmbeddingCache(store).names()) == 2
    report = embed_excerpts(store, shas, MeteredEmbeddingClient(inner, prices=PRICES), dimensions=4, batch=2)
    assert report.cached == 2 and report.embedded == 2


def test_a_zero_token_answer_is_an_instrument_failure(store: MemoryStore) -> None:
    shas = _excerpts(store, 1)
    with pytest.raises(UnmeteredUsage):
        embed_excerpts(store, shas, MeteredEmbeddingClient(ScriptedEmbedder(report_usage=False), prices=PRICES), dimensions=4)


def test_a_dimension_change_is_refused(store: MemoryStore) -> None:
    shas = _excerpts(store, 1)
    with pytest.raises(EmbeddingError, match="dimension"):
        embed_excerpts(store, shas, MeteredEmbeddingClient(ScriptedEmbedder(dims=3), prices=PRICES), dimensions=4)


def test_candidate_vector_is_cached_by_its_excerpt_sha(store: MemoryStore) -> None:
    inner = ScriptedEmbedder()
    cache = EmbeddingCache(store)
    first = vector_for("def g():\n    pass\n", cache, MeteredEmbeddingClient(inner, prices=PRICES))
    second = vector_for("def g():   \n    pass", cache, MeteredEmbeddingClient(inner, prices=PRICES))
    assert first == second and len(inner.calls) == 1 and cache.names() == {excerpt_sha("def g():\n    pass\n")}
    assert vector_for("other", cache, None) is None


def test_vectors_round_trip_and_cosine() -> None:
    vector = [0.25, -1.5, 3.0]
    assert decode_vector(encode_vector(vector)) == vector
    assert cosine([1, 0], [1, 0]) == 1.0 and cosine([1, 0], [0, 1]) == 0.0
    assert model_slug("openai/text-embedding-3-small") == "openai__text-embedding-3-small"


def test_usage_is_kept_from_the_provider_payload() -> None:
    vectors, usage = parse_embedding_payload({"data": [{"embedding": [1, 2]}], "usage": {"prompt_tokens": 7, "total_tokens": 7}})
    assert vectors == [[1.0, 2.0]] and usage["prompt_tokens"] == 7
    assert parse_embedding_payload({"data": [{"embedding": [1]}]})[1] == {}


def test_the_embedding_model_manifest_prices_input_only() -> None:
    model = load_manifests([Path("plane/models/openrouter-embedding.yaml")]).models["openrouter-embedding"]
    assert model.provider == "openrouter" and model.model == "openai/text-embedding-3-small"
    assert model.parameters["input_per_m"] == 0.02 and model.parameters["output_per_m"] == 0
    assert model.metadata.annotations["openultrasast.io/egress-hosts"] == "openrouter.ai"
