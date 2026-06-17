import json
from pathlib import Path

import pytest

from openultrasast.index import CodeChunk
from openultrasast.index import (
    build_code_chunks,
    build_retrieval_package,
    build_vector_index,
    chunk_text_namespace,
    index_reuse_key,
    query_vector_index,
    read_vector_index,
    write_vector_index,
)
from openultrasast.preprocess import RepoSnapshot, preprocess_repository
from openultrasast.vectorstore import bakeoff_json_local, bakeoff_payload


class FakeEmbeddingClient:
    def embed(self, *, model: str, inputs: list[str], timeout_seconds: int = 60) -> list[list[float]]:
        return [[float(len(text)), 1.0] for text in inputs]


def test_build_code_chunks_preserves_metadata_filters(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def login(user):\n    return user\n")
    _, targets = preprocess_repository(repo)

    chunks = build_code_chunks(repo, targets, max_lines=1)

    assert len(chunks) == 2
    assert chunks[0].metadata["path"] == "app.py"
    assert chunks[0].metadata["language"] == "python"
    assert chunks[0].start_line == 1


def test_json_vector_index_round_trips_and_filters(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def login(user):\n    return user\n")
    snapshot, targets = preprocess_repository(repo)
    chunks = build_code_chunks(repo, targets)
    index = build_vector_index(snapshot=snapshot, chunks=chunks, embedding_model="openrouter/embed", client=FakeEmbeddingClient())
    output = tmp_path / "index.json"

    write_vector_index(index, output)
    loaded = read_vector_index(output)
    matches = query_vector_index(loaded, [20.0, 1.0], metadata_filter={"language": "python"})

    assert loaded.embedding_model == "openrouter/embed"
    assert matches[0][1].path == "app.py"
    assert json.loads(output.read_text())["store"] == "json-local"


def test_vector_index_rejects_embedding_count_mismatch() -> None:
    class EmptyEmbeddingClient:
        def embed(self, *, model: str, inputs: list[str], timeout_seconds: int = 60) -> list[list[float]]:
            return []

    chunk = CodeChunk(
        chunk_id="chunk-1",
        namespace="repo_code",
        path="app.py",
        language="python",
        start_line=1,
        end_line=1,
        text="print('x')",
        metadata={"path": "app.py", "language": "python"},
    )
    snapshot = RepoSnapshot(root="/repo", commit=None, file_count=0, languages={})
    with pytest.raises(ValueError):
        build_vector_index(snapshot=snapshot, chunks=[chunk], embedding_model="model", client=EmptyEmbeddingClient())


def test_namespace_chunks_and_reuse_key_are_metadata_scoped() -> None:
    chunks = chunk_text_namespace(
        namespace="skills",
        path="semgrep.md",
        text="Use Semgrep for variant mapping.\nKeep provenance.",
        metadata={"language": "markdown", "vulnerability_class": "mapping"},
        max_lines=1,
    )
    snapshot = RepoSnapshot(root="/repo", commit="abc", file_count=1, languages={"python": 1})

    assert len(chunks) == 2
    assert chunks[0].namespace == "skills"
    assert chunks[0].metadata["vulnerability_class"] == "mapping"
    assert index_reuse_key(snapshot, "embed-a") != index_reuse_key(snapshot, "embed-b")


def test_retrieval_package_is_bounded_by_character_budget() -> None:
    chunks = chunk_text_namespace(namespace="docs", path="README.md", text="alpha\n" + "beta" * 100, max_lines=1)
    snapshot = RepoSnapshot(root="/repo", commit=None, file_count=1, languages={"markdown": 1})
    index = build_vector_index(snapshot=snapshot, chunks=chunks, embedding_model="model", client=FakeEmbeddingClient())

    package = build_retrieval_package(role="verifier", index=index, query_embedding=[4.0, 1.0], max_chars=80)

    assert package.role == "verifier"
    assert package.hits
    assert package.truncated is True


def test_json_local_bakeoff_selects_default_store(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def login(user):\n    return user\n")
    snapshot, targets = preprocess_repository(repo)
    chunks = build_code_chunks(repo, targets)
    index = build_vector_index(snapshot=snapshot, chunks=chunks, embedding_model="model", client=FakeEmbeddingClient())

    result = bakeoff_json_local(index, tmp_path / "vector-index.json", query_embedding=[20.0, 1.0])

    assert result.passed is True
    assert bakeoff_payload(result)["selected_default"] is True
