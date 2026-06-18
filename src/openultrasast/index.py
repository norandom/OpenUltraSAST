from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from .preprocess import FileTarget, RepoSnapshot

VALID_NAMESPACES = {"repo_code", "docs", "static_findings", "mechanisms", "skills", "traces"}


@dataclass(frozen=True)
class CodeChunk:
    chunk_id: str
    namespace: str
    path: str
    language: str
    start_line: int
    end_line: int
    text: str
    metadata: dict[str, str | int | bool]


@dataclass(frozen=True)
class VectorRecord:
    chunk: CodeChunk
    embedding: list[float]


@dataclass(frozen=True)
class VectorIndex:
    store: str
    embedding_model: str
    repo_root: str
    repo_commit: str | None
    records: list[VectorRecord]


@dataclass(frozen=True)
class RetrievalHit:
    score: float
    chunk: CodeChunk


@dataclass(frozen=True)
class RetrievalPackage:
    role: str
    hits: list[RetrievalHit]
    text: str
    truncated: bool


class EmbeddingClient(Protocol):
    def embed(self, *, model: str, inputs: list[str], timeout_seconds: int = 60) -> list[list[float]]:
        raise NotImplementedError


def chunk_file(root: Path, target: FileTarget, *, max_lines: int = 80) -> list[CodeChunk]:
    if max_lines < 1:
        raise ValueError("max_lines must be at least 1")
    text = (root / target.path).read_text(errors="ignore")
    lines = text.splitlines()
    chunks: list[CodeChunk] = []
    for start in range(0, len(lines), max_lines):
        chunk_lines = lines[start : start + max_lines]
        if not any(line.strip() for line in chunk_lines):
            continue
        start_line = start + 1
        end_line = start + len(chunk_lines)
        chunk_text = "\n".join(chunk_lines)
        chunks.append(
            CodeChunk(
                chunk_id=_chunk_id(target.path, start_line, end_line, chunk_text),
                namespace="repo_code",
                path=target.path,
                language=target.language,
                start_line=start_line,
                end_line=end_line,
                text=chunk_text,
                metadata={
                    "path": target.path,
                    "language": target.language,
                    "start_line": start_line,
                    "end_line": end_line,
                    "has_fuzz_entry_point": target.has_fuzz_entry_point,
                    "tags": ",".join(target.tags),
                },
            )
        )
    return chunks


def build_code_chunks(root: Path, targets: list[FileTarget], *, max_lines: int = 80) -> list[CodeChunk]:
    chunks: list[CodeChunk] = []
    for target in targets:
        chunks.extend(chunk_file(root, target, max_lines=max_lines))
    return chunks


def chunk_text_namespace(
    *,
    namespace: str,
    path: str,
    text: str,
    metadata: dict[str, str | int | bool] | None = None,
    max_lines: int = 80,
) -> list[CodeChunk]:
    if namespace not in VALID_NAMESPACES:
        raise ValueError(f"unsupported namespace: {namespace}")
    if max_lines < 1:
        raise ValueError("max_lines must be at least 1")
    lines = text.splitlines()
    chunks: list[CodeChunk] = []
    for start in range(0, len(lines), max_lines):
        chunk_lines = lines[start : start + max_lines]
        if not any(line.strip() for line in chunk_lines):
            continue
        start_line = start + 1
        end_line = start + len(chunk_lines)
        chunk_text = "\n".join(chunk_lines)
        chunk_metadata: dict[str, str | int | bool] = {
            "path": path,
            "namespace": namespace,
            "start_line": start_line,
            "end_line": end_line,
        }
        if metadata:
            chunk_metadata.update({key: value for key, value in metadata.items() if isinstance(value, str | int | bool)})
        chunks.append(
            CodeChunk(
                chunk_id=_chunk_id(f"{namespace}:{path}", start_line, end_line, chunk_text),
                namespace=namespace,
                path=path,
                language=str(chunk_metadata.get("language", "text")),
                start_line=start_line,
                end_line=end_line,
                text=chunk_text,
                metadata=chunk_metadata,
            )
        )
    return chunks


def index_reuse_key(snapshot: RepoSnapshot, embedding_model: str) -> str:
    source = {
        "root": snapshot.root,
        "commit": snapshot.commit,
        "file_count": snapshot.file_count,
        "languages": snapshot.languages,
        "embedding_model": embedding_model,
    }
    return hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()[:24]


def build_vector_index(
    *,
    snapshot: RepoSnapshot,
    chunks: list[CodeChunk],
    embedding_model: str,
    client: EmbeddingClient,
    store: str = "json-local",
    batch_size: int = 32,
) -> VectorIndex:
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    records: list[VectorRecord] = []
    for start in range(0, len(chunks), batch_size):
        batch = chunks[start : start + batch_size]
        vectors = client.embed(model=embedding_model, inputs=[chunk.text for chunk in batch])
        if len(vectors) != len(batch):
            raise ValueError("embedding response count did not match chunk count")
        records.extend(VectorRecord(chunk=chunk, embedding=vector) for chunk, vector in zip(batch, vectors, strict=True))
    return VectorIndex(
        store=store,
        embedding_model=embedding_model,
        repo_root=snapshot.root,
        repo_commit=snapshot.commit,
        records=records,
    )


def write_vector_index(index: VectorIndex, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_index_to_payload(index), indent=2, sort_keys=True) + "\n")


def read_vector_index(path: Path) -> VectorIndex:
    payload = json.loads(path.read_text())
    return VectorIndex(
        store=str(payload["store"]),
        embedding_model=str(payload["embedding_model"]),
        repo_root=str(payload["repo_root"]),
        repo_commit=payload.get("repo_commit"),
        records=[
            VectorRecord(
                chunk=CodeChunk(**item["chunk"]),
                embedding=[float(value) for value in item["embedding"]],
            )
            for item in payload.get("records", [])
        ],
    )


def query_vector_index(
    index: VectorIndex,
    query_embedding: list[float],
    *,
    metadata_filter: dict[str, str | int | bool] | None = None,
    limit: int = 5,
) -> list[tuple[float, CodeChunk]]:
    matches: list[tuple[float, CodeChunk]] = []
    for record in index.records:
        if metadata_filter and not _metadata_matches(record.chunk.metadata, metadata_filter):
            continue
        matches.append((_cosine_similarity(query_embedding, record.embedding), record.chunk))
    return sorted(matches, key=lambda item: item[0], reverse=True)[:limit]


def build_retrieval_package(
    *,
    role: str,
    index: VectorIndex,
    query_embedding: list[float],
    metadata_filter: dict[str, str | int | bool] | None = None,
    limit: int = 5,
    max_chars: int = 4000,
) -> RetrievalPackage:
    hits: list[RetrievalHit] = []
    parts: list[str] = []
    total = 0
    truncated = False
    for score, chunk in query_vector_index(index, query_embedding, metadata_filter=metadata_filter, limit=limit):
        block = f"[{chunk.namespace}] {chunk.path}:{chunk.start_line}-{chunk.end_line}\n{chunk.text}"
        if total + len(block) > max_chars:
            truncated = True
            break
        hits.append(RetrievalHit(score=score, chunk=chunk))
        parts.append(block)
        total += len(block)
    return RetrievalPackage(role=role, hits=hits, text="\n\n".join(parts), truncated=truncated)


def _index_to_payload(index: VectorIndex) -> dict[str, object]:
    return {
        "store": index.store,
        "embedding_model": index.embedding_model,
        "repo_root": index.repo_root,
        "repo_commit": index.repo_commit,
        "records": [{"chunk": asdict(record.chunk), "embedding": record.embedding} for record in index.records],
    }


def _metadata_matches(metadata: dict[str, str | int | bool], expected: dict[str, str | int | bool]) -> bool:
    return all(metadata.get(key) == value for key, value in expected.items())


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        return 0.0
    numerator = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return numerator / (left_norm * right_norm)


def _chunk_id(path: str, start_line: int, end_line: int, text: str) -> str:
    digest = hashlib.sha256(f"{path}:{start_line}:{end_line}:{text}".encode()).hexdigest()[:16]
    return f"{path}:{start_line}-{end_line}:{digest}"
