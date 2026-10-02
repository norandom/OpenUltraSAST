"""Text chunking for the skill router (`skills.py`).

The vector index that once lived beside the chunker (`VectorIndex`, `build_vector_index`, `query_vector_index`,
`build_retrieval_package`) and the `ousast index` subcommand that fed it were removed on 2026-10-02: nothing ever
read the `chunks.json` they wrote. The decision engine's embeddings live in `learn/embeddings.py`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

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


def _chunk_id(path: str, start_line: int, end_line: int, text: str) -> str:
    digest = hashlib.sha256(f"{path}:{start_line}:{end_line}:{text}".encode()).hexdigest()[:16]
    return f"{path}:{start_line}-{end_line}:{digest}"
