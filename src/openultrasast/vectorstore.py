from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .index import VectorIndex, index_reuse_key, query_vector_index, read_vector_index, write_vector_index
from .preprocess import RepoSnapshot


SELECTED_LOCAL_VECTOR_STORE = "json-local"


@dataclass(frozen=True)
class VectorStoreBakeoffResult:
    store: str
    metadata_filtering: bool
    local_persistence: bool
    incremental_keying: bool
    export_import: bool
    retrieval_quality: bool
    selected_default: bool

    @property
    def passed(self) -> bool:
        return all(
            (
                self.metadata_filtering,
                self.local_persistence,
                self.incremental_keying,
                self.export_import,
                self.retrieval_quality,
                self.selected_default,
            )
        )


def bakeoff_json_local(index: VectorIndex, output_path: Path, *, query_embedding: list[float]) -> VectorStoreBakeoffResult:
    write_vector_index(index, output_path)
    loaded = read_vector_index(output_path)
    metadata_matches = query_vector_index(loaded, query_embedding, metadata_filter={"language": "python"}, limit=1)
    unfiltered_matches = query_vector_index(loaded, query_embedding, limit=1)
    snapshot = RepoSnapshot(
        root=loaded.repo_root,
        commit=loaded.repo_commit,
        file_count=len({record.chunk.path for record in loaded.records}),
        languages=_language_counts(loaded),
    )
    result = VectorStoreBakeoffResult(
        store=SELECTED_LOCAL_VECTOR_STORE,
        metadata_filtering=bool(metadata_matches) and metadata_matches[0][1].metadata.get("language") == "python",
        local_persistence=output_path.exists() and output_path.stat().st_size > 0,
        incremental_keying=index_reuse_key(snapshot, loaded.embedding_model) == index_reuse_key(snapshot, loaded.embedding_model),
        export_import=len(loaded.records) == len(index.records) and loaded.embedding_model == index.embedding_model,
        retrieval_quality=bool(unfiltered_matches) and unfiltered_matches[0][0] > 0,
        selected_default=SELECTED_LOCAL_VECTOR_STORE == "json-local",
    )
    return result


def bakeoff_payload(result: VectorStoreBakeoffResult) -> dict[str, object]:
    payload = asdict(result)
    payload["passed"] = result.passed
    return payload


def _language_counts(index: VectorIndex) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in index.records:
        counts[record.chunk.language] = counts.get(record.chunk.language, 0) + 1
    return counts
