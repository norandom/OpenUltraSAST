import pytest

from openultrasast.index import chunk_text_namespace


def test_namespace_chunks_are_metadata_scoped() -> None:
    chunks = chunk_text_namespace(
        namespace="skills",
        path="semgrep.md",
        text="Use Semgrep for variant mapping.\nKeep provenance.",
        metadata={"language": "markdown", "vulnerability_class": "mapping"},
        max_lines=1,
    )

    assert len(chunks) == 2
    assert chunks[0].namespace == "skills"
    assert chunks[0].language == "markdown"
    assert chunks[0].metadata["vulnerability_class"] == "mapping"
    assert (chunks[0].start_line, chunks[0].end_line) == (1, 1)
    assert chunks[0].chunk_id != chunks[1].chunk_id


def test_blank_blocks_are_skipped_and_the_language_defaults_to_text() -> None:
    chunks = chunk_text_namespace(namespace="docs", path="README.md", text="alpha\n\n\nbeta\n", max_lines=1)

    assert [chunk.text for chunk in chunks] == ["alpha", "beta"]
    assert chunks[0].language == "text"


@pytest.mark.parametrize(("namespace", "max_lines"), [("unknown", 80), ("docs", 0)])
def test_invalid_namespace_or_window_is_rejected(namespace: str, max_lines: int) -> None:
    with pytest.raises(ValueError):
        chunk_text_namespace(namespace=namespace, path="x", text="y", max_lines=max_lines)
