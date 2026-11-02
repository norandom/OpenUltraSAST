"""Read-only historical validation for the detection-core v1 migration."""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from openultrasast.core.legacy import (
    LEGACY_REPORT_SCHEMA,
    LEGACY_TRACE_SCHEMA,
    LegacyArtifactError,
    decode_legacy_artifact,
    read_legacy_artifact,
)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests/fixtures/detection_core/v1"
TRACE_SHA256 = "93c58ba7c51f11a3173c939e9dcc1eac33334c05a1e066bcc1e4879c4c8de8f0"
REPORT_SHA256 = "e07f10c838b3161040edf05965d1cd1e861023dce36f74f7367dc030b883bcca"


@pytest.mark.parametrize(
    ("name", "digest", "length"),
    (("trace.json", TRACE_SHA256, 401), ("report.json", REPORT_SHA256, 1902)),
)
def test_v1_fixtures_are_nonzero_and_byte_exact(name: str, digest: str, length: int) -> None:
    content = (FIXTURES / name).read_bytes()

    assert len(content) == length, "the historical instrument must read the expected nonzero bytes"
    assert hashlib.sha256(content).hexdigest() == digest


def test_legacy_reader_routes_explicit_trace_and_report_schemas() -> None:
    trace = read_legacy_artifact(FIXTURES / "trace.json", schema_version=LEGACY_TRACE_SCHEMA)
    report = read_legacy_artifact(FIXTURES / "report.json", schema_version=LEGACY_REPORT_SCHEMA)

    assert trace.schema_version == "trace-v1" and trace.byte_length == 401
    assert trace.payload["judgment"] == "unguarded"
    assert report.schema_version == "admission-report-v1" and report.byte_length == 1902
    assert report.payload["decision"] == "NO-GO"
    assert trace.content == (FIXTURES / "trace.json").read_bytes()
    assert report.content == (FIXTURES / "report.json").read_bytes()


def test_legacy_reader_exposes_no_writer_converter_or_baseline_comparison() -> None:
    from openultrasast.core.evidence import EvidenceRecord

    artifact = read_legacy_artifact(FIXTURES / "trace.json", schema_version=LEGACY_TRACE_SCHEMA)

    assert not isinstance(artifact, EvidenceRecord)
    for prohibited in ("write", "to_v2", "decision", "baseline_identity", "compare_identity"):
        assert not hasattr(artifact, prohibited)
    with pytest.raises(AttributeError):
        artifact.content = b"replacement"  # type: ignore[misc]
    changed = artifact.payload
    changed["judgment"] = "discharged"
    assert artifact.payload["judgment"] == "unguarded"


@pytest.mark.parametrize("schema", ("", "trace-v2", "admission-report-v2", "unknown"))
def test_legacy_reader_refuses_unknown_or_v2_schema_routes(schema: str) -> None:
    content = (FIXTURES / "trace.json").read_bytes()

    with pytest.raises(LegacyArtifactError, match="schema"):
        decode_legacy_artifact(content, schema_version=schema)


def test_legacy_reader_refuses_cross_routed_or_embedded_schema_identity() -> None:
    with pytest.raises(LegacyArtifactError):
        decode_legacy_artifact((FIXTURES / "trace.json").read_bytes(), schema_version=LEGACY_REPORT_SCHEMA)
    with pytest.raises(LegacyArtifactError):
        decode_legacy_artifact((FIXTURES / "report.json").read_bytes(), schema_version=LEGACY_TRACE_SCHEMA)
    embedded = {**json.loads((FIXTURES / "trace.json").read_bytes()), "schema_version": LEGACY_TRACE_SCHEMA}
    with pytest.raises(LegacyArtifactError, match="ambiguous"):
        decode_legacy_artifact(json.dumps(embedded).encode(), schema_version=LEGACY_TRACE_SCHEMA)


def test_legacy_reader_refuses_duplicate_json_fields_and_bytes_subclasses() -> None:
    duplicated = b'{"entry":"shadow",' + (FIXTURES / "trace.json").read_bytes()[1:]
    with pytest.raises(LegacyArtifactError, match="duplicate"):
        decode_legacy_artifact(duplicated, schema_version=LEGACY_TRACE_SCHEMA)

    class HostileBytes(bytes):
        def __len__(self) -> int:
            raise AssertionError("subclass methods must not be observed")

    with pytest.raises(LegacyArtifactError, match="exact bytes"):
        decode_legacy_artifact(HostileBytes((FIXTURES / "trace.json").read_bytes()), schema_version=LEGACY_TRACE_SCHEMA)


@pytest.mark.parametrize(
    ("fixture", "schema", "mutation"),
    (
        ("trace.json", "trace-v1", lambda value: {**value, "unknown": True}),
        ("trace.json", "trace-v1", lambda value: {**value, "judgment": "clean"}),
        ("report.json", "admission-report-v1", lambda value: {**value, "decision": "MAYBE"}),
        ("report.json", "admission-report-v1", lambda value: {key: item for key, item in value.items() if key != "manifest"}),
    ),
)
def test_legacy_reader_refuses_open_or_invalid_historical_shapes(
    fixture: str,
    schema: str,
    mutation: Callable[[dict[str, object]], dict[str, object]],
) -> None:
    value = json.loads((FIXTURES / fixture).read_bytes())

    with pytest.raises(LegacyArtifactError):
        decode_legacy_artifact(json.dumps(mutation(value)).encode(), schema_version=schema)


def test_legacy_reader_refuses_empty_or_unreadable_input(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")

    with pytest.raises(LegacyArtifactError, match="nonempty"):
        read_legacy_artifact(empty, schema_version=LEGACY_TRACE_SCHEMA)
    with pytest.raises(LegacyArtifactError, match="readable"):
        read_legacy_artifact(tmp_path / "missing.json", schema_version=LEGACY_TRACE_SCHEMA)


def test_legacy_decoder_has_no_compatibility_or_v2_domain_dependency() -> None:
    path = REPO / "src/openultrasast/core/legacy.py"
    content = path.read_bytes()
    assert content, "the import-boundary instrument must read nonzero decoder bytes"
    tree = ast.parse(content, filename=str(path.relative_to(REPO)))
    modules = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module is not None} | {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    }

    assert "openultrasast.core.legacy_v1" not in modules
    assert "openultrasast.core.evidence" not in modules
    assert modules & {"openultrasast.core.canonical"} == {"openultrasast.core.canonical"}


def test_legacy_reader_is_not_reexported_from_the_public_core_api() -> None:
    import openultrasast.core as core

    assert not ({"LegacyArtifact", "decode_legacy_artifact", "read_legacy_artifact"} & set(core.__all__))
