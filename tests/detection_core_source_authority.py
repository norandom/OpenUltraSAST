"""Frozen source authority for detection-core end-to-end fixtures."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import cast

from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import canonical, evidence, provenance

_SCHEMA = "detection-core-source-authority-v1"
_MANIFEST = "source_authority.json"
_HEADER_KEYS = {"schema_version", "repository", "producer_identity", "reviewer_identity", "cases"}
_CASE_KEYS = {"case_id", "path", "content_digest"}
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(frozen=True)
class ReviewedSource:
    case_id: str
    path: str
    content: bytes
    content_digest: str


@dataclass(frozen=True)
class SourceAuthority:
    repository: str
    manifest_content: bytes
    authority_digest: str
    sources: tuple[ReviewedSource, ...]


def bind_source_record(
    value: evidence.EvidenceRecord,
    acquisition_digest: str,
    change_input_digest: str,
) -> evidence.EvidenceRecord:
    stamp = replace(
        value.packet.provenance,
        analyzer_revision=canonical.content_digest("analyzer"),
        acquisition_record_digest=acquisition_digest,
        configuration_digest=canonical.content_digest("configuration"),
        population_digest=canonical.content_digest("population"),
        change_input_digest=change_input_digest,
    )
    packet = replace(value.packet, provenance=stamp)
    decision = replace(value.decision, packet_digest=evidence.derive_packet_digest(packet))
    return evidence.EvidenceRecord(packet, decision, "")


def bind_source_inputs(
    named: provenance.NamedInputs,
    resolver: InMemoryContentResolver,
    authority_content: bytes,
    source: ReviewedSource,
) -> tuple[provenance.NamedInputs, InMemoryContentResolver]:
    artifacts = dict(resolver.artifacts)
    items = []
    replacements = {
        provenance.ProvenanceInputRole.ACQUISITION: authority_content,
        provenance.ProvenanceInputRole.CHANGE_INPUT: source.content,
    }
    for item in named.inputs:
        content = replacements.get(item.role)
        if content is not None:
            reference, replacement = stored_artifact(content, artifact_id=item.content.artifact_id)
            artifacts.update(replacement.artifacts)
            item = replace(item, identity=reference.content_digest, content=reference)
        items.append(item)
    values = tuple(items)
    digest = provenance.derive_named_inputs_digest(values)
    return provenance.NamedInputs(values, digest), InMemoryContentResolver(artifacts)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"source authority {label} must be an object")
    return cast(dict[str, object], value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"source authority {label} must be nonempty text")
    return value


def _canonical_path(value: object) -> str:
    raw = _text(value, "path")
    path = PurePosixPath(raw)
    forbidden = "\x00" in raw or "\\" in raw or any(part in ("", ".", "..") for part in path.parts)
    if path.is_absolute() or path.as_posix() != raw or forbidden:
        raise ValueError(f"source authority path is not canonical: {raw}")
    return raw


@contextmanager
def _repository_descriptor(repository_root: Path) -> Iterator[int]:
    try:
        descriptor = os.open(repository_root, _DIR_FLAGS)
    except (OSError, ValueError) as exc:
        raise ValueError("source authority repository root is unsafe") from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ValueError("source authority repository root is not a directory")
        yield descriptor
    finally:
        os.close(descriptor)


def _open_directory(parent: int, name: str) -> int:
    try:
        descriptor = os.open(name, _DIR_FLAGS, dir_fd=parent)
    except (OSError, ValueError) as exc:
        raise ValueError(f"source authority directory component is unsafe: {name}") from exc
    try:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            return descriptor
        raise ValueError("source authority path component is not a directory")
    except (OSError, ValueError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ValueError(f"source authority directory component is unsafe: {name}") from exc


def _read_regular(root: int, relative: str) -> bytes:
    parts = PurePosixPath(relative).parts
    directory = os.dup(root)
    try:
        for part in parts[:-1]:
            child = _open_directory(directory, part)
            os.close(directory)
            directory = child
        return _read_final_regular(directory, parts[-1], relative)
    finally:
        os.close(directory)


def _read_final_regular(parent: int, name: str, relative: str) -> bytes:
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent)
    except (OSError, ValueError) as exc:
        raise ValueError(f"source authority entry is unsafe: {relative}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"source authority entry is not a regular file: {relative}")
        content = _read_descriptor(descriptor, relative)
        after = os.fstat(descriptor)
        if len(content) != before.st_size or after.st_size != before.st_size:
            raise ValueError(f"source authority entry changed while reading: {relative}")
        return content
    finally:
        os.close(descriptor)


def _read_descriptor(descriptor: int, relative: str) -> bytes:
    chunks: list[bytes] = []
    try:
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
    except OSError as exc:
        raise ValueError(f"source authority entry could not be read: {relative}") from exc
    return b"".join(chunks)


def _read_source(root: int, case: dict[str, object]) -> ReviewedSource:
    if set(case) != _CASE_KEYS:
        raise ValueError("source authority case fields do not match the closed schema")
    case_id = _text(case["case_id"], "case_id")
    relative = _canonical_path(case["path"])
    expected_digest = _text(case["content_digest"], "content_digest")
    content = _read_regular(root, relative)
    if not content:
        raise ValueError(f"source authority input is empty: {case_id}")
    if canonical.bytes_digest(content) != expected_digest:
        raise ValueError(f"source authority content mismatch: {case_id}")
    return ReviewedSource(case_id, relative, content, expected_digest)


def _allowed_directories(files: set[str]) -> set[str]:
    directories: set[str] = set()
    for value in files:
        parts = PurePosixPath(value).parts
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    return directories


def _entry_mode(entry: os.DirEntry[str], relative: str) -> int:
    try:
        return entry.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise ValueError(f"source authority entry cannot be inspected: {relative}") from exc


def _scan_child(parent: int, entry: os.DirEntry[str], relative: str, files: set[str], directories: set[str]) -> set[str]:
    if relative not in directories:
        raise ValueError(f"source authority contains an additional directory: {relative}")
    descriptor = _open_directory(parent, entry.name)
    try:
        return _scan_directory(descriptor, relative, files, directories)
    finally:
        os.close(descriptor)


def _scan_entry(parent: int, entry: os.DirEntry[str], prefix: str, files: set[str], directories: set[str]) -> set[str]:
    relative = f"{prefix}/{entry.name}" if prefix else entry.name
    mode = _entry_mode(entry, relative)
    if stat.S_ISLNK(mode):
        raise ValueError(f"source authority contains a symlink: {relative}")
    if stat.S_ISDIR(mode):
        return _scan_child(parent, entry, relative, files, directories)
    if stat.S_ISREG(mode) and relative in files:
        return {relative}
    kind = "additional file" if stat.S_ISREG(mode) else "special entry"
    raise ValueError(f"source authority contains an {kind}: {relative}")


def _scan_directory(root: int, prefix: str, files: set[str], directories: set[str]) -> set[str]:
    found: set[str] = set()
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                found.update(_scan_entry(root, entry, prefix, files, directories))
    except OSError as exc:
        raise ValueError("source authority repository census failed") from exc
    return found


def _validate_repository_entries(root: int, source_paths: tuple[str, ...]) -> None:
    allowed_files = {_MANIFEST, *source_paths}
    found = _scan_directory(root, "", allowed_files, _allowed_directories(allowed_files))
    if found != allowed_files:
        raise ValueError("source authority entries do not match the exact repository")


def load_source_authority(
    repository_root: Path,
    repository: str,
    expected_cases: tuple[tuple[str, str], ...],
) -> SourceAuthority:
    with _repository_descriptor(repository_root) as root:
        manifest_content = _read_regular(root, _MANIFEST)
        manifest = _validate_manifest(manifest_content, repository)
        cases = _manifest_cases(manifest, expected_cases)
        _validate_repository_entries(root, tuple(path for _, path in expected_cases))
        sources = tuple(_read_source(root, item) for item in cases)
    return SourceAuthority(repository, manifest_content, canonical.bytes_digest(manifest_content), sources)


def _validate_manifest(content: bytes, repository: str) -> dict[str, object]:
    if not content:
        raise ValueError("source authority manifest is empty")
    manifest = _object(json.loads(content), "manifest")
    if set(manifest) != _HEADER_KEYS or manifest.get("schema_version") != _SCHEMA:
        raise ValueError("source authority manifest does not match the closed schema")
    if manifest.get("repository") != repository:
        raise ValueError("source authority repository identity does not match")
    producer = _text(manifest["producer_identity"], "producer_identity")
    reviewer = _text(manifest["reviewer_identity"], "reviewer_identity")
    if producer == reviewer:
        raise ValueError("source authority requires an independent reviewer")
    return manifest


def _manifest_cases(manifest: dict[str, object], expected_cases: tuple[tuple[str, str], ...]) -> tuple[dict[str, object], ...]:
    raw_cases = manifest["cases"]
    if not isinstance(raw_cases, list):
        raise ValueError("source authority cases must be a list")
    cases = tuple(_object(item, "case") for item in raw_cases)
    declared = tuple((_text(item.get("case_id"), "case_id"), _canonical_path(item.get("path"))) for item in cases)
    if declared != expected_cases or len(set(declared)) != len(declared):
        raise ValueError("source authority cases do not match the exact authored cases")
    return cases


__all__ = [
    "ReviewedSource",
    "SourceAuthority",
    "bind_source_inputs",
    "bind_source_record",
    "load_source_authority",
]
