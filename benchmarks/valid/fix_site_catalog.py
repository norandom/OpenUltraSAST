"""Replacement fix-site candidates anchored only to the security-fix pair."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol

from benchmarks.unseen.extract import Rejected, functions
from benchmarks.valid.reservation_identity import RepositoryNetworkIdentity
from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes, content_digest

FIX_SITE_CANDIDATE_SCHEMA = "openultrasast.valid-detection-benchmark.fix-site-candidate.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


class FixSiteCatalogError(ValueError):
    """Fix-site evidence is absent, ambiguous, or inconsistent."""


class FixSiteReader(Protocol):
    def parents(self, revision: str) -> Sequence[str]: ...

    def blob(self, revision: str, path: str) -> str | None: ...


@dataclass(frozen=True)
class EvidenceRef:
    path: str
    content_digest: str
    byte_length: int


@dataclass(frozen=True)
class PackageEcosystemEvidence:
    ecosystem_hint: str
    manifest: EvidenceRef


@dataclass(frozen=True)
class LicenseEvidence:
    expression: str
    source: EvidenceRef


@dataclass(frozen=True)
class SourceEvidence:
    source_kind: str
    source_locator: str
    evidence_digest: str


@dataclass(frozen=True)
class FixSiteRequest:
    repository: RepositoryNetworkIdentity
    vulnerable_parent: str
    fixed_revision: str
    path: str
    function: str
    observed_language: str
    package_evidence: PackageEcosystemEvidence
    license_evidence: LicenseEvidence
    source_evidence: SourceEvidence
    change_inputs_digest: str


@dataclass(frozen=True)
class FunctionSnapshot:
    revision: str
    path: str
    function: str
    start_line: int
    end_line: int
    byte_length: int
    content_digest: str
    content: str


@dataclass(frozen=True)
class FixSiteCandidateV1:
    canonical_repository: str
    network_identity_digest: str
    observed_language: str
    package_evidence: PackageEcosystemEvidence
    license_evidence: LicenseEvidence
    source_evidence: SourceEvidence
    change_inputs_digest: str
    vulnerable: FunctionSnapshot
    fixed: FunctionSnapshot
    provenance_digest: str
    candidate_digest: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FixSiteCatalogError(f"{field} must be nonempty text")
    return value.strip()


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise FixSiteCatalogError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _revision(value: object, field: str) -> str:
    if not isinstance(value, str) or _REVISION.fullmatch(value) is None:
        raise FixSiteCatalogError(f"{field} must be a full Git object identity")
    return value


def _path(value: object, field: str) -> str:
    text = _text(value, field)
    path = PurePosixPath(text)
    if path.is_absolute() or str(path) != text or any(part in {"", ".", ".."} for part in path.parts):
        raise FixSiteCatalogError(f"{field} must be a canonical repository-relative path")
    return text


def _evidence_value(reference: EvidenceRef) -> dict[str, JsonValue]:
    path = _path(reference.path, "evidence path")
    digest = _digest(reference.content_digest, "evidence content digest")
    if isinstance(reference.byte_length, bool) or not isinstance(reference.byte_length, int) or reference.byte_length <= 0:
        raise FixSiteCatalogError("evidence byte length must be positive")
    return {"path": path, "content_digest": digest, "byte_length": reference.byte_length}


def _package_value(evidence: PackageEcosystemEvidence) -> dict[str, JsonValue]:
    hint = _text(evidence.ecosystem_hint, "package ecosystem hint")
    if hint not in {"python", "javascript", "unresolved"}:
        raise FixSiteCatalogError("package ecosystem hint is unsupported")
    return {"ecosystem_hint": hint, "manifest": _evidence_value(evidence.manifest)}


def _license_value(evidence: LicenseEvidence) -> dict[str, JsonValue]:
    return {"expression": _text(evidence.expression, "license expression"), "source": _evidence_value(evidence.source)}


def _source_value(evidence: SourceEvidence) -> dict[str, JsonValue]:
    return {
        "source_kind": _text(evidence.source_kind, "source evidence kind"),
        "source_locator": _text(evidence.source_locator, "source evidence locator"),
        "evidence_digest": _digest(evidence.evidence_digest, "source evidence digest"),
    }


def _snapshot_value(snapshot: FunctionSnapshot) -> dict[str, JsonValue]:
    if snapshot.start_line <= 0 or snapshot.end_line < snapshot.start_line:
        raise FixSiteCatalogError("function line range is invalid")
    content = _text(snapshot.content, "function content")
    encoded = content.encode("utf-8")
    if snapshot.byte_length != len(encoded) or snapshot.content_digest != bytes_digest(encoded):
        raise FixSiteCatalogError("function byte receipt does not match content")
    return {
        "revision": _revision(snapshot.revision, "function revision"),
        "path": _path(snapshot.path, "function path"),
        "function": _text(snapshot.function, "function name"),
        "start_line": snapshot.start_line,
        "end_line": snapshot.end_line,
        "byte_length": snapshot.byte_length,
        "content_digest": snapshot.content_digest,
        "content": content,
    }


def _provenance_value(candidate: FixSiteCandidateV1) -> dict[str, JsonValue]:
    canonical_repository = _text(candidate.canonical_repository, "canonical repository")
    network_digest = _digest(candidate.network_identity_digest, "repository network identity digest")
    observed_language = _text(candidate.observed_language, "observed language")
    vulnerable = _snapshot_value(candidate.vulnerable)
    fixed = _snapshot_value(candidate.fixed)
    if (candidate.vulnerable.path, candidate.vulnerable.function) != (
        candidate.fixed.path,
        candidate.fixed.function,
    ):
        raise FixSiteCatalogError("fix-site snapshots do not identify the same file and function")
    if candidate.vulnerable.revision == candidate.fixed.revision:
        raise FixSiteCatalogError("fix-site revisions must differ")
    if _LANGUAGE_BY_SUFFIX.get(PurePosixPath(candidate.vulnerable.path).suffix) != observed_language:
        raise FixSiteCatalogError("observed language does not match the fix-site path")
    return {
        "canonical_repository": canonical_repository,
        "network_identity_digest": network_digest,
        "observed_language": observed_language,
        "package_evidence": _package_value(candidate.package_evidence),
        "license_evidence": _license_value(candidate.license_evidence),
        "source_evidence": _source_value(candidate.source_evidence),
        "change_inputs_digest": _digest(candidate.change_inputs_digest, "change inputs digest"),
        "vulnerable": vulnerable,
        "fixed": fixed,
    }


def _candidate_value(candidate: FixSiteCandidateV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value = {"schema_version": FIX_SITE_CANDIDATE_SCHEMA, **_provenance_value(candidate)}
    value["provenance_digest"] = candidate.provenance_digest
    if include_digest:
        value["candidate_digest"] = candidate.candidate_digest
    return value


def _snapshot(reader: FixSiteReader, revision: str, path: str, function: str) -> FunctionSnapshot:
    source = reader.blob(revision, path)
    if source is None:
        raise FixSiteCatalogError("fix-site function is unreadable at the exact revision and path")
    if not source.strip():
        raise FixSiteCatalogError("fix-site source bytes are empty")
    try:
        matches = [span for span in functions(path, source) if span[0] == function]
    except Rejected as error:
        raise FixSiteCatalogError("fix-site function is unreadable") from error
    if not matches:
        raise FixSiteCatalogError("fix-site function is not present at the exact revision and path")
    if len(matches) != 1:
        raise FixSiteCatalogError("fix-site function is ambiguous")
    _, start, end = matches[0]
    content = "\n".join(source.splitlines()[start - 1 : end])
    if not content.strip():
        raise FixSiteCatalogError("fix-site function bytes are empty")
    encoded = content.encode("utf-8")
    return FunctionSnapshot(revision, path, function, start, end, len(encoded), bytes_digest(encoded), content)


def _validate_request(request: FixSiteRequest) -> tuple[str, str, str, str]:
    parent = _revision(request.vulnerable_parent, "vulnerable parent")
    fixed = _revision(request.fixed_revision, "fixed revision")
    if parent == fixed:
        raise FixSiteCatalogError("vulnerable parent and fixed revision must differ")
    path = _path(request.path, "fix-site path")
    function = _text(request.function, "fix-site function")
    language = _text(request.observed_language, "observed language")
    if _LANGUAGE_BY_SUFFIX.get(PurePosixPath(path).suffix) != language:
        raise FixSiteCatalogError("observed language does not match the fix-site path")
    _package_value(request.package_evidence)
    _license_value(request.license_evidence)
    _source_value(request.source_evidence)
    _digest(request.change_inputs_digest, "change inputs digest")
    return parent, fixed, path, function


def build_fix_site_candidate(reader: FixSiteReader, request: FixSiteRequest) -> FixSiteCandidateV1:
    """Build evidence from only the exact fix and its supplied parent."""
    parent, fixed, path, function = _validate_request(request)
    if tuple(reader.parents(fixed)) != (parent,):
        raise FixSiteCatalogError("fixed revision does not have the exact vulnerable parent")
    vulnerable = _snapshot(reader, parent, path, function)
    repaired = _snapshot(reader, fixed, path, function)
    if vulnerable.content_digest == repaired.content_digest:
        raise FixSiteCatalogError("fix-site function is unchanged across the security fix")
    draft = FixSiteCandidateV1(
        request.repository.canonical_repository,
        request.repository.network_identity_digest,
        request.observed_language,
        request.package_evidence,
        request.license_evidence,
        request.source_evidence,
        request.change_inputs_digest,
        vulnerable,
        repaired,
        "",
        "",
    )
    provenance = content_digest(_provenance_value(draft))
    reviewed = FixSiteCandidateV1(**{**vars(draft), "provenance_digest": provenance})
    candidate = FixSiteCandidateV1(
        **{**vars(reviewed), "candidate_digest": content_digest(_candidate_value(reviewed, include_digest=False))}
    )
    fix_site_candidate_bytes(candidate)
    return candidate


def fix_site_candidate_bytes(candidate: FixSiteCandidateV1) -> bytes:
    """Validate and encode a candidate for later independent review."""
    if candidate.provenance_digest != content_digest(_provenance_value(candidate)):
        raise FixSiteCatalogError("fix-site provenance digest does not match")
    if candidate.candidate_digest != content_digest(_candidate_value(candidate, include_digest=False)):
        raise FixSiteCatalogError("fix-site candidate digest does not match")
    return canonical_bytes(_candidate_value(candidate, include_digest=True))


__all__ = [
    "EvidenceRef",
    "FixSiteCandidateV1",
    "FixSiteCatalogError",
    "FixSiteReader",
    "FixSiteRequest",
    "FunctionSnapshot",
    "LicenseEvidence",
    "PackageEcosystemEvidence",
    "SourceEvidence",
    "build_fix_site_candidate",
    "fix_site_candidate_bytes",
]
