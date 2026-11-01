"""Installed entry-fact authority and projection-only legacy recognition."""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import cast

from openultrasast.core import canonical, provenance
from openultrasast.mapping.authority_ceremony import (
    INSTALLED_ARTIFACT_STORE_IDENTITY,
    load_installed_authority_ceremony,
    validate_authority_ceremony_bindings,
)
from openultrasast.mapping.fact_authority import (
    EntryFactAuthorityContext,
    authenticate_entry_fact_authority,
)
from openultrasast.mapping.installed_fact_authority import (
    PACK_FILES,
    DigestDirectoryResolver,
    InstalledAuthorityWireError,
    decode_fact_pack_bytes,
    decode_installed_authority_bytes,
)
from openultrasast.semantic.obligations.core_contract import production_access_control_contract

RECOGNITION_PROJECTION_SCHEMA = "openultrasast.entry-recognition-projection.v1"
_PROJECTION_FIELDS = {"schema_version", "facts"}
_ROW_FIELDS = {"legacy_fact_id", "languages", "defines_handler", "handler_kind", "pattern"}
_LANGUAGE_ALIASES = {"js": "javascript", "ts": "typescript"}
_STATE_FILES = (
    "bootstrap.json",
    "identities/generator.json",
    "identities/maintainer-reviewer.json",
    "identities/custodian.json",
    "authority.json",
    *PACK_FILES,
    "express.json",
)
_CACHE_LIMIT = 8
_FileIdentity = tuple[str, int, int, int, int, int, str]
_InstalledState = tuple[_FileIdentity, ...]
_CachedPatterns = tuple[tuple[str, tuple[re.Pattern[str], ...]], ...]
_cache: OrderedDict[str, tuple[_InstalledState, _CachedPatterns]] = OrderedDict()
_cache_lock = Lock()


@dataclass(frozen=True)
class _RecognitionRow:
    legacy_fact_id: str
    languages: tuple[str, ...]
    defines_handler: bool
    handler_kind: str
    pattern: str


class _ProjectionOnlyCustody:
    """Authority authentication port that refuses evaluation-state use."""

    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        raise AssertionError(f"projection loading consumed target custody: {population_digest}")


def _package_root(repo_root: Path | None) -> Path:
    if repo_root is not None:
        return repo_root
    import openultrasast

    return Path(openultrasast.__file__).resolve().parent


def _entries_root(repo_root: Path | None) -> Path:
    return _package_root(repo_root) / "ruleset" / "entries"


def _state_paths(entries: Path) -> tuple[Path, ...]:
    fixed = tuple(entries / relative for relative in _STATE_FILES)
    artifact_root = entries / "artifacts" / "sha256"
    try:
        artifacts = tuple(sorted(path for path in artifact_root.rglob("*") if path.is_file()))
    except OSError as exc:
        raise InstalledAuthorityWireError("installed artifact state is unavailable") from exc
    return (*fixed, *artifacts)


def _file_identity(entries: Path, path: Path) -> _FileIdentity:
    try:
        before = path.lstat()
        content = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise InstalledAuthorityWireError("installed authority state is unavailable") from exc
    before_metadata = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
    after_metadata = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
    if before_metadata != after_metadata:
        raise InstalledAuthorityWireError("installed authority state changed while fingerprinting")
    return (
        path.relative_to(entries).as_posix(),
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        canonical.bytes_digest(content),
    )


def _installed_state(entries: Path) -> _InstalledState:
    paths = _state_paths(entries)
    state = tuple(_file_identity(entries, path) for path in paths)
    if paths != _state_paths(entries):
        raise InstalledAuthorityWireError("installed artifact set changed while fingerprinting")
    return state


def _cached_patterns(entries: Path, state: _InstalledState) -> dict[str, list[re.Pattern[str]]] | None:
    key = str(entries.resolve())
    with _cache_lock:
        cached = _cache.get(key)
        if cached is None or cached[0] != state:
            return None
        _cache.move_to_end(key)
        return {language: list(patterns) for language, patterns in cached[1]}


def _remember_patterns(entries: Path, state: _InstalledState, patterns: dict[str, list[re.Pattern[str]]]) -> None:
    key = str(entries.resolve())
    frozen = tuple((language, tuple(values)) for language, values in sorted(patterns.items()))
    with _cache_lock:
        _cache[key] = (state, frozen)
        _cache.move_to_end(key)
        while len(_cache) > _CACHE_LIMIT:
            _cache.popitem(last=False)


def load_installed_entry_fact_authority(
    custody: provenance.PopulationCustodyPort,
    repo_root: Path | None = None,
) -> EntryFactAuthorityContext:
    """Decode and externally authenticate the closed installed v2 authority.

    ``custody`` remains caller supplied. Authority authentication verifies its port
    shape but deliberately does not read evaluation population state.
    """
    entries = _entries_root(repo_root)
    contract = production_access_control_contract()
    try:
        packs = tuple(decode_fact_pack_bytes((entries / name).read_bytes()) for name in PACK_FILES)
        bundle = decode_installed_authority_bytes((entries / "authority.json").read_bytes(), packs, contract)
    except OSError as exc:
        raise InstalledAuthorityWireError("installed entry authority is unavailable") from exc
    ceremony = load_installed_authority_ceremony(entries)
    validate_authority_ceremony_bindings(ceremony, bundle)
    resolver = DigestDirectoryResolver(entries, INSTALLED_ARTIFACT_STORE_IDENTITY)
    return authenticate_entry_fact_authority(bundle, ceremony.bootstrap, custody, resolver)


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InstalledAuthorityWireError(f"{field} must be nonempty text")
    return value


def _decode_projection(content: bytes) -> tuple[_RecognitionRow, ...]:
    try:
        raw = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstalledAuthorityWireError("recognition projection is not canonical JSON") from exc
    if not isinstance(raw, dict) or set(raw) != _PROJECTION_FIELDS:
        raise InstalledAuthorityWireError("recognition projection has unknown or missing fields")
    if raw.get("schema_version") != RECOGNITION_PROJECTION_SCHEMA:
        raise InstalledAuthorityWireError("recognition projection schema is unknown")
    facts = raw.get("facts")
    if not isinstance(facts, list) or not facts:
        raise InstalledAuthorityWireError("recognition projection facts must be a nonempty list")
    rows: list[_RecognitionRow] = []
    for item in facts:
        if not isinstance(item, dict) or set(item) != _ROW_FIELDS:
            raise InstalledAuthorityWireError("recognition projection row has unknown or missing fields")
        languages = item["languages"]
        if (
            not isinstance(languages, list)
            or not languages
            or not all(isinstance(language, str) and language for language in languages)
            or len(set(languages)) != len(languages)
        ):
            raise InstalledAuthorityWireError("recognition projection languages are invalid")
        defines_handler = item["defines_handler"]
        if not isinstance(defines_handler, bool):
            raise InstalledAuthorityWireError("recognition projection defines_handler must be boolean")
        rows.append(
            _RecognitionRow(
                _text(item["legacy_fact_id"], "legacy_fact_id"),
                tuple(languages),
                defines_handler,
                _text(item["handler_kind"], "handler_kind"),
                _text(item["pattern"], "pattern"),
            )
        )
    record = cast(
        Mapping[str, canonical.JsonValue],
        {
            "schema_version": RECOGNITION_PROJECTION_SCHEMA,
            "facts": tuple(
                {
                    "legacy_fact_id": row.legacy_fact_id,
                    "languages": row.languages,
                    "defines_handler": row.defines_handler,
                    "handler_kind": row.handler_kind,
                    "pattern": row.pattern,
                }
                for row in rows
            ),
        },
    )
    expected = canonical.canonical_record_bytes(record, known_schema_versions=(RECOGNITION_PROJECTION_SCHEMA,))
    if content != expected:
        raise InstalledAuthorityWireError("recognition projection does not round-trip canonically")
    return tuple(rows)


def load_entry_pack_patterns(repo_root: Path | None = None) -> dict[str, list[re.Pattern[str]]]:
    """Return legacy recognition regexes from an authenticated projection only.

    This compatibility API intentionally returns no ``FactPack``, structural
    requirement, relation effect, or readiness value. A projection hit therefore
    cannot be promoted into detection-core evidence.
    """
    entries = _entries_root(repo_root)
    if not entries.is_dir():
        return {}
    state = _installed_state(entries)
    cached = _cached_patterns(entries, state)
    if cached is not None:
        return cached
    context = load_installed_entry_fact_authority(_ProjectionOnlyCustody(), repo_root)
    resolved = context.resolver.resolve(context.bundle.recognition_projection).content
    try:
        installed = (entries / "express.json").read_bytes()
    except OSError as exc:
        raise InstalledAuthorityWireError("installed recognition projection is unavailable") from exc
    if installed != resolved:
        raise InstalledAuthorityWireError("compatibility projection differs from authenticated artifact")
    patterns: dict[str, list[re.Pattern[str]]] = {}
    for row in _decode_projection(installed):
        if row.handler_kind != "route" or not row.defines_handler:
            continue
        for raw_language in row.languages:
            language = _LANGUAGE_ALIASES.get(str(raw_language), str(raw_language))
            patterns.setdefault(language, []).append(re.compile(row.pattern))
    if state != _installed_state(entries):
        raise InstalledAuthorityWireError("installed authority state changed during authentication")
    _remember_patterns(entries, state, patterns)
    return patterns


__all__ = [
    "RECOGNITION_PROJECTION_SCHEMA",
    "load_entry_pack_patterns",
    "load_installed_entry_fact_authority",
]
