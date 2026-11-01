"""Family-neutral acceptance helpers for downstream fact handoffs."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, cast

from openultrasast.core import canonical

SCHEMA = "openultrasast.access-control.entry-fact-conformance.v1"
CORE_ENTRY_POINTS = (
    "openultrasast.core.factapply.apply_fact",
    "openultrasast.core.factmatch.validate_fact_match",
    "openultrasast.core.factpack.validate_fact_pack",
    "openultrasast.core.factvalidate.validate_fact_relations",
)
EXPECTED_CASES = {
    "authority_substitution": ("refused", "match_pack_identity_substituted"),
    "complete": ("passed", None),
    "custody_contamination": ("refused", "protected_population_contamination"),
    "deterministic_replay": ("passed", None),
    "legacy_projection_only": ("refused", "name_only_match"),
    "lineage_omission": ("refused", "matcher_lineage_omitted"),
    "name_only": ("refused", "missing_observation:receiver"),
    "partial": ("refused", "missing_observation:arguments"),
    "producer_reviewer_conflict": ("refused", "self_authored_review_evidence"),
    "resolver_byte_substitution": ("refused", "resolver_byte_substitution"),
}
VALIDATOR_MATRIX = {
    case_id: tuple((name, status, reason) for name in (CORE_ENTRY_POINTS if case_id == "complete" else (validator,)))
    for case_id, (status, reason), validator in (
        ("authority_substitution", EXPECTED_CASES["authority_substitution"], CORE_ENTRY_POINTS[1]),
        ("complete", EXPECTED_CASES["complete"], CORE_ENTRY_POINTS[0]),
        ("custody_contamination", EXPECTED_CASES["custody_contamination"], CORE_ENTRY_POINTS[1]),
        ("deterministic_replay", EXPECTED_CASES["deterministic_replay"], CORE_ENTRY_POINTS[1]),
        ("legacy_projection_only", EXPECTED_CASES["legacy_projection_only"], CORE_ENTRY_POINTS[1]),
        ("lineage_omission", EXPECTED_CASES["lineage_omission"], CORE_ENTRY_POINTS[1]),
        ("name_only", EXPECTED_CASES["name_only"], CORE_ENTRY_POINTS[1]),
        ("partial", EXPECTED_CASES["partial"], CORE_ENTRY_POINTS[1]),
        ("producer_reviewer_conflict", EXPECTED_CASES["producer_reviewer_conflict"], CORE_ENTRY_POINTS[2]),
        ("resolver_byte_substitution", EXPECTED_CASES["resolver_byte_substitution"], CORE_ENTRY_POINTS[1]),
    )
}
DOWNSTREAM_MATRIX = {
    **{case_id: () for case_id in EXPECTED_CASES},
    "authority_substitution": (
        ("openultrasast.mapping.fact_authority.authenticate_entry_fact_authority", "refused", "authority_bundle_digest_substituted"),
    ),
    "producer_reviewer_conflict": (
        ("openultrasast.mapping.fact_authority.authenticate_entry_fact_authority", "refused", "producer_reviewer_conflict"),
    ),
}
TOP_FIELDS = {"schema_version", "handoff_digest", "core_entry_points", "cases"}
CASE_FIELDS = {
    "case_id",
    "fixture_path",
    "fixture_digest",
    "fixture_byte_length",
    "expected_status",
    "reason",
    "artifacts",
    "validators",
    "downstream_validators",
}
ARTIFACT_FIELDS = {"kind", "path", "content_digest", "byte_length"}
VALIDATOR_FIELDS = {"name", "status", "reason"}


def freeze(value: object) -> canonical.JsonValue:
    if isinstance(value, list):
        return tuple(freeze(item) for item in value)
    if isinstance(value, dict):
        return {str(key): freeze(item) for key, item in value.items()}
    return cast(canonical.JsonValue, value)


def relative_path(value: object) -> str:
    assert isinstance(value, str) and value
    path = PurePosixPath(value)
    assert not path.is_absolute() and ".." not in path.parts and path.as_posix() == value
    return value


def read_regular_nofollow(path: Path, kind: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise AssertionError(f"{kind} is unreadable or redirected") from exc
    try:
        mode = os.fstat(fd).st_mode
        assert stat.S_ISREG(mode), f"{kind} is not a regular file"
        assert mode & 0o444, f"{kind} is unreadable"
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        content = b"".join(chunks)
        assert content, f"{kind} is empty"
        return content
    finally:
        os.close(fd)


def require_real_directory(path: Path, kind: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise AssertionError(f"{kind} is redirected or not a directory") from exc
    try:
        assert stat.S_ISDIR(os.fstat(fd).st_mode), f"{kind} is not a real directory"
    finally:
        os.close(fd)


def flat_regular_names(path: Path, kind: str) -> set[str]:
    require_real_directory(path, kind)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with os.scandir(fd) as entries:
            values = tuple(entries)
        assert all(entry.is_file(follow_symlinks=False) and not entry.is_symlink() for entry in values), f"unsafe {kind} entry"
        return {entry.name for entry in values}
    finally:
        os.close(fd)


def validator_rows(value: object, field: str) -> tuple[tuple[object, object, object], ...]:
    assert isinstance(value, list), f"{field} must be an array"
    rows = []
    for item in value:
        assert isinstance(item, dict) and set(item) == VALIDATOR_FIELDS, f"{field} has an open row"
        rows.append((item["name"], item["status"], item["reason"]))
    return tuple(rows)


def validate_case(value: object) -> dict[str, Any]:
    assert isinstance(value, dict) and set(value) == CASE_FIELDS, "case has an open schema"
    case = cast(dict[str, Any], value)
    case_id = case["case_id"]
    assert case_id in EXPECTED_CASES, "unknown case"
    assert (case["expected_status"], case["reason"]) == EXPECTED_CASES[case_id]
    assert validator_rows(case["validators"], "validators") == VALIDATOR_MATRIX[case_id], "validator matrix differs"
    assert validator_rows(case["downstream_validators"], "downstream_validators") == DOWNSTREAM_MATRIX[case_id]
    assert relative_path(case["fixture_path"]).startswith("sources/")
    assert isinstance(case["artifacts"], list) and case["artifacts"]
    for artifact in case["artifacts"]:
        assert isinstance(artifact, dict) and set(artifact) == ARTIFACT_FIELDS
        assert relative_path(artifact["path"]) == f"artifacts/sha256/{artifact['content_digest']}"
        assert isinstance(artifact["byte_length"], int) and artifact["byte_length"] > 0
    return case


def validate_materialized(root: Path, cases: tuple[dict[str, Any], ...]) -> None:
    require_real_directory(root / "sources", "source root")
    declared_sources = {PurePosixPath(case["fixture_path"]).name for case in cases}
    assert flat_regular_names(root / "sources", "source root") == declared_sources, "source census differs"
    require_real_directory(root / "artifacts", "artifact root")
    artifact_root = root / "artifacts" / "sha256"
    declared_artifacts = {PurePosixPath(item["path"]).name for case in cases for item in case["artifacts"]}
    assert flat_regular_names(artifact_root, "artifact root") == declared_artifacts, "artifact census differs"
    for case in cases:
        fixture = read_regular_nofollow(root / case["fixture_path"], "source fixture")
        assert len(fixture) == case["fixture_byte_length"]
        assert canonical.bytes_digest(fixture) == case["fixture_digest"]
        for artifact in case["artifacts"]:
            content = read_regular_nofollow(root / artifact["path"], "artifact")
            assert len(content) == artifact["byte_length"]
            assert canonical.bytes_digest(content) == artifact["content_digest"]


def validate_manifest_bytes(content: bytes, root: Path) -> dict[str, Any]:
    assert content, "manifest is empty"
    value = json.loads(content)
    assert isinstance(value, dict) and set(value) == TOP_FIELDS, "manifest has an open schema"
    manifest = cast(dict[str, Any], value)
    assert canonical.canonical_bytes(freeze(manifest)) == content
    assert manifest["schema_version"] == SCHEMA
    assert tuple(manifest["core_entry_points"]) == CORE_ENTRY_POINTS
    assert isinstance(manifest["cases"], list) and manifest["cases"]
    cases = tuple(validate_case(item) for item in manifest["cases"])
    assert tuple(case["case_id"] for case in cases) == tuple(sorted(EXPECTED_CASES))
    payload = {"schema_version": SCHEMA, "core_entry_points": CORE_ENTRY_POINTS, "cases": tuple(freeze(case) for case in cases)}
    assert canonical.content_digest(payload) == manifest["handoff_digest"]
    validate_materialized(root, cases)
    return manifest


def validated_manifest(root: Path) -> tuple[bytes, dict[str, Any]]:
    content = read_regular_nofollow(root / "manifest.json", "manifest")
    return content, validate_manifest_bytes(content, root)


EXPECTED_REFUSALS = {
    ("authority_substitution", CORE_ENTRY_POINTS[1]): "match pack digest",
    ("lineage_omission", CORE_ENTRY_POINTS[1]): "matcher lineage",
    ("producer_reviewer_conflict", CORE_ENTRY_POINTS[2]): "producer and reviewer",
    ("resolver_byte_substitution", CORE_ENTRY_POINTS[1]): "resolved content digest",
}
MATCH_STABLE_REASONS = {
    "custody_contamination": "protected_population_labels:",
    "legacy_projection_only": "name_only_match",
    "name_only": "missing_observation:receiver",
    "partial": "missing_observation:arguments",
}
ISOLATED_REPLAY_SCRIPT = r"""
import importlib
import importlib.abc
import json
import pathlib
import sys
class BlockTargetImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(('openultrasast.mapping', 'openultrasast.semantic')):
            raise ImportError(f'forbidden target import: {fullname}')
        return None
sys.meta_path.insert(0, BlockTargetImports())
for item in (sys.argv[2], sys.argv[3], sys.argv[4]):
    sys.path.insert(0, item)
consumer = importlib.import_module(sys.argv[5])
root = pathlib.Path(sys.argv[1])
assert len((root / 'manifest.json').read_bytes()) > 0
trace = []
current_case = [None]
refusals = {
    ('authority_substitution', 'openultrasast.core.factmatch.validate_fact_match'): 'match pack digest',
    ('lineage_omission', 'openultrasast.core.factmatch.validate_fact_match'): 'matcher lineage',
    ('producer_reviewer_conflict', 'openultrasast.core.factpack.validate_fact_pack'): 'producer and reviewer',
    ('resolver_byte_substitution', 'openultrasast.core.factmatch.validate_fact_match'): 'resolved content digest',
}
original_run_case = consumer._run_case
def traced_run_case(*args, **kwargs):
    current_case[0] = args[0]
    try:
        return original_run_case(*args, **kwargs)
    finally:
        current_case[0] = None
consumer._run_case = traced_run_case
def success_detail(qualified, result, args):
    case = current_case[0]
    if qualified.endswith('validate_fact_match'):
        reasons = list(result.reasons)
        eligible = case in {'complete', 'deterministic_replay'}
        assert result.effect_eligible is eligible
        stable = {
            'custody_contamination': 'protected_population_labels:',
            'legacy_projection_only': 'name_only_match',
            'name_only': 'missing_observation:receiver',
            'partial': 'missing_observation:arguments',
        }.get(case)
        if stable is not None:
            assert any(reason == stable or reason.startswith(stable) for reason in reasons)
        if eligible:
            assert reasons == []
        return {'effect_eligible': result.effect_eligible, 'reasons': reasons}
    if qualified.endswith('apply_fact'):
        pack, fact_id, _, match_reference = args[:4]
        assert result and len(result) == 1
        for relation in result:
            provenance = relation.provenance
            assert provenance.semantic_pack_digest == pack.normalized_content_digest
            assert provenance.semantic_fact_id == fact_id
            assert provenance.fact_match == match_reference
        return {
            'relation_count': len(result),
            'pack_digest': pack.normalized_content_digest,
            'fact_id': fact_id,
            'match_content_digest': match_reference.content_digest,
        }
    assert result is None
    return {'clean_return': True}
def wrapper(original, qualified):
    def traced(*args, **kwargs):
        case = current_case[0]
        assert case is not None, 'validator ran outside a replay case'
        expected_refusal = refusals.get((case, qualified))
        try:
            result = original(*args, **kwargs)
        except ValueError as exc:
            assert expected_refusal is not None and expected_refusal in str(exc), 'unexpected validator ValueError'
            trace.append({
                'case': case,
                'api': qualified,
                'outcome': 'refused',
                'detail': {'exception': type(exc).__name__, 'message_fragment': expected_refusal},
            })
            raise
        except Exception as exc:
            raise AssertionError(f'unexpected validator failure: {type(exc).__name__}: {exc}') from exc
        assert expected_refusal is None, 'expected validator refusal returned cleanly'
        trace.append({'case': case, 'api': qualified, 'outcome': 'returned', 'detail': success_detail(qualified, result, args)})
        return result
    return traced
for attribute, qualified in (
    ('validate_fact_pack', 'openultrasast.core.factpack.validate_fact_pack'),
    ('validate_fact_match', 'openultrasast.core.factmatch.validate_fact_match'),
    ('apply_fact', 'openultrasast.core.factapply.apply_fact'),
    ('validate_fact_relations', 'openultrasast.core.factvalidate.validate_fact_relations'),
):
    original = getattr(consumer, attribute)
    expected_module, expected_name = qualified.rsplit('.', 1)
    assert (original.__module__, original.__name__) == (expected_module, expected_name)
    setattr(consumer, attribute, wrapper(original, qualified))
results = consumer.replay_all(root)
assert not any(name.startswith(('openultrasast.mapping', 'openultrasast.semantic')) for name in sys.modules)
print(json.dumps({'results': results, 'trace': trace}, sort_keys=True, separators=(',', ':')))
"""


def run_isolated_replay(
    root: Path, tests_root: Path, module: str = "entry_fact_core_consumer", extra_path: Path | None = None
) -> dict[str, Any]:
    extra = tests_root if extra_path is None else extra_path
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            ISOLATED_REPLAY_SCRIPT,
            str(root),
            str(tests_root),
            str(tests_root.parent / "src"),
            str(extra),
            module,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _expected_trace_shape() -> tuple[tuple[str, str, str], ...]:
    complete_order = (CORE_ENTRY_POINTS[2], CORE_ENTRY_POINTS[1], CORE_ENTRY_POINTS[0], CORE_ENTRY_POINTS[3])
    values = []
    for case_id in sorted(EXPECTED_CASES):
        names = complete_order if case_id == "complete" else tuple(row[0] for row in VALIDATOR_MATRIX[case_id])
        for name in names:
            values.append((case_id, name, "refused" if (case_id, name) in EXPECTED_REFUSALS else "returned"))
    return tuple(values)


def verify_replay(replayed: object, trace: object) -> None:
    expected = {case_id: list(result) for case_id, result in EXPECTED_CASES.items()}
    assert replayed == expected, "core replay outcomes differ from the manifest"
    assert isinstance(trace, list)
    actual_shape = tuple((item["case"], item["api"], item["outcome"]) for item in trace)
    assert actual_shape == _expected_trace_shape(), "core API trace differs from the exact replay plan"
    for item in trace:
        detail = item["detail"]
        if item["outcome"] == "refused":
            assert detail["exception"] in {"FactMatchValidationError", "FactPackValidationError"}
            assert detail["message_fragment"] == EXPECTED_REFUSALS[(item["case"], item["api"])]
        elif item["api"] == CORE_ENTRY_POINTS[0]:
            assert detail["relation_count"] == 1
            assert all(detail[key] for key in ("pack_digest", "fact_id", "match_content_digest"))
        elif item["api"] == CORE_ENTRY_POINTS[1]:
            eligible = item["case"] in {"complete", "deterministic_replay"}
            assert detail["effect_eligible"] is eligible
            stable = MATCH_STABLE_REASONS.get(item["case"])
            if stable is not None:
                assert any(reason == stable or reason.startswith(stable) for reason in detail["reasons"])
            if eligible:
                assert detail["reasons"] == []
        elif item["api"] in {CORE_ENTRY_POINTS[2], CORE_ENTRY_POINTS[3]}:
            assert detail == {"clean_return": True}


__all__ = [
    "CORE_ENTRY_POINTS",
    "EXPECTED_CASES",
    "FIXTURE_ROOT",
    "freeze",
    "run_isolated_replay",
    "validate_manifest_bytes",
    "validated_manifest",
    "verify_replay",
]


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "access_control" / "conformance" / "v1"
