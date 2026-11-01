"""Installed reviewed entry-pack migration and legacy recognition wiring."""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core import canonical, provenance, semantics  # noqa: E402
from openultrasast.core.factpack import (  # noqa: E402
    StructuralRequirementKind,
    validate_fact_pack,
)
from openultrasast.mapping import entry_packs as entry_pack_module  # noqa: E402
from openultrasast.mapping.entry_packs import (  # noqa: E402
    load_entry_pack_patterns,
    load_installed_entry_fact_authority,
)
from openultrasast.mapping.fact_authority import (  # noqa: E402
    EntryFactAuthorityContext,
    EntryFactAuthorityError,
)
from openultrasast.mapping.installed_fact_authority import (  # noqa: E402
    InstalledAuthorityWireError,
    decode_fact_pack_bytes,
)
from openultrasast.mapping.legacy import _js_entry_points, analyze_entry_points, entry_framework  # noqa: E402
from openultrasast.preprocess import FileTarget, detect_language  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
ENTRIES = REPO / "src" / "openultrasast" / "ruleset" / "entries"

TS_SOURCE = """import express from "express";
const app = express();
app.all("/admin", adminHandler);
function adminHandler(req, res) { res.send("ok"); }
"""

_LEGACY_ROWS = (
    (
        "entry:express:app-route",
        True,
        "route",
        r"app.(get|post|put|delete|patch|all|use)\s*\(",
    ),
    (
        "entry:express:router-route",
        True,
        "route",
        r"router.(get|post|put|delete|patch|all|use)\s*\(",
    ),
    ("entry:express:express-app", False, "app", r"express\s*\(\s*\)"),
)


class _UnusedCustody:
    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        raise AssertionError(f"authority authentication read target custody: {population_digest}")


class _InstalledCustody:
    def __init__(self, logs: dict[str, provenance.PopulationCustodyLog]) -> None:
        self._logs = logs

    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        return self._logs[population_digest]


def _custody_for_installed_lineages(
    lineages: tuple[provenance.LineageManifest, ...],
    policy: provenance.PopulationCustodyPolicy,
) -> _InstalledCustody:
    custodian = policy.reviewed_custodian_digests[0]
    logs: dict[str, provenance.PopulationCustodyLog] = {}
    for lineage in lineages:
        for use in lineage.uses:
            prior = logs.setdefault(
                use.source_population_digest,
                provenance.empty_population_custody_log(use.source_population_digest, custodian),
            )
            request = provenance.PopulationUseRequest(
                use.source_population_digest,
                lineage.arm_id,
                use.purpose,
                use.labels_accessed,
                use.influenced_artifact_digest,
                prior.log_digest,
            )
            receipt = provenance.record_population_use(request, prior, custodian, policy)
            assert receipt.receipt_digest == use.population_use_receipt_digest
            logs[use.source_population_digest] = provenance.append_population_use(prior, receipt, policy)
    return _InstalledCustody(logs)


def _target(root: Path, name: str, text: str) -> FileTarget:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return FileTarget(name, str(path), detect_language(path), 5, [], False, [], [])


def _stage_entries(root: Path) -> Path:
    staged = root / "ruleset" / "entries"
    shutil.copytree(ENTRIES, staged)
    return staged


def test_pack_patterns_loaded_for_typescript() -> None:
    patterns = load_entry_pack_patterns()
    assert patterns.get("typescript") and any(p.search("app.all(") for p in patterns["typescript"])


def test_installed_v2_packs_authenticate_and_validate_from_a_proven_legacy_input() -> None:
    context = load_installed_entry_fact_authority(_UnusedCustody())
    bundle = context.bundle
    legacy_reference = bundle.packs[0].review_evidence[0].content
    legacy_artifact = REPO / "src" / "openultrasast" / "ruleset" / "entries" / "artifacts" / "sha256" / legacy_reference.content_digest

    legacy_bytes = legacy_artifact.read_bytes()
    assert legacy_artifact.stat().st_size == 963
    assert len(legacy_bytes) == 963
    assert canonical.bytes_digest(legacy_bytes) == legacy_reference.content_digest

    assert tuple(pack.language for pack in bundle.packs) == ("javascript", "typescript")
    custody = _custody_for_installed_lineages(bundle.lineages, bundle.custody_policy)
    for pack in bundle.packs:
        validate_fact_pack(
            pack,
            bundle.contract,
            None,
            bundle.lineages,
            custody,
            bundle.custody_policy,
            bundle.review_policy,
            context.resolver,
        )


def test_reviewed_pack_mapping_is_exact_and_language_scoped() -> None:
    bundle = load_installed_entry_fact_authority(_UnusedCustody()).bundle
    methods = ("get", "post", "put", "delete", "patch", "all", "use")

    for pack in bundle.packs:
        facts = {fact.fact_id: fact for fact in pack.facts}
        assert set(facts) == {
            *(f"entry:express:app-route:{method}" for method in methods),
            *(f"entry:express:router-route:{method}" for method in methods),
            "entry:express:express-app",
        }
        for receiver_name, receiver_type in (("app", "express_application"), ("router", "express_router")):
            for method in methods:
                fact = facts[f"entry:express:{receiver_name}-route:{method}"]
                assert fact.role == "entry_registration"
                assert tuple((item.requirement_id, item.kind, item.field, item.expected) for item in fact.structural_requirements) == (
                    ("qualified_target", StructuralRequirementKind.QUALIFIED_NAME, "qualified_target", f"{receiver_name}.{method}"),
                    ("call_shape", StructuralRequirementKind.AST_SHAPE, "call_shape", "member_call"),
                    ("receiver", StructuralRequirementKind.RECEIVER_TYPE, "receiver", receiver_type),
                    ("arguments", StructuralRequirementKind.ARGUMENT_SHAPE, "arguments", "route_path_and_handler"),
                )
                assert tuple(
                    (effect.kind, effect.role, effect.source_role, effect.target_role, effect.conditions)
                    for effect in fact.relation_effects
                ) == ((semantics.RelationKind.REGISTRATION, "entry_registration", "framework_instance", "entry_handler", ()),)
        app = facts["entry:express:express-app"]
        assert app.role == "framework_instance"
        assert tuple((item.requirement_id, item.kind, item.field, item.expected) for item in app.structural_requirements) == (
            ("qualified_target", StructuralRequirementKind.QUALIFIED_NAME, "qualified_target", "express"),
            ("call_shape", StructuralRequirementKind.AST_SHAPE, "call_shape", "factory_call"),
            ("binding", StructuralRequirementKind.ARGUMENT_SHAPE, "binding", "application_instance_binding"),
        )
        assert tuple(
            (effect.kind, effect.role, effect.source_role, effect.target_role, effect.conditions) for effect in app.relation_effects
        ) == ((semantics.RelationKind.REGISTRATION, "framework_instance", "framework_factory", "framework_instance", ()),)


def test_projection_preserves_legacy_rows_but_is_not_a_fact_pack() -> None:
    projection_path = REPO / "src" / "openultrasast" / "ruleset" / "entries" / "express.json"
    content = projection_path.read_bytes()
    raw = json.loads(content)

    assert content == json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    assert raw["schema_version"] == "openultrasast.entry-recognition-projection.v1"
    assert (
        tuple(
            (
                row["legacy_fact_id"],
                row["defines_handler"],
                row["handler_kind"],
                row["pattern"],
            )
            for row in raw["facts"]
        )
        == _LEGACY_ROWS
    )
    assert all(set(row) == {"legacy_fact_id", "languages", "defines_handler", "handler_kind", "pattern"} for row in raw["facts"])
    with pytest.raises(InstalledAuthorityWireError):
        decode_fact_pack_bytes(content)


def test_repeated_pattern_load_reuses_fully_authenticated_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stage_entries(tmp_path)
    entry_pack_module._cache.clear()
    authenticates = 0
    real_load = entry_pack_module.load_installed_entry_fact_authority

    def counted_load(
        custody: provenance.PopulationCustodyPort,
        repo_root: Path | None = None,
    ) -> EntryFactAuthorityContext:
        nonlocal authenticates
        authenticates += 1
        return real_load(custody, repo_root)

    monkeypatch.setattr(entry_pack_module, "load_installed_entry_fact_authority", counted_load)

    first = load_entry_pack_patterns(tmp_path)
    second = load_entry_pack_patterns(tmp_path)

    assert authenticates == 1
    assert first is not second
    assert tuple(pattern.pattern for pattern in first["javascript"]) == tuple(pattern.pattern for pattern in second["javascript"])


@pytest.mark.parametrize(
    "relative_path",
    (
        "bootstrap.json",
        "identities/generator.json",
        "authority.json",
        "express.javascript.v2.json",
        "express.json",
        "artifacts/sha256/529d18ba2b351a8de985a9cf416261d717ef55a4b7a9d9d65bce53b97d59ab35",
    ),
)
def test_pattern_cache_invalidates_for_every_authority_state_class(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    entries = _stage_entries(tmp_path)
    entry_pack_module._cache.clear()
    authenticates = 0
    real_load = entry_pack_module.load_installed_entry_fact_authority

    def counted_load(
        custody: provenance.PopulationCustodyPort,
        repo_root: Path | None = None,
    ) -> EntryFactAuthorityContext:
        nonlocal authenticates
        authenticates += 1
        return real_load(custody, repo_root)

    monkeypatch.setattr(entry_pack_module, "load_installed_entry_fact_authority", counted_load)
    load_entry_pack_patterns(tmp_path)
    changed = entries / relative_path
    stat = changed.stat()
    os.utime(changed, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))

    load_entry_pack_patterns(tmp_path)

    assert authenticates == 2


def test_pattern_cache_fingerprints_content_even_when_size_and_mtime_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = _stage_entries(tmp_path)
    entry_pack_module._cache.clear()
    authenticates = 0
    real_load = entry_pack_module.load_installed_entry_fact_authority

    def counted_load(
        custody: provenance.PopulationCustodyPort,
        repo_root: Path | None = None,
    ) -> EntryFactAuthorityContext:
        nonlocal authenticates
        authenticates += 1
        return real_load(custody, repo_root)

    monkeypatch.setattr(entry_pack_module, "load_installed_entry_fact_authority", counted_load)
    load_entry_pack_patterns(tmp_path)
    artifact = entries / "artifacts" / "sha256" / "529d18ba2b351a8de985a9cf416261d717ef55a4b7a9d9d65bce53b97d59ab35"
    content = artifact.read_bytes()
    stat = artifact.stat()
    artifact.write_bytes(bytes((content[0] ^ 1,)) + content[1:])
    os.utime(artifact, ns=(stat.st_atime_ns, stat.st_mtime_ns))

    with pytest.raises(EntryFactAuthorityError):
        load_entry_pack_patterns(tmp_path)

    assert authenticates == 2


def test_pack_patterns_resolve_from_package_not_target_repo() -> None:
    # default call reads the installed package's ruleset, independent of any analyzed repo
    assert load_entry_pack_patterns().get("typescript")
    # an explicit root is a test-staging override only
    with tempfile.TemporaryDirectory() as tmp:
        assert load_entry_pack_patterns(Path(tmp)) == {}


def test_pack_only_pattern_recognised_as_express_route() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = _target(root, "src/routes.ts", TS_SOURCE)
        without = _js_entry_points(target, TS_SOURCE, [])
        assert not any(e.kind == "route" for e in without)
        packs = load_entry_pack_patterns()
        with_pack = _js_entry_points(target, TS_SOURCE, packs.get("typescript", []))
        routes = [e for e in with_pack if e.kind == "route"]
        assert routes, "pack-only pattern app.all( must be recognised"
        assert any("Express" in " ".join(e.access_evidence) for e in routes)
        assert entry_framework(routes[0]) == "express"


def test_analyze_entry_points_uses_packs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = _target(root, "src/routes.ts", TS_SOURCE)
        entries = analyze_entry_points(root, [target], texts={target.path: TS_SOURCE}, include_manifests=False)
        routes = [e for e in entries if e.kind == "route" and e.defines_handler]
        assert routes
        assert entry_framework(routes[0]) == "express"
