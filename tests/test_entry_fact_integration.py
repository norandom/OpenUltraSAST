"""Production mapping integration for reviewed entry facts."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from openultrasast.core import canonical, provenance
from openultrasast.core.semantics import RelationStatus
from openultrasast.mapping.entry_fact_integration import match_reviewed_entry_targets
from openultrasast.mapping.entry_packs import load_installed_entry_fact_authority
from openultrasast.mapping.fact_authority import EntryFactAuthorityContext
from openultrasast.mapping.fact_match_store import FactMatchArtifactWriter
from openultrasast.mapping.legacy import analyze_entry_points, analyze_entry_points_with_facts
from openultrasast.preprocess import FileTarget, detect_language

SRC = Path(__file__).parents[1] / "src" / "openultrasast"


class _UnusedCustody:
    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        raise AssertionError(f"authority load read custody: {population_digest}")


class _Custody:
    def __init__(self, logs: dict[str, provenance.PopulationCustodyLog]) -> None:
        self.logs = logs

    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        return self.logs[population_digest]


class _EqualitySpoofResolver:
    def __eq__(self, other: object) -> bool:
        return True

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        raise AssertionError(f"synthetic resolver used: {reference.artifact_id}")


class _ContextSubclass(EntryFactAuthorityContext):
    pass


class _MemoryWriter(FactMatchArtifactWriter):
    def persist_observation(self, value: object) -> canonical.ContentRef:
        raise AssertionError(f"memory writer used: {value!r}")

    def persist_match(self, value: object) -> canonical.ContentRef:
        raise AssertionError(f"memory writer used: {value!r}")


def _authority() -> tuple[EntryFactAuthorityContext, str]:
    loaded = load_installed_entry_fact_authority(_UnusedCustody())
    bundle = loaded.bundle
    custodian = bundle.custody_policy.reviewed_custodian_digests[0]
    logs: dict[str, provenance.PopulationCustodyLog] = {}
    for lineage in bundle.lineages:
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
            receipt = provenance.record_population_use(request, prior, custodian, bundle.custody_policy)
            assert receipt.receipt_digest == use.population_use_receipt_digest
            logs[use.source_population_digest] = provenance.append_population_use(prior, receipt, bundle.custody_policy)
    evaluation = canonical.content_digest("production-entry-integration-population")
    logs[evaluation] = provenance.empty_population_custody_log(evaluation, custodian)
    return replace(loaded, custody=_Custody(logs)), evaluation


def _target(root: Path, name: str, content: str) -> FileTarget:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    assert path.stat().st_size > 0
    return FileTarget(name, str(path), detect_language(path), content.count("\n") + 1, [], False, [], [])


def _writer(root: Path, authority: EntryFactAuthorityContext) -> FactMatchArtifactWriter:
    return FactMatchArtifactWriter(
        root / "fact-matches",
        authority.bundle.review_policy.trusted_store_identities[0],
        canonical.content_digest("retain-production-entry-facts"),
    )


def _canonical_records(values: object) -> bytes:
    return json.dumps([asdict(item) for item in values], sort_keys=True, separators=(",", ":")).encode()


def test_default_entry_mapping_remains_byte_stable_when_v2_is_not_requested(tmp_path: Path) -> None:
    from openultrasast.mapping import legacy

    source = 'import express from "express";\nconst app = express();\napp.get("/x", handler);\nfunction handler() {}\n'
    target = _target(tmp_path, "src/routes.js", source)
    before = analyze_entry_points(tmp_path, [target], include_manifests=False)
    assert not hasattr(legacy, "match_reviewed_entry_targets")
    after = analyze_entry_points(tmp_path, [target], include_manifests=False)

    assert _canonical_records(before) == _canonical_records(after)
    assert json.loads(_canonical_records(after)) == [
        {
            "access_declared": False,
            "access_evidence": ['app.get("/x", handler);'],
            "access_level": "public",
            "conditions": [],
            "defines_handler": True,
            "end_line": 4,
            "function_name": "handler",
            "kind": "route",
            "line": 4,
            "name": "http_handler",
            "path": "src/routes.js",
            "provenance": "entrypoint:route:public",
            "rationale": "route surface classified as public at http_request",
            "registered_by": "",
            "trust_boundary": "http_request",
        }
    ]


def test_explicit_v2_path_persists_complete_matches_beside_legacy_output(tmp_path: Path) -> None:
    authority, evaluation = _authority()
    writer = _writer(tmp_path, authority)
    target = _target(
        tmp_path,
        "src/routes.js",
        'import express from "express";\n'
        "const app = express();\n"
        'app.get("/admin", adminHandler);\n'
        "function adminHandler(req, res) { res.sendStatus(204); }\n",
    )

    analysis = analyze_entry_points_with_facts(
        tmp_path,
        [target],
        authority=authority,
        writer=writer,
        evaluation_population_digest=evaluation,
        include_manifests=False,
    )

    assert _canonical_records(analysis.entry_points) == _canonical_records(
        analyze_entry_points(tmp_path, [target], include_manifests=False)
    )
    route = next(item for item in analysis.fact_matches if item.match.fact_id == "entry:express:app-route:get")
    assert route.decision.status is RelationStatus.COMPLETE
    assert route.relations
    assert writer.resolver.resolve(route.match_reference).content
    assert all(writer.resolver.resolve(item.evidence).content for item in route.match.observations)


@pytest.mark.parametrize(
    "name,source,reason,legacy_only",
    (
        (
            "name-only.js",
            'app.get("/admin", adminHandler);\nfunction adminHandler(req, res) { res.sendStatus(204); }\n',
            "missing_observation:receiver",
            False,
        ),
        (
            "partial.js",
            'import express from "express";\nconst app = express();\napp.get("/admin");\n',
            "missing_observation:arguments",
            False,
        ),
        (
            "legacy-only.js",
            '// Legacy recognition text only: app.get("/admin", adminHandler)\nexport const marker = "not structural";\n',
            None,
            True,
        ),
    ),
)
def test_projection_or_incomplete_structure_cannot_become_v2_evidence(
    tmp_path: Path, name: str, source: str, reason: str | None, legacy_only: bool
) -> None:
    authority, evaluation = _authority()
    target = _target(tmp_path, name, source)
    analysis = analyze_entry_points_with_facts(
        tmp_path,
        [target],
        authority=authority,
        writer=_writer(tmp_path, authority),
        evaluation_population_digest=evaluation,
        include_manifests=False,
    )

    route_matches = [item for item in analysis.fact_matches if item.match.fact_id == "entry:express:app-route:get"]
    if legacy_only:
        assert analysis.entry_points and route_matches == []
    else:
        assert len(route_matches) == 1
        assert route_matches[0].decision.status is not RelationStatus.COMPLETE
        assert reason in route_matches[0].decision.reasons
        assert all(relation.status is not RelationStatus.COMPLETE for relation in route_matches[0].relations)


def test_explicit_v2_boundary_rejects_untrusted_writer_or_context(tmp_path: Path) -> None:
    authority, evaluation = _authority()
    target = _target(tmp_path, "src/routes.js", 'app.get("/x", handler);\nfunction handler() {}\n')
    untrusted = FactMatchArtifactWriter(
        tmp_path / "untrusted",
        "unreviewed-store",
        canonical.content_digest("retain-untrusted"),
    )
    with pytest.raises(ValueError, match="trusted store"):
        match_reviewed_entry_targets(tmp_path, [target], authority, untrusted, evaluation)
    with pytest.raises(TypeError, match="authority"):
        match_reviewed_entry_targets(tmp_path, [target], object(), _writer(tmp_path, authority), evaluation)  # type: ignore[arg-type]
    substituted = replace(authority, bundle=replace(authority.bundle, bundle_digest="0" * 64))
    with pytest.raises(ValueError, match="externally authenticated"):
        match_reviewed_entry_targets(tmp_path, [target], substituted, _writer(tmp_path, authority), evaluation)
    subclassed = _ContextSubclass(authority.bundle, authority.custody, authority.resolver)
    with pytest.raises(TypeError, match="authority"):
        match_reviewed_entry_targets(tmp_path, [target], subclassed, _writer(tmp_path, authority), evaluation)


def test_explicit_v2_rejects_equality_spoofed_resolver_before_matching(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.mapping import entry_fact_integration

    authority, evaluation = _authority()
    target = _target(tmp_path, "src/routes.js", 'app.get("/x", handler);\nfunction handler() {}\n')
    spoofed = replace(authority, resolver=_EqualitySpoofResolver())
    monkeypatch.setattr(entry_fact_integration, "match_entry_fact", lambda **kwargs: pytest.fail("matcher reached"))

    with pytest.raises(ValueError, match="resolver"):
        match_reviewed_entry_targets(tmp_path, [target], spoofed, _writer(tmp_path, authority), evaluation)


def test_explicit_v2_rejects_writer_subclass_before_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.mapping import entry_fact_integration

    authority, evaluation = _authority()
    target = _target(tmp_path, "src/routes.js", 'app.get("/x", handler);\nfunction handler() {}\n')
    real = _writer(tmp_path, authority)
    writer = _MemoryWriter(real.root, real.store_identity, real.retention_policy_digest)
    monkeypatch.setattr(entry_fact_integration, "match_entry_fact", lambda **kwargs: pytest.fail("matcher reached"))

    with pytest.raises(TypeError, match="writer"):
        match_reviewed_entry_targets(tmp_path, [target], authority, writer, evaluation)


def test_explicit_v2_rejects_same_type_pack_body_substitution_before_matching(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.mapping import entry_fact_integration

    authority, evaluation = _authority()
    target = _target(tmp_path, "src/routes.js", 'app.get("/x", handler);\nfunction handler() {}\n')
    pack = replace(authority.bundle.packs[0], normalized_content_digest="0" * 64)
    bundle = replace(authority.bundle, packs=(pack, *authority.bundle.packs[1:]))
    substituted = replace(authority, bundle=bundle)
    monkeypatch.setattr(entry_fact_integration, "match_entry_fact", lambda **kwargs: pytest.fail("matcher reached"))

    with pytest.raises(ValueError, match="pack"):
        match_reviewed_entry_targets(tmp_path, [target], substituted, _writer(tmp_path, authority), evaluation)


def test_explicit_v2_rejects_same_type_contract_body_substitution_before_matching(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.mapping import entry_fact_integration

    authority, evaluation = _authority()
    target = _target(tmp_path, "src/routes.js", 'app.get("/x", handler);\nfunction handler() {}\n')
    contract = replace(authority.bundle.contract, family_version="2.0.1")
    substituted = replace(authority, bundle=replace(authority.bundle, contract=contract))
    monkeypatch.setattr(entry_fact_integration, "match_entry_fact", lambda **kwargs: pytest.fail("matcher reached"))

    with pytest.raises(ValueError, match="contract"):
        match_reviewed_entry_targets(tmp_path, [target], substituted, _writer(tmp_path, authority), evaluation)


def test_default_legacy_import_does_not_eagerly_load_v2_matcher_modules() -> None:
    script = """
import sys
import openultrasast.mapping.legacy
forbidden = {
    'openultrasast.mapping.entry_fact_integration',
    'openultrasast.mapping.entry_fact_matcher',
    'openultrasast.mapping.entry_fact_structure',
}
assert forbidden.isdisjoint(sys.modules), sorted(forbidden.intersection(sys.modules))
"""
    completed = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr


def test_explicit_v2_refuses_cached_text_that_differs_from_product_bytes(tmp_path: Path) -> None:
    authority, evaluation = _authority()
    source = 'app.get("/real", handler);\nfunction handler() {}\n'
    target = _target(tmp_path, "src/routes.js", source)
    with pytest.raises(ValueError, match="cached source text differs"):
        analyze_entry_points_with_facts(
            tmp_path,
            [target],
            authority=authority,
            writer=_writer(tmp_path, authority),
            evaluation_population_digest=evaluation,
            texts={target.path: source.replace("/real", "/stale")},
            include_manifests=False,
        )


def test_production_censuses_find_no_projection_evidence_or_writer_bypass() -> None:
    calls: dict[str, list[str]] = {
        "load_entry_pack_patterns": [],
        "match_entry_fact": [],
        "persist_observation": [],
        "persist_match": [],
        "StructuralObservation": [],
        "FactMatchEvidence": [],
        "FactMatchArtifactWriter": [],
    }
    conformance_only = {
        "mapping/_entry_fact_conformance_fs.py",
        "mapping/_entry_fact_conformance_negative.py",
        "mapping/_entry_fact_conformance_replay.py",
        "mapping/_entry_fact_conformance_wire.py",
        "mapping/entry_fact_conformance.py",
        "mapping/entry_fact_conformance_manifest.py",
    }
    production = tuple(path for path in SRC.rglob("*.py") if path.relative_to(SRC).as_posix() not in conformance_only)
    imports: dict[str, list[str]] = {"load_entry_pack_patterns": [], "match_entry_fact": []}
    for path in production:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name in imports:
                        imports[alias.name].append(path.relative_to(SRC).as_posix())
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if name in calls:
                calls[name].append(path.relative_to(SRC).as_posix())

    assert imports["load_entry_pack_patterns"] == ["mapping/legacy.py"]
    assert calls["load_entry_pack_patterns"] == ["mapping/legacy.py"]
    assert imports["match_entry_fact"] == ["mapping/entry_fact_integration.py"]
    assert calls["match_entry_fact"] == ["mapping/entry_fact_integration.py"]
    assert calls["persist_observation"] == ["mapping/entry_fact_matcher.py"]
    assert calls["persist_match"] == ["mapping/entry_fact_matcher.py"]
    assert calls["StructuralObservation"] == ["core/factvalidate.py", "mapping/entry_fact_matcher.py"]
    assert calls["FactMatchEvidence"] == ["core/factvalidate.py", "mapping/entry_fact_matcher.py"]
    assert calls["FactMatchArtifactWriter"] == []
    assert "load_entry_pack_patterns" not in (SRC / "mapping" / "entry_fact_integration.py").read_text(encoding="utf-8")
    legacy_source = (SRC / "mapping" / "legacy.py").read_text(encoding="utf-8")
    assert "FactMatchEvidence" not in legacy_source and "StructuralObservation" not in legacy_source
