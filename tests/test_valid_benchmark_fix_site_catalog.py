"""Replacement fix-site catalog remains anchored to the exact security fix."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import catalog as catalog_facade  # noqa: E402
from benchmarks.valid import fix_site_catalog as catalog  # noqa: E402
from benchmarks.valid.reservation import build_network_identity  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

PARENT = "1" * 40
FIX = "2" * 40


class FixtureReader:
    def __init__(self, blobs: dict[tuple[str, str], str | None], parents: tuple[str, ...] = (PARENT,)) -> None:
        self.blobs = blobs
        self.fixed_parents = parents
        self.calls: list[tuple[str, ...]] = []

    def parents(self, revision: str) -> tuple[str, ...]:
        self.calls.append(("parents", revision))
        return self.fixed_parents

    def blob(self, revision: str, path: str) -> str | None:
        self.calls.append(("blob", revision, path))
        return self.blobs.get((revision, path))

    def blame(self, *_args: object) -> None:
        raise AssertionError("SZZ/blame is outside the fix-site catalog boundary")


def _ref(path: str, text: str) -> catalog.EvidenceRef:
    return catalog.EvidenceRef(path, content_digest(text), len(text.encode()))


def _request(**changes: object) -> catalog.FixSiteRequest:
    value = catalog.FixSiteRequest(
        repository=build_network_identity("https://github.com/example/application"),
        vulnerable_parent=PARENT,
        fixed_revision=FIX,
        path="src/service.py",
        function="handle",
        observed_language="python",
        package_evidence=catalog.PackageEcosystemEvidence("python", _ref("pyproject.toml", "[project]")),
        license_evidence=catalog.LicenseEvidence("Apache-2.0", _ref("LICENSE", "license text")),
        source_evidence=catalog.SourceEvidence("advisory", "GHSA-test-test-test", content_digest("advisory")),
        change_inputs_digest=content_digest("exact diff inputs"),
    )
    return replace(value, **changes)


def _reader(pre: str | None = None, post: str | None = None) -> FixtureReader:
    pre = pre if pre is not None else "def handle(value):\n    return dangerous(value)\n"
    post = post if post is not None else "def handle(value):\n    return safe(value)\n"
    return FixtureReader({(PARENT, "src/service.py"): pre, (FIX, "src/service.py"): post})


def test_candidate_preserves_exact_fix_pair_and_provenance() -> None:
    reader = _reader()
    candidate = catalog.build_fix_site_candidate(reader, _request())

    assert candidate.vulnerable.revision == PARENT
    assert candidate.fixed.revision == FIX
    assert candidate.vulnerable.content == "def handle(value):\n    return dangerous(value)"
    assert candidate.fixed.content == "def handle(value):\n    return safe(value)"
    assert candidate.canonical_repository == "https://github.com/example/application"
    assert candidate.package_evidence.ecosystem_hint == "python"
    assert candidate.license_evidence.expression == "Apache-2.0"
    assert candidate.source_evidence.source_kind == "advisory"
    assert candidate.provenance_digest and candidate.candidate_digest
    assert reader.calls == [
        ("parents", FIX),
        ("blob", PARENT, "src/service.py"),
        ("blob", FIX, "src/service.py"),
    ]


def test_local_git_fixture_reads_exact_parent_and_fix_objects(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "fixture@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Fixture"], check=True)
    source = tmp_path / "src/service.py"
    source.parent.mkdir()
    source.write_text("def handle(value):\n    return dangerous(value)\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "src/service.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "vulnerable"], check=True)
    parent = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    source.write_text("def handle(value):\n    return safe(value)\n")
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qam", "security fix"], check=True)
    fixed = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    reader = catalog_facade.local_git(tmp_path)

    candidate = catalog.build_fix_site_candidate(
        reader,
        _request(vulnerable_parent=parent, fixed_revision=fixed),
    )

    assert candidate.vulnerable.content.endswith("dangerous(value)")
    assert candidate.fixed.content.endswith("safe(value)")
    assert reader.files_read == 2
    assert reader.bytes_read > 0


def test_equal_inputs_produce_equal_candidate_identity() -> None:
    first = catalog.build_fix_site_candidate(_reader(), _request())
    second = catalog.build_fix_site_candidate(_reader(), _request())
    assert first == second
    assert catalog.fix_site_candidate_bytes(first) == catalog.fix_site_candidate_bytes(second)


def test_changed_function_bytes_cannot_reuse_candidate_identity() -> None:
    candidate = catalog.build_fix_site_candidate(_reader(), _request())
    changed = replace(candidate.vulnerable, content=candidate.vulnerable.content + "\n# changed")

    with pytest.raises(catalog.FixSiteCatalogError, match="receipt"):
        catalog.fix_site_candidate_bytes(replace(candidate, vulnerable=changed))


@pytest.mark.parametrize(
    "reader,fix_request,message",
    (
        (_reader(), _request(vulnerable_parent="3" * 40), "parent"),
        (_reader(pre=""), _request(), "empty"),
        (FixtureReader({(FIX, "src/service.py"): "def handle():\n    pass\n"}), _request(), "unreadable"),
        (_reader(pre="def handle():\n    pass\ndef handle():\n    pass\n"), _request(), "ambiguous"),
        (_reader(), _request(path="../service.py"), "path"),
        (_reader(), _request(function="missing"), "function"),
    ),
)
def test_invalid_or_unreadable_fix_sites_are_refused(reader: FixtureReader, fix_request: catalog.FixSiteRequest, message: str) -> None:
    with pytest.raises(catalog.FixSiteCatalogError, match=message):
        catalog.build_fix_site_candidate(reader, fix_request)


def test_rename_is_not_inferred_across_the_fix() -> None:
    reader = FixtureReader(
        {
            (PARENT, "src/old.py"): "def handle():\n    return 1\n",
            (FIX, "src/service.py"): "def handle():\n    return 2\n",
        }
    )
    with pytest.raises(catalog.FixSiteCatalogError, match="unreadable"):
        catalog.build_fix_site_candidate(reader, _request())


def test_typescript_is_observed_language_with_javascript_package_evidence() -> None:
    request = _request(
        path="src/service.ts",
        function="handle",
        observed_language="typescript",
        package_evidence=catalog.PackageEcosystemEvidence("javascript", _ref("package.json", "{}")),
    )
    reader = FixtureReader(
        {
            (PARENT, "src/service.ts"): "function handle(value) { return dangerous(value); }\n",
            (FIX, "src/service.ts"): "function handle(value) { return safe(value); }\n",
        }
    )
    assert catalog.build_fix_site_candidate(reader, request).observed_language == "typescript"


def test_catalog_surface_has_no_szz_or_introducing_commit_operation() -> None:
    assert not {"blame", "introducing", "introducing_revision"} & set(catalog.FixSiteReader.__dict__)
