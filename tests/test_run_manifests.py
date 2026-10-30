"""Analyzer bundle materialisation and verification (task 12.1, Reqs 5.1, 5.5, 12.1)."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import run_manifests  # noqa: E402

_HEX12 = re.compile(r"^[0-9a-f]{12}$")


def _facts_file(tmp_path: Path) -> Path:
    facts = tmp_path / "facts.toml"
    facts.write_text("[[operation]]\nid = 'protected-read'\n", encoding="utf-8")
    return facts


def _acquisition_file(tmp_path: Path) -> Path:
    acquisition = tmp_path / "acquisition.json"
    acquisition.write_text('{"label_blind": true}\n', encoding="utf-8")
    return acquisition


def _git_head(repo_root: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_root, capture_output=True, text=True, check=True).stdout.strip()


def _workdir(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    work = tmp_path / "repo"
    work.mkdir()
    base = _commit(work, "class Plain {}")
    head = _commit(work, "class Fixture {}")
    change: dict[str, object] = {
        "id": "change-1",
        "repo": "fixture/repo",
        "kind": "vulnerability",
        "base": base,
        "head": head,
        "files": [{"path": "Fixture.java", "head_lines": [[1, 2]]}],
        "head_lines": {1: "class Fixture {}"},
    }
    return work, change


def _commit(work: Path, text: str) -> str:
    def run(command: list[str]) -> str:
        return subprocess.run(command, cwd=work, capture_output=True, text=True, check=True).stdout.strip()

    run(["git", "init", "-q"])
    run(["git", "config", "user.email", "fixture@example.com"])
    run(["git", "config", "user.name", "Fixture"])
    (work / "Fixture.java").write_text(text, encoding="utf-8")
    run(["git", "add", "Fixture.java"])
    run(["git", "commit", "-qm", "fixture"])
    return run(["git", "rev-parse", "HEAD"])


def test_bundle_digests_are_populated_and_hex12(tmp_path: Path) -> None:
    work, _change = _workdir(tmp_path)
    bundle = run_manifests.bundle_from(work, _facts_file(tmp_path), _acquisition_file(tmp_path), (("judgment_mode", "true"),))
    assert bundle.analyzer_revision == _git_head(work)
    assert _HEX12.match(bundle.fact_set_digest)
    assert _HEX12.match(bundle.acquisition_record_digest)
    assert _HEX12.match(bundle.configuration_digest)


def test_configuration_digest_is_order_stable(tmp_path: Path) -> None:
    work, _change = _workdir(tmp_path)
    first = run_manifests.bundle_from(work, _facts_file(tmp_path), configuration=(("judgment_mode", "true"), ("max_depth", "3")))
    second = run_manifests.bundle_from(work, _facts_file(tmp_path), configuration=(("max_depth", "3"), ("judgment_mode", "true")))
    assert first.configuration_digest == second.configuration_digest


def test_missing_acquisition_uses_sentinel_none_digest(tmp_path: Path) -> None:
    work, _change = _workdir(tmp_path)
    bundle = run_manifests.bundle_from(work, _facts_file(tmp_path))
    assert bundle.acquisition_record_digest == "none"


def test_materialise_writes_manifest_and_copies_artifacts(tmp_path: Path) -> None:
    import json

    work, _change = _workdir(tmp_path)
    facts = _facts_file(tmp_path)
    acquisition = _acquisition_file(tmp_path)
    bundle = run_manifests.bundle_from(work, facts, acquisition, (("judgment_mode", "true"),))
    out_dir = tmp_path / "bundle"
    manifest = run_manifests.materialise(bundle, facts, acquisition, out_dir)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["analyzer_revision"] == bundle.analyzer_revision
    assert payload["fact_set_digest"] == bundle.fact_set_digest
    assert payload["acquisition_record_digest"] == bundle.acquisition_record_digest
    assert payload["configuration_digest"] == bundle.configuration_digest
    assert (out_dir / "facts.toml").read_text(encoding="utf-8") == facts.read_text(encoding="utf-8")
    assert (out_dir / "acquisition.json").exists()


def test_verify_round_trips_an_untampered_bundle(tmp_path: Path) -> None:
    work, _change = _workdir(tmp_path)
    facts = _facts_file(tmp_path)
    bundle = run_manifests.bundle_from(work, facts, configuration=(("max_depth", "3"),))
    out_dir = tmp_path / "bundle"
    run_manifests.materialise(bundle, facts, None, out_dir)
    assert run_manifests.verify(out_dir, work) == bundle


def test_tampered_artifact_is_refused(tmp_path: Path) -> None:
    work, _change = _workdir(tmp_path)
    facts = _facts_file(tmp_path)
    bundle = run_manifests.bundle_from(work, facts)
    out_dir = tmp_path / "bundle"
    run_manifests.materialise(bundle, facts, None, out_dir)
    (out_dir / "facts.toml").write_text("[[operation]]\nid = 'tampered'\n", encoding="utf-8")
    with pytest.raises(run_manifests.BundleMismatch) as excinfo:
        run_manifests.verify(out_dir, work)
    assert "fact_set_digest" in str(excinfo.value)


def test_missing_artifact_refuses_materialisation(tmp_path: Path) -> None:
    work, _change = _workdir(tmp_path)
    absent = tmp_path / "absent.toml"
    with pytest.raises(FileNotFoundError):
        run_manifests.bundle_from(work, absent)


def test_reconstruction_is_deterministic(tmp_path: Path) -> None:
    work, _change = _workdir(tmp_path)
    facts = _facts_file(tmp_path)
    acquisition = _acquisition_file(tmp_path)
    bundle = run_manifests.bundle_from(work, facts, acquisition)
    first_dir = tmp_path / "bundle-a"
    second_dir = tmp_path / "bundle-b"
    first = run_manifests.materialise(bundle, facts, acquisition, first_dir)
    second = run_manifests.materialise(bundle, facts, acquisition, second_dir)
    assert first.read_bytes() == second.read_bytes()
    assert run_manifests.verify(first_dir, work) == run_manifests.verify(second_dir, work)


def test_analyzer_bundle_is_frozen(tmp_path: Path) -> None:
    work, _change = _workdir(tmp_path)
    bundle = run_manifests.bundle_from(work, _facts_file(tmp_path))
    with pytest.raises(Exception):  # noqa: B017
        bundle.analyzer_revision = "deadbeef"  # type: ignore[misc]
