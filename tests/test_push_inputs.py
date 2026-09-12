"""Input provenance fails closed without dropping a declared evaluation case."""

import hashlib
import json
import subprocess

import pytest

from openultrasast.push_inputs import validate_manifest


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()


@pytest.fixture
def manifest(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    git(source, "init", "-q")
    for name, value in [("LICENSE", "test license\n"), ("api.js", "eval(req.body.value);\n")]:
        (source / name).write_text(value)
    git(source, "add", ".")
    git(source, "-c", "user.name=Test", "-c", "user.email=test@example.org", "commit", "-qm", "input")
    sha = git(source, "rev-parse", "HEAD")
    cache = tmp_path / "cache" / "sample" / sha[:12]
    cache.parent.mkdir(parents=True)
    source.rename(cache)
    recipe = tmp_path / "sample.toml"
    recipe.write_text(
        f'name="sample"\nurl="https://example.org/sample.git"\ncommit="{sha}"\nlanguage="javascript"\nlicense="MIT"\nlicense_file="LICENSE"\nmeasures=["envelope"]\n'
    )
    files = [
        {"path": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "size": p.stat().st_size}
        for p in [cache / "LICENSE", cache / "api.js"]
    ]
    data = {
        "schema_version": 1,
        "snapshots": [{"id": "vuln", "recipe": "sample.toml", "files": files}],
        "cases": [
            {
                "id": "case",
                "base": "vuln",
                "tip": "vuln",
                "label": "vulnerable",
                "role": "development",
                "capability": "javascript/express/injection",
                "provenance": "upstream teaching example",
                "prerequisites": [],
            }
        ],
    }
    path = tmp_path / "inputs.json"

    def run():
        path.write_text(json.dumps(data))
        return validate_manifest(path, cache_root=tmp_path / "cache")

    return data, cache, run


def test_immutable_bytes_ignore_dirty_worktree(manifest):
    _, root, run = manifest
    (root / "api.js").write_text("different worktree\n")
    result = run()
    assert result["cases"][0]["status"] == "ready"
    assert result["snapshots"][0]["bytes_read"] > 0


@pytest.mark.parametrize("mutation", ["hash", "empty", "escape", "missing", "ref"])
def test_invalid_input_keeps_case_in_population(manifest, mutation):
    data, _, run = manifest
    snap = data["snapshots"][0]
    file = snap["files"][1]
    if mutation == "hash":
        file["sha256"] = "0" * 64
    elif mutation == "empty":
        file["size"] = 0
    elif mutation == "escape":
        file["path"] = "../api.js"
    elif mutation == "missing":
        file["path"] = "missing.js"
    else:
        snap["commit"] = "main"
    result = run()
    assert result["population"] == 1
    assert result["cases"][0]["status"] == "invalid_input"


def test_unavailable_source_is_explicit(manifest):
    data, _, run = manifest
    data["snapshots"][0]["commit"] = "a" * 40
    result = run()
    assert result["cases"][0]["status"] == "missing_prerequisite"
    assert "fetch" in str(result)


def test_missing_holdout_labels_never_qualify_capability(manifest):
    data, _, run = manifest
    data["cases"][0].update(role="reserved_holdout", label="unreviewed", prerequisites=["review independent positive/fixed/benign pair"])
    result = run()
    assert result["cases"][0]["status"] == "missing_prerequisite"
    assert result["cases"][0]["admission"] == "experimental"


def test_invalid_label_rejected(manifest):
    data, _, run = manifest
    data["cases"][0]["label"] = "clean"
    assert run()["cases"][0]["status"] == "invalid_input"


def test_authored_edit_requires_exact_original_and_provenance(manifest):
    data, _, run = manifest
    f = data["snapshots"][0]["files"][1]
    f["edit"] = {"before": "not in source", "after": "safe", "provenance": "authored repair"}
    assert run()["cases"][0]["status"] == "invalid_input"


@pytest.mark.parametrize("field", ["snapshots", "cases"])
def test_empty_population_rejected(manifest, field):
    from openultrasast.push_inputs import InputError

    data, _, run = manifest
    data[field] = []
    with pytest.raises(InputError, match="nonempty"):
        run()


def test_missing_snapshot_identity_rejected(manifest):
    from openultrasast.push_inputs import InputError

    data, _, run = manifest
    del data["snapshots"][0]["id"]
    with pytest.raises(InputError, match="identity"):
        run()


def test_missing_language_holdouts_retained(manifest):
    data, _, run = manifest
    data["capability_prerequisites"] = {"php/wordpress/injection": ["untouched PHP pair missing"]}
    assert run()["capability_prerequisites"] == data["capability_prerequisites"]
