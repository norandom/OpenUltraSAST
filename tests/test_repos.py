"""Pinned known-vulnerable checkouts (Req 4.1).

Every test here is offline. The one that fetches builds a git repository in ``tmp_path`` and uses it as the
recipe's url, which exercises the real fetch path -- ``git init``, ``fetch``, ``checkout`` -- with no network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from openultrasast.repos import (
    DEFAULT_REPO_DIR,
    RepoRecipeError,
    RepoUnavailable,
    checkout_path,
    load_repo_recipe,
    load_repo_recipes,
    network_allowed,
    recipe_payload,
    resolve,
    select,
    verify,
)

RECIPE = """
name = "sample"
url = "{url}"
commit = "{commit}"
language = "python"
license = "MIT"
license_file = "LICENSE"
measures = ["detection"]

[[known]]
id = "SAMPLE-1"
family = "injection"
weakness = "the parameter is interpolated into the query"
file = "app.py"
function = "handler"
line = 3
reference = "README"
in_scope = true
"""


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def origin(tmp_path: Path) -> tuple[Path, str]:
    """A real git repository standing in for a remote, and the SHA a recipe would pin."""
    root = tmp_path / "origin"
    (root / "sub").mkdir(parents=True)
    (root / "LICENSE").write_text("MIT")
    (root / "app.py").write_text("def handler(name):\n    q = f'select {name}'\n    execute(q)\n")
    _git(root, "init", "--quiet", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "sample")
    return root, _git(root, "rev-parse", "HEAD")


@pytest.fixture
def recipe_path(tmp_path: Path, origin: tuple[Path, str]) -> Path:
    root, commit = origin
    path = tmp_path / "sample.toml"
    path.write_text(RECIPE.format(url=root.as_uri(), commit=commit))
    return path


def test_recipe_round_trips(recipe_path: Path) -> None:
    recipe = load_repo_recipe(recipe_path)
    assert recipe.name == "sample"
    assert recipe.measures == ("detection",)
    assert [item.id for item in recipe.in_scope] == ["SAMPLE-1"]
    assert recipe_payload(recipe)["known"] == [
        {
            "id": "SAMPLE-1",
            "family": "injection",
            "weakness": "the parameter is interpolated into the query",
            "location": "app.py:handler:3",
            "in_scope": True,
        }
    ]


def test_a_branch_is_not_a_pin(tmp_path: Path) -> None:
    """A tag or branch would make the same recipe mean different code next month."""
    path = tmp_path / "loose.toml"
    path.write_text(RECIPE.format(url="https://example.invalid/x.git", commit="main"))
    with pytest.raises(RepoRecipeError, match="full 40-character SHA"):
        load_repo_recipe(path)


def test_in_scope_must_be_stated(tmp_path: Path, origin: tuple[Path, str]) -> None:
    """Defaulting it would silently decide whether 'not found' is a miss or a non-question."""
    _, commit = origin
    path = tmp_path / "quiet.toml"
    path.write_text(RECIPE.format(url="https://example.invalid/x.git", commit=commit).replace("in_scope = true\n", ""))
    with pytest.raises(RepoRecipeError, match="must state in_scope explicitly"):
        load_repo_recipe(path)


def test_detection_needs_something_in_scope(tmp_path: Path, origin: tuple[Path, str]) -> None:
    _, commit = origin
    path = tmp_path / "empty.toml"
    path.write_text(RECIPE.format(url="https://example.invalid/x.git", commit=commit).replace("in_scope = true", "in_scope = false"))
    with pytest.raises(RepoRecipeError, match="names no in-scope vulnerability"):
        load_repo_recipe(path)


def test_unknown_measure_is_rejected(tmp_path: Path, origin: tuple[Path, str]) -> None:
    _, commit = origin
    path = tmp_path / "odd.toml"
    path.write_text(RECIPE.format(url="https://example.invalid/x.git", commit=commit).replace('["detection"]', '["vibes"]'))
    with pytest.raises(RepoRecipeError, match="unknown measures"):
        load_repo_recipe(path)


def test_offline_by_default(recipe_path: Path, tmp_path: Path) -> None:
    """No switch, no fetch -- this is what keeps CI from reaching the network."""
    assert network_allowed() is False
    with pytest.raises(RepoUnavailable, match="--fetch"):
        resolve(load_repo_recipe(recipe_path), cache_root=tmp_path / "cache")


def test_the_switch_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENULTRASAST_REPOS_NETWORK", "1")
    assert network_allowed() is True
    assert network_allowed(False) is False, "an explicit flag beats the environment"


def test_resolve_fetches_then_serves_from_cache(recipe_path: Path, tmp_path: Path) -> None:
    recipe = load_repo_recipe(recipe_path)
    cache = tmp_path / "cache"

    root = resolve(recipe, fetch=True, cache_root=cache)

    assert root == checkout_path(recipe, cache)
    assert (root / "app.py").is_file()
    assert verify(recipe, root) == (), "the recipe describes what was actually fetched"
    # A warm cache spares the fetch; it never turns an offline run into a networked one.
    assert resolve(recipe, cache_root=cache) == root


def test_checkout_is_keyed_by_commit(recipe_path: Path, tmp_path: Path) -> None:
    """Re-pinning must not overwrite the source an older baseline was measured against."""
    recipe = load_repo_recipe(recipe_path)
    other = checkout_path(recipe, tmp_path)
    assert other.name == recipe.commit[:12]
    assert other.parent.name == "sample"


def test_verify_catches_the_wrong_commit(recipe_path: Path, tmp_path: Path, origin: tuple[Path, str]) -> None:
    root_repo, _ = origin
    recipe = load_repo_recipe(recipe_path)
    root = resolve(recipe, fetch=True, cache_root=tmp_path / "cache")
    (root_repo / "app.py").write_text("def handler(name):\n    pass\n")
    _git(root_repo, "commit", "--quiet", "-am", "moved on")
    moved = _git(root_repo, "rev-parse", "HEAD")
    _git(root, "fetch", "--quiet", "origin", moved)
    _git(root, "checkout", "--quiet", "FETCH_HEAD")

    assert any("HEAD is" in problem for problem in verify(recipe, root))


def test_verify_catches_a_recipe_that_describes_absent_code(recipe_path: Path, tmp_path: Path) -> None:
    recipe = load_repo_recipe(recipe_path)
    root = resolve(recipe, fetch=True, cache_root=tmp_path / "cache")
    (root / "app.py").unlink()
    (root / "LICENSE").unlink()

    problems = verify(recipe, root)

    assert any("LICENSE" in problem for problem in problems)
    assert any("app.py is not in the checkout" in problem for problem in problems)


def test_verify_catches_a_line_outside_the_file(recipe_path: Path, tmp_path: Path) -> None:
    recipe = load_repo_recipe(recipe_path)
    root = resolve(recipe, fetch=True, cache_root=tmp_path / "cache")
    (root / "app.py").write_text("only one line\n")

    assert any("outside" in problem for problem in verify(recipe, root))


def test_verify_catches_a_function_that_is_not_there(recipe_path: Path, tmp_path: Path) -> None:
    recipe = load_repo_recipe(recipe_path)
    root = resolve(recipe, fetch=True, cache_root=tmp_path / "cache")
    (root / "app.py").write_text("a\nb\nc\n")

    assert any("handler is not within" in problem for problem in verify(recipe, root))


def test_select_by_name(recipe_path: Path) -> None:
    recipes = (load_repo_recipe(recipe_path),)
    assert select(recipes, "all") == recipes
    assert select(recipes, "sample") == recipes
    assert select(recipes, "absent") == ()


def test_the_committed_recipes_parse() -> None:
    """The corpus itself, offline: every field present, every commit pinned, every scope decided."""
    recipes = load_repo_recipes(DEFAULT_REPO_DIR)

    assert {recipe.name for recipe in recipes} >= {"vampi", "libpng"}
    for recipe in recipes:
        assert recipe.license, f"{recipe.name} names no licence"
        assert recipe.known, f"{recipe.name} names no known vulnerability"
        assert all(item.line > 0 for item in recipe.known)


def test_the_envelope_checkout_claims_no_detection() -> None:
    """libpng's CVE is a memory-safety bug: recording 'not found' as a miss would make the number lie."""
    libpng = next(recipe for recipe in load_repo_recipes(DEFAULT_REPO_DIR) if recipe.name == "libpng")

    assert "detection" not in libpng.measures
    assert libpng.in_scope == ()
