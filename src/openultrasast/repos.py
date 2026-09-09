"""Pinned known-vulnerable repository checkouts (Req 4.1).

The corpus scores excerpts. Nothing in it exercises a whole repository: region ranking, the budget, one CPG
over thousands of files, or whether a verdict that holds on a fifteen-line excerpt still holds when the
source, the sink and the guard live in three different modules. These recipes name real checkouts so that
question can be measured instead of assumed.

Two rules carried over from the pointer pairs, for the same reasons:

* **Offline by default.** A recipe is inert until someone asks for the network, by ``--fetch`` for one run or
  ``OPENULTRASAST_REPOS_NETWORK=1``. CI sets neither, so CI never fetches.
* **Pinned, not tracked.** ``commit`` must be a full SHA. A branch or a tag would make the same recipe mean
  different code next month, and a measurement against moving code is not a baseline.

A third rule is specific to these: **a recipe declares what it can measure.** ``in_scope`` says, per known
vulnerability, whether it belongs to a family the model layer arbitrates at all. A memory-safety CVE in a C
library is a fine envelope test and an impossible detection test, and a measurement that does not separate
the two invites reading "not found" as a miss when it was never in scope.
"""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_CACHE_ENV = "OPENULTRASAST_REPO_CACHE"
REPOS_NETWORK_ENV = "OPENULTRASAST_REPOS_NETWORK"
DEFAULT_REPO_CACHE = Path.home() / ".cache" / "openultrasast" / "repos"
DEFAULT_REPO_DIR = Path("benchmarks/repos")

MEASURES = ("envelope", "detection")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_RECIPE_REQUIRED = ("name", "url", "commit", "language", "license", "license_file", "measures")
_KNOWN_REQUIRED = ("id", "family", "weakness", "file", "function", "line", "reference")
# How far above the declared line the function signature may sit. This is a consistency check between
# three fields, not a parse: C functions in libpng run past ninety lines, so a tight window rejects
# honest recipes, and a window this size still catches a line number that belongs to a different
# function entirely.
_FUNCTION_WINDOW = 200


class RepoRecipeError(ValueError):
    """A recipe that cannot be trusted to name one checkout."""


class RepoUnavailable(RuntimeError):
    """The checkout is not on disk and the network was not offered."""


@dataclass(frozen=True)
class KnownVulnerability:
    """One documented vulnerability, and whether this engine could decide it even in principle."""

    id: str
    family: str
    weakness: str
    file: str
    function: str
    line: int
    reference: str
    in_scope: bool

    @property
    def location(self) -> str:
        return f"{self.file}:{self.function}:{self.line}"


@dataclass(frozen=True)
class RepoRecipe:
    name: str
    url: str
    commit: str
    language: str
    license: str
    license_file: str
    measures: tuple[str, ...]
    known: tuple[KnownVulnerability, ...]
    environment: Mapping[str, str]
    note: str

    @property
    def in_scope(self) -> tuple[KnownVulnerability, ...]:
        """The known vulnerabilities a rung can be reported for; the rest are envelope-only."""
        return tuple(item for item in self.known if item.in_scope)


def load_repo_recipes(directory: Path = DEFAULT_REPO_DIR) -> tuple[RepoRecipe, ...]:
    if not directory.is_dir():
        return ()
    return tuple(load_repo_recipe(path) for path in sorted(directory.glob("*.toml")))


def load_repo_recipe(path: Path) -> RepoRecipe:
    data = tomllib.loads(path.read_text())
    missing = [key for key in _RECIPE_REQUIRED if not data.get(key)]
    if missing:
        raise RepoRecipeError(f"{path.name}: missing {', '.join(missing)}")

    commit = str(data["commit"])
    if not _SHA.match(commit):
        # A tag moves when it is re-cut and a branch moves every week. Either would make this recipe name
        # different code over time while the baseline it produced kept the old numbers.
        raise RepoRecipeError(f"{path.name}: commit must be a full 40-character SHA, not {commit!r}")

    measures = tuple(str(item) for item in data["measures"])
    unknown = [item for item in measures if item not in MEASURES]
    if unknown:
        raise RepoRecipeError(f"{path.name}: unknown measures {unknown}; expected any of {list(MEASURES)}")

    known = tuple(_known(item, path.name) for item in data.get("known", ()))
    if "detection" in measures and not any(item.in_scope for item in known):
        raise RepoRecipeError(f"{path.name}: declares detection but names no in-scope vulnerability to detect")

    return RepoRecipe(
        name=str(data["name"]),
        url=str(data["url"]),
        commit=commit,
        language=str(data["language"]),
        license=str(data["license"]),
        license_file=str(data["license_file"]),
        measures=measures,
        known=known,
        environment={str(k): str(v) for k, v in dict(data.get("environment", {})).items()},
        note=str(data.get("note", "")),
    )


def _known(item: object, name: str) -> KnownVulnerability:
    if not isinstance(item, dict):
        raise RepoRecipeError(f"{name}: each [[known]] entry must be a table")
    missing = [key for key in _KNOWN_REQUIRED if item.get(key) in (None, "")]
    if missing:
        raise RepoRecipeError(f"{name}: [[known]] missing {', '.join(missing)}")
    if "in_scope" not in item:
        # Deliberately not defaulted. Whether the engine could ever decide this is the difference between a
        # miss and a non-question, and a default would silently pick one.
        raise RepoRecipeError(f"{name}: [[known]] {item['id']} must state in_scope explicitly")
    return KnownVulnerability(
        id=str(item["id"]),
        family=str(item["family"]),
        weakness=str(item["weakness"]),
        file=str(item["file"]),
        function=str(item["function"]),
        line=int(item["line"]),
        reference=str(item["reference"]),
        in_scope=bool(item["in_scope"]),
    )


def repo_cache_dir() -> Path:
    """Checkout root; outside the repository unless the operator points it elsewhere."""
    return Path(os.environ.get(REPO_CACHE_ENV) or DEFAULT_REPO_CACHE).expanduser()


def network_allowed(fetch: bool | None = None) -> bool:
    """``repos --fetch`` for one run, or OPENULTRASAST_REPOS_NETWORK=1; CI sets neither."""
    if fetch is not None:
        return fetch
    return os.environ.get(REPOS_NETWORK_ENV, "") == "1"


def checkout_path(recipe: RepoRecipe, cache_root: Path | None = None) -> Path:
    """Where this exact commit lives. Keyed by SHA, so a re-pin never overwrites an older baseline's source."""
    return (cache_root or repo_cache_dir()) / recipe.name / recipe.commit[:12]


def resolve(recipe: RepoRecipe, *, fetch: bool | None = None, cache_root: Path | None = None) -> Path:
    """The checkout on disk, fetching only if the network was offered.

    A warm cache spares the fetch; it never turns an offline run into a networked one.
    """
    dest = checkout_path(recipe, cache_root)
    if (dest / ".git").is_dir():
        return dest
    if not network_allowed(fetch):
        raise RepoUnavailable(
            f"{recipe.name} is not checked out at {recipe.commit[:12]}; run with --fetch or {REPOS_NETWORK_ENV}=1 to fetch it"
        )
    _fetch(recipe, dest)
    return dest


def _fetch(recipe: RepoRecipe, dest: Path) -> None:
    """Fetch just the pinned commit. Falls back to a full clone where the server refuses a SHA fetch."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        _git(dest, "init", "--quiet")
        _git(dest, "remote", "add", "origin", recipe.url)
        _git(dest, "fetch", "--quiet", "--depth", "1", "origin", recipe.commit)
        _git(dest, "checkout", "--quiet", "FETCH_HEAD")
    except subprocess.CalledProcessError:
        for child in dest.iterdir():
            _remove(child)
        _git(dest.parent, "clone", "--quiet", recipe.url, dest.name)
        _git(dest, "checkout", "--quiet", recipe.commit)


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        for child in path.iterdir():
            _remove(child)
        path.rmdir()
    else:
        path.unlink()


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed program, arguments from a committed recipe
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    return result.stdout.strip()


def verify(recipe: RepoRecipe, root: Path) -> tuple[str, ...]:
    """Problems with a materialised checkout: empty means the recipe describes what is actually there.

    This is what keeps a recipe from drifting into fiction. Every field that claims something about the code
    -- the commit, the licence file, and each vulnerability's file and function -- is checked against the
    checkout rather than trusted.
    """
    problems: list[str] = []
    try:
        head = _git(root, "rev-parse", "HEAD")
    except (subprocess.CalledProcessError, OSError) as exc:
        return (f"cannot read HEAD: {exc}",)
    if head != recipe.commit:
        problems.append(f"HEAD is {head[:12]}, recipe pins {recipe.commit[:12]}")
    if not (root / recipe.license_file).is_file():
        problems.append(f"license_file {recipe.license_file} is not in the checkout")
    for item in recipe.known:
        problems.extend(_verify_known(item, root))
    return tuple(problems)


def _verify_known(item: KnownVulnerability, root: Path) -> tuple[str, ...]:
    path = root / item.file
    if not path.is_file():
        return (f"{item.id}: {item.file} is not in the checkout",)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not 1 <= item.line <= len(lines):
        return (f"{item.id}: line {item.line} is outside {item.file} ({len(lines)} lines)",)
    # The declared line is where the vulnerability is, not where the function opens, so look for the name in
    # a window above it rather than on it.
    window = lines[max(item.line - _FUNCTION_WINDOW, 0) : item.line]
    if not any(item.function in line for line in window):
        return (f"{item.id}: {item.function} is not within {_FUNCTION_WINDOW} lines above {item.file}:{item.line}",)
    return ()


def recipe_payload(recipe: RepoRecipe) -> dict[str, object]:
    """The recipe as it should appear in a measurement artifact (Req 4.2, 10.4)."""
    return {
        "name": recipe.name,
        "url": recipe.url,
        "commit": recipe.commit,
        "language": recipe.language,
        "license": recipe.license,
        "measures": list(recipe.measures),
        "known": [
            {
                "id": item.id,
                "family": item.family,
                "weakness": item.weakness,
                "location": item.location,
                "in_scope": item.in_scope,
            }
            for item in recipe.known
        ],
    }


def select(recipes: Sequence[RepoRecipe], name: str | None) -> tuple[RepoRecipe, ...]:
    if name in (None, "all"):
        return tuple(recipes)
    return tuple(recipe for recipe in recipes if recipe.name == name)
