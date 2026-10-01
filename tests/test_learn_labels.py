"""Labels from ground truth with provenance (learned-decision-engine task 4; Req 2.1-2.3, 7.1) on fixture
populations, pairs, adjudications and a fixture git history. The fail-closed source list is checked with a
v3-named population that must never be opened."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.learn import labels as L
from openultrasast.pairs import PairCase

DAY = 86_400
T0 = 1_600_000_000  # 2020-09-13


def _git(repo: Path, *args: str, when: int | None = None) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}
    if when is not None:
        env |= {"GIT_AUTHOR_DATE": f"{when} +0000", "GIT_COMMITTER_DATE": f"{when} +0000"}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()


def _commit(repo: Path, files: dict[str, str], message: str, when: int) -> str:
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message, when=when)
    return _git(repo, "rev-parse", "HEAD")


APP = (
    "<?php\nfunction show($id) {\n    $q = 'SELECT * WHERE id=' . $id;\n    return mysqli_query($db, $q);\n}\n"
    "function helper($x) {\n    return $x;\n}\n"
)
FIXED = APP.replace("'SELECT * WHERE id=' . $id", "'SELECT * WHERE id=' . intval($id)")
OTHER = "<?php\nfunction render($a) {\n    return $a;\n}\n"


def _case_repo(cache: Path, case_id: str) -> dict[str, str]:
    """A clone with history: old ordinary commits, a Chinese security commit, the vulnerable and fixed pins, a benign push."""
    repo = cache / "independent" / case_id
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    pins: dict[str, str] = {}
    _commit(repo, {"src/app.php": APP, "src/other.php": OTHER, "composer.json": '{"require": {"php": ">=7"}}'}, "initial import", T0)
    pins["ordinary"] = _commit(repo, {"src/other.php": OTHER.replace("$a;", "$a . '';")}, "tidy the render helper", T0 + 10 * DAY)
    pins["chinese"] = _commit(repo, {"src/admin.php": OTHER.replace("render", "grant")}, "修复越权访问问题", T0 + 20 * DAY)
    pins["touched_later"] = _commit(repo, {"src/app.php": APP + "\n"}, "whitespace in app", T0 + 30 * DAY)
    pins["near_fix"] = _commit(repo, {"src/other.php": OTHER}, "reword the renderer", T0 + 190 * DAY)
    pins["vulnerable"] = _commit(repo, {"src/app.php": APP}, "restore app", T0 + 200 * DAY)
    pins["fixed"] = _commit(repo, {"src/app.php": FIXED}, "cast the id", T0 + 260 * DAY)
    pins["benign_base"] = pins["fixed"]
    pins["benign_tip"] = _commit(repo, {"src/app.php": FIXED.replace("return $x;", "return $x; // same")}, "comment", T0 + 270 * DAY)
    return pins


def _layout(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    """A repository root with a v2-shaped population, a v3-named reserved population beside it, results files, and
    the sources.toml that lists the first and excludes the second."""
    root, cache = tmp_path / "repo", tmp_path / "cache"
    pins = _case_repo(cache, "acme-sqli")
    ind = root / "benchmarks" / "independent"
    ind.mkdir(parents=True)
    population = (
        '[[case]]\nid = "acme-sqli"\nrepo = "https://github.com/Acme/Shop.git"\nfamily = "injection"\nlanguage = "php"\n'
        f'advisory = ["CVE-2024-0001"]\nvulnerable = "{pins["vulnerable"]}"\nfixed = "{pins["fixed"]}"\n'
        'sites = ["src/app.php::show", "src/app.php::helper"]\n'
        f'benign = {{ base = "{pins["benign_base"]}", tip = "{pins["benign_tip"]}" }}\n'
    )
    (ind / "population-v2.toml").write_text(population)
    (ind / "population-v3-php.toml").write_text('[[case]]\nid = "secret"\n')
    (ind / "results-v2.json").write_text(
        json.dumps(
            {
                "precision_sample": [
                    {
                        "case": "acme-sqli",
                        "site": "src/other.php:3:render",
                        "family": "injection",
                        "verdict": "False, guarded",
                        "reason": "cast",
                    },
                    {
                        "case": "acme-sqli",
                        "site": "src/app.php:4:",
                        "family": "injection",
                        "verdict": "True, privileged",
                        "reason": "admin only",
                    },
                ]
            }
        )  # fmt: skip
    )
    sources = (
        'version = 1\n\n[[source]]\nid = "population-v2"\nkind = "population"\nfile = "benchmarks/independent/population-v2.toml"\n'
        'evaluation = ["benchmarks/independent/results-v2.json"]\nrecorded = "2026-09-28"\nstatus = "spent"\nmatching = "declared_sites"\n'
        'design_informed = true\ncache = "independent"\n\n'
        '[[source]]\nid = "adjudications"\nkind = "adjudications"\nfiles = ["benchmarks/independent/results-v2.json#precision_sample"]\n'
        'evaluation = []\nrecorded = "2026-09-28"\nstatus = "recorded"\n\n'
        '[[source]]\nid = "assumed_benign"\nkind = "history"\nrepositories_from = ["population-v2"]\nrecorded = "2026-09-30"\n'
        'status = "assumption"\nweight = 0.5\nmin_days_from_fix = 90\nscan_commits = 100\nmax_commits_per_repository = 10\n'
        'max_files_per_commit = 20\n\n[[excluded]]\nfile = "population-v3-php.toml"\nreason = "reserved"\n'
    )
    (root / "sources.toml").write_text(sources)
    return root, cache, pins


def _build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch | None = None) -> tuple[L.Build, dict[str, Any], list[str], dict[str, str]]:
    root, cache, pins = _layout(tmp_path)
    opened: list[str] = []
    if monkeypatch is not None:
        real_read = Path.read_text
        real_open = open

        def read_text(self: Path, *a: Any, **k: Any) -> str:
            opened.append(self.name)
            return real_read(self, *a, **k)

        def tracking_open(file: Any, *a: Any, **k: Any) -> Any:
            opened.append(Path(str(file)).name)
            return real_open(file, *a, **k)

        monkeypatch.setattr(Path, "read_text", read_text)
        monkeypatch.setattr("builtins.open", tracking_open)
    build, record = L.build_labels(root, sources_path=root / "sources.toml", cache=cache, created="2026-09-30")
    return build, record, opened, pins


def test_population_positives_negatives_and_the_untouched_function(tmp_path: Path) -> None:
    build, _, _, pins = _build(tmp_path)
    index = L.LabelIndex(build.labels)
    show = index.lookup("src/app.php::show", "injection")
    assert show is not None and show.label == 1 and show.design_informed and show.group == "acme/shop" and show.pin == pins["vulnerable"]
    negative = index.lookup("src/app.php::show", "injection", pin_role="fixed")
    assert negative is not None and negative.label == 0 and negative.pin == pins["fixed"]
    assert index.lookup("src/app.php::helper", "injection").label == 1  # type: ignore[union-attr]
    assert index.lookup("src/app.php::helper", "injection", pin_role="fixed") is None, "the fix did not touch helper: not a negative"
    assert index.lookup("src/app.php::nowhere", "injection") is None, "an unmatched candidate is unlabelled, never negative"
    deltas = {(r.candidate, r.direction, r.label) for r in build.labels if r.unit == "delta" and r.source == "population-v2"}
    assert ("src/app.php::show", "introduce", 1) in deltas and ("src/app.php::show", "repair", 0) in deltas
    benign = [r for r in build.labels if r.source == "benign_control"]
    assert [r.candidate for r in benign] == ["src/app.php::helper"] and benign[0].conditional == L.CONDITIONAL
    assert all(r.frameworks == () for r in build.labels if r.source == "population-v2"), "composer.json names no framework"


def test_adjudications_map_verdicts_and_resolve_a_missing_function(tmp_path: Path) -> None:
    build, _, _, _ = _build(tmp_path)
    rows = {r.candidate: r for r in build.labels if r.source == "adjudications"}
    assert rows["src/other.php::render"].label == 0 and "guarded" in rows["src/other.php::render"].evidence
    assert rows["src/app.php::show"].label == 1 and rows["src/app.php::show"].privileged, "the line resolved to its function"


def test_v3_is_never_opened_and_an_unlisted_source_cannot_label(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    build, _, opened, _ = _build(tmp_path, monkeypatch)
    assert build.labels and "population-v2.toml" in opened
    assert "population-v3-php.toml" not in opened, "the reserved population must never be read"
    sources = L.load_sources(tmp_path / "repo" / "sources.toml")
    with pytest.raises(L.LabelSourceError, match="not a label source"):
        sources.get("population-v3")
    guard = L.SourceGuard(sources, tmp_path / "repo")
    with pytest.raises(L.LabelSourceError, match="excluded"):
        guard.text("benchmarks/independent/population-v3-php.toml")
    with pytest.raises(L.LabelSourceError, match="not a listed label source"):
        guard.text("benchmarks/independent/results-v1.json")
    assert "population-v3-php.toml" not in opened


def test_a_source_naming_an_excluded_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "s.toml").write_text(
        '[[source]]\nid = "v3"\nkind = "population"\nfile = "b/population-v3-php.toml"\nrecorded = "x"\nstatus = "x"\n'
        '[[excluded]]\nfile = "population-v3-php.toml"\n'
    )
    with pytest.raises(L.LabelSourceError, match="excluded"):
        L.load_sources(tmp_path / "s.toml")


def test_a_source_without_its_evaluation_record_cannot_label(tmp_path: Path) -> None:
    root, cache, _ = _layout(tmp_path)
    (root / "benchmarks" / "independent" / "results-v2.json").unlink()
    with pytest.raises(L.LabelSourceError, match="evaluation record"):
        L.build_labels(root, sources_path=root / "sources.toml", cache=cache)


def test_assumed_benign_is_mined_separately_and_the_filter_is_multilingual(tmp_path: Path) -> None:
    build, record, _, pins = _build(tmp_path)
    mined = [r for r in build.labels if r.source == "assumed_benign"]
    assert {r.pin for r in mined} == {pins["ordinary"]}, "only the ordinary commit far from the fix, whose files no later fix touched"
    assert all(r.weight == 0.5 and r.conditional == L.CONDITIONAL and r.label == 0 for r in mined)
    history = record["assumed_benign_history"]
    assert history["rejected"]["other_language"] == 1, "the Chinese 'fix IDOR' commit is caught with no English word"
    assert history["rejected"]["near_fix"] >= 1 and history["rejected"]["later fix touches its files"] >= 1
    assert not [r for r in L.verified(build.labels) if r.source == "assumed_benign"], "never merged with verified negatives"
    assert "assumed_benign" in record["conditional_negatives"] and "assumed_benign" not in record["verified_pin_labels"]["by_source"]


@pytest.mark.parametrize(
    "message,reason",
    [
        ("修复越权访问问题", "other_language"),
        ("修复 IDOR", "english"),
        ("脆弱性の修正", "other_language"),
        ("보안 취약점 수정", "other_language"),
        ("исправлена уязвимость", "other_language"),
        ("Sicherheitslücke geschlossen", "other_language"),
        ("corrige une faille", "other_language"),
        ("Corrige una falla de seguridad", "other_language"),
        ("Fix CVE-2024-1234", "reference"),
        ("see GHSA-abcd-efgh-ijkl", "reference"),
        ("Escape the title (CWE-79)", "reference"),
        ("Prevent XSS in comments", "english"),
        ("sanitize input", "english"),
        ("Bump lodash from 4.17.20 to 4.17.21", "dependency"),
        ("fix: validate log file name more thoroughly", "english"),
        ("add password masking to the keyboard", "english"),
        ("增加文件名校验", "other_language"),
        ("Update README", None),
        ("修复拼写错误", None),
        ("重构代码结构", None),
        ("Añadir traducción al español", None),
        ("Refactor the settings page", None),
    ],
)
def test_security_filter(message: str, reason: str | None) -> None:
    assert L.security_reason(message) == reason


def test_repository_groups_merge_urls_forks_and_advisories() -> None:
    assert L.repo_name("https://github.com/Acme/Shop.git") == L.repo_name("git@github.com:acme/shop") == "acme/shop"
    assert L.repo_name("github.com/acme/shop/") == "acme/shop"
    groups = L.Groups({"someone/renamed": "acme/shop"})
    groups.add("https://github.com/acme/shop", advisory_ids={"CVE-2024-0001"}, commits=("a" * 40,))
    groups.add("https://github.com/fork/shop-mirror", advisory_ids={"CVE-2024-0001"})
    groups.add("https://gitlab.com/other/copy", commits=("a" * 40,))
    groups.add("someone/renamed")
    groups.add("unrelated/shop")
    assert groups.group("fork/shop-mirror") == groups.group("other/copy") == groups.group("someone/renamed") == groups.group("acme/shop")
    assert groups.group("unrelated/shop") != groups.group("acme/shop"), "a shared name alone does not merge"
    assert groups.merged == {"advisory": 1, "commit": 1, "alias": 1} and groups.count() == 2
    assert L.advisories("fix for cve-2024-0001 and GHSA-mh7h-gpmx-fggj") == {"CVE-2024-0001", "GHSA-MH7H-GPMX-FGGJ"}


VULN_PY = "def f(q):\n    return db.execute('SELECT ' + q)\n"
FIXED_PY = "def f(q):\n    return db.execute('SELECT ?', (q,))\n"


def _pair(
    name: str,
    *,
    tier: str = "advisory",
    unscorable: str | None = None,
    function: str | None = "f",
    repo: str = "",
    root: Path | None = None,
    vuln: str = VULN_PY,
    fixed: str = FIXED_PY,
    parent: str = "a" * 40,
    commit: str = "b" * 40,
) -> PairCase:
    expected = (ExpectedFinding(cwe="CWE-89", vulnerability_class="sqli", path="a.py", evidence="e", function=function),)
    folder = (root or Path("/nonexistent")) / "pairs" / name
    if root is not None:
        folder.mkdir(parents=True, exist_ok=True)
        header = f"# Provenance: fixture\n# commit: {commit}\n# parent: {parent}\n# function: {function}\n"
        (folder / "vuln.py").write_text(header + vuln)
        (folder / "fixed.py").write_text(header + fixed)
    return PairCase(
        name=name, slice="vfc", language="python", origin="o", vuln_file=folder / "vuln.py", fixed_file=folder / "fixed.py",
        relpath="a.py", expected=expected, min_recall=1.0, fix_policy="p", repo=repo, commit=commit, cve="CVE-2024-0001",
        review_tier=tier, unscorable=unscorable,
    )  # fmt: skip


def test_pairs_exclude_unscorable_and_title_and_group_by_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pairs").mkdir()
    (tmp_path / "pairs" / "catalog.toml").write_text("")
    (tmp_path / "s.toml").write_text(
        '[[source]]\nid = "pairs"\nkind = "pairs"\nfile = "pairs/catalog.toml"\nrecorded = "x"\nstatus = "x"\nexclude_tiers = ["title"]\n'
    )
    cases = (
        _pair("ok", repo="https://github.com/o/r", root=tmp_path), _pair("twin", unscorable="identical_twin"),
        _pair("titled", tier="title", root=tmp_path), _pair("nofn", function=None),
        _pair("fork", repo="https://github.com/x/r-fork", root=tmp_path),
    )  # fmt: skip
    monkeypatch.setattr("openultrasast.pairs.load_pair_catalog", lambda path: cases)
    build, record = L.build_labels(tmp_path, sources_path=tmp_path / "s.toml", cache=tmp_path, assumed_benign=False)
    refs = {r.source_ref for r in build.labels}
    assert refs == {"ok", "fork"}
    assert {r.group for r in build.labels} == {"o/r"}, "the fork shares the CVE, so it is one repository group"
    assert {(r.unit, r.label, r.pin_role) for r in build.labels if r.source_ref == "ok"} == {
        ("pin", 1, "vulnerable"),
        ("delta", 1, "vulnerable"),
        ("pin", 0, "fixed"),
        ("delta", 0, "fixed"),
    }
    assert record["skipped"] == {"pairs: label names no function": 1, "pairs: title tier (sensitivity arm)": 1, "pairs: unscorable pair": 1}
    family = record["verified_pin_labels"]["by_family"]["injection"]
    assert family["positive_groups"] == family["negative_groups"] == 1 and family["model"] == "insufficient"
    titled, _ = L.build_labels(tmp_path, sources_path=tmp_path / "s.toml", cache=tmp_path, assumed_benign=False, include_title=True)
    assert "titled" in {r.source_ref for r in titled.labels}


def _pair_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *cases: PairCase) -> tuple[L.Build, dict[str, Any]]:
    (tmp_path / "pairs").mkdir(exist_ok=True)
    (tmp_path / "pairs" / "catalog.toml").write_text("")
    source = '[[source]]\nid = "pairs"\nkind = "pairs"\nfile = "pairs/catalog.toml"\nrecorded = "x"\nstatus = "x"\n'
    (tmp_path / "s.toml").write_text(source)
    monkeypatch.setattr("openultrasast.pairs.load_pair_catalog", lambda path: cases)
    return L.build_labels(tmp_path, sources_path=tmp_path / "s.toml", cache=tmp_path, assumed_benign=False)


def _fixed_rows(build: L.Build, name: str) -> list[L.Label]:
    return [r for r in build.labels if r.source_ref == name and r.pin_role == "fixed"]


GATE = "def _gate(q):\n    return bool(q)\n"  # a guard helper of the same snapshot, same parameter list as the labelled f


def test_a_fixed_side_without_the_function_gives_no_negative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = "c" * 40
    cases = (
        _pair("gate", root=tmp_path, fixed=GATE, parent=snapshot, commit=snapshot),  # the kolega-ai-dev pointer shape
        _pair("other", root=tmp_path, fixed="def g(a, b):\n    return a\n"),  # a real fix, but no renamed equivalent
        _pair("unread", root=None),
    )
    build, record = _pair_build(tmp_path, monkeypatch, *cases)
    for name in ("gate", "other", "unread"):
        assert _fixed_rows(build, name) == [], name
        assert {(r.unit, r.label) for r in build.labels if r.source_ref == name} == {("pin", 1), ("delta", 1)}, "positives stay"
    assert record["pair_fixed_side"] == {"absent_fixed_side": {"labels": 3, "by_family": {"injection": 3}}, "fixed_side_moved": 0}
    assert record["skipped"] == {
        f"pairs: no fixed-side negative ({L.ABSENT_SAME_SNAPSHOT})": 1,
        f"pairs: no fixed-side negative ({L.ABSENT_NO_EQUIVALENT})": 1,
        f"pairs: no fixed-side negative ({L.ABSENT_UNREAD})": 1,
    }
    assert record["verified_pin_labels"]["by_family"]["injection"]["negative_groups"] == 0


def test_a_renamed_function_at_a_real_fix_is_a_moved_negative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    moved = "def f_safe(q):\n    return db.execute('SELECT ?', (q,))\n"
    build, record = _pair_build(tmp_path, monkeypatch, _pair("moved", root=tmp_path, fixed=moved, repo="https://github.com/o/r"))
    rows = _fixed_rows(build, "moved")
    assert {(r.unit, r.label, r.candidate, r.provenance) for r in rows} == {
        ("pin", 0, "a.py::f_safe", L.FIXED_MOVED),
        ("delta", 0, "a.py::f_safe", L.FIXED_MOVED),
    }
    assert all("f -> f_safe" in r.evidence for r in rows)
    assert record["pair_fixed_side"]["fixed_side_moved"] == 1 and record["pair_fixed_side"]["absent_fixed_side"]["labels"] == 0
    # the same rename in one snapshot (no fix commit) is a sibling function, never a negative
    snapshot = "d" * 40
    same, _ = _pair_build(tmp_path, monkeypatch, _pair("sibling", root=tmp_path, fixed=moved, parent=snapshot, commit=snapshot))
    assert _fixed_rows(same, "sibling") == []
    # two candidate renames are ambiguous: no negative
    two = moved + "\n\ndef f_other(q):\n    return q\n"
    ambiguous, _ = _pair_build(tmp_path, monkeypatch, _pair("two", root=tmp_path, fixed=two))
    assert _fixed_rows(ambiguous, "two") == []


def test_ordinary_pairs_and_matcher_limits_keep_their_negative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    js_vuln, js_fixed = (
        "module.exports = {\n  ps: function(pid) {\n    exec('ps ' + pid)\n  }\n}\n",
        ("module.exports = {\n  ps: function(pid) {\n    execFile('ps', [pid])\n  }\n}\n"),
    )
    cache = tmp_path / "pointer-cache"
    monkeypatch.setenv("OPENULTRASAST_PAIR_CACHE", str(cache))
    js = _pair("js", root=cache, function="ps", vuln=js_vuln, fixed=js_fixed)
    js = PairCase(**{**js.__dict__, "language": "javascript"})
    build, record = _pair_build(tmp_path, monkeypatch, _pair("plain", root=tmp_path), js)
    assert {(r.unit, r.candidate, r.provenance) for r in _fixed_rows(build, "plain")} == {("pin", "a.py::f", ""), ("delta", "a.py::f", "")}
    assert {r.candidate for r in _fixed_rows(build, "js")} == {"a.py::ps"}, "the pointer file in the pair cache was read"
    assert record["pair_fixed_side"]["absent_fixed_side"]["labels"] == 0
    assert record["verified_pin_labels"]["by_family"]["injection"]["negative_rows"] == 2


def test_the_snapshot_carries_counts_only(tmp_path: Path) -> None:
    _, record, _, pins = _build(tmp_path)
    text = json.dumps(record)
    for identity in ("acme", "shop", "show", "helper", "src/app.php", *pins.values()):
        assert identity not in text, f"{identity} leaked into the committed snapshot"
    assert record["verified_pin_labels"]["by_family"]["injection"]["positive_groups"] == 1


def test_frameworks_from_manifests_and_plugin_header() -> None:
    assert L.frameworks_from({"requirements.txt": "Django==4.2\nrequests"}) == ("django", "requests")
    assert L.frameworks_from({}, ["<?php\n/*\n * Plugin Name: Shop\n */"]) == ("wordpress",)
    assert L.frameworks_from({"package.json": '{"dependencies": {"express-session": "1"}}'}) == ()
