"""Authored fix pairs only: no store, models, containers, or population files."""

from __future__ import annotations

import importlib.util
import json
from dataclasses import replace

import pytest

from openultrasast.learn.folds import Fold
from openultrasast.learn.mechanisms import Pair, mine_pairs


def pair(before: str, after: str, *, language: str = "python", family: str = "output_encoding", repo: str = "owner/alpha") -> Pair:
    return Pair("pair-" + repo, repo, repo, language, family, before, after)


def repeated(p: Pair, **kwargs):
    return mine_pairs([p, replace(p, id="pair-beta", repository="owner/beta", group="owner/beta")], **kwargs)


def test_learn_mechanisms_sanitizer_return_and_def_use():
    p = pair("def f(x):\n    return x", "def f(x):\n    y = html.escape(x)\n    return y")
    result = repeated(p)
    assert [(c["form"], c["pattern"]) for c in result.candidates] == [("sanitizer", {"callee": "html.escape", "argument": 0})]
    assert result.candidates[0]["repository_count"] == 2
    assert "owner/alpha" not in json.dumps(result.record)
    assert result.record["pairs_mined"] == 2


def test_learn_mechanisms_javascript():
    p = pair("function f(x) { res.send(x); }", "function f(x) { const y = escapeHtml(x); res.send(y); }", language="javascript")
    assert repeated(p).candidates[0]["pattern"] == {"callee": "escapeHtml", "argument": 0}


def test_learn_mechanisms_guard_and_known():
    p = pair(
        "def f(u):\n    redirect(u)",
        "def f(u):\n    if not is_safe_url(u):\n        abort()\n    redirect(u)",
        family="untrusted_destination",
    )
    candidate = repeated(p).candidates[0]
    assert candidate["form"] == "guard"
    assert candidate["pattern"] == {"callee": "is_safe_url", "argument": 0, "predicate": "truthy"}
    assert candidate["known"] is True
    assert not any(f["eligible"] for f in candidate["folds"])


@pytest.mark.skipif(importlib.util.find_spec("tree_sitter_php") is None, reason="PHP tree-sitter wheel unavailable")
def test_learn_mechanisms_php_safe_argument_and_echo():
    p = pair(
        "function f($d) { return unserialize($d); }",
        "function f($d) { return unserialize($d, ['allowed_classes' => false]); }",
        language="php",
        family="deserialization",
    )
    assert repeated(p).candidates[0]["pattern"] == {"callee": "unserialize", "argument": 1, "key": "allowed_classes", "value": False}
    assert repeated(p).candidates[0]["form"] == "safe_argument"
    p = pair("function f($x) { echo $x; }", "function f($x) { echo htmlspecialchars($x); }", language="php")
    assert repeated(p).candidates[0]["form"] == "sanitizer"


def test_learn_mechanisms_safe_alternative():
    p = pair("def f(x):\n    return yaml.load(x)", "def f(x):\n    return yaml.safe_load(x)", family="deserialization")
    candidate = repeated(p).candidates[0]
    assert candidate["form"] == "safe_alternative"
    assert candidate["pattern"] == {"callee": "yaml.load", "replacement": "yaml.safe_load"}
    assert candidate["known"] is True


def test_learn_mechanisms_keyword():
    p = pair("def f(x):\n    subprocess.run(x, shell=True)", "def f(x):\n    subprocess.run(x, shell=False)", family="injection")
    result = repeated(p)
    assert any(c["pattern"] == {"callee": "subprocess.run", "key": "shell", "value": False} for c in result.candidates)


def test_learn_mechanisms_one_repository_and_local_helpers_rejected():
    p = pair("def f(x):\n    return x", "def f(x):\n    return cleanse(x)")
    assert mine_pairs([p]).candidates == []
    local = replace(p, fixed="def cleanse(x):\n    return x\ndef f(x):\n    return cleanse(x)")
    result = repeated(local)
    assert result.candidates == []
    assert result.record["skips"]["local_definition"] == 2
    assert repeated(replace(p, fixed="def f(x):\n    return alpha_escape(x)")).candidates == []


def test_learn_mechanisms_folds_exclude_proposers():
    p = pair("def f(x):\n    return x", "def f(x):\n    return cleanse(x)")
    folds = [Fold("outer", "outer-0", frozenset({p.group})), Fold("outer", "outer-1", frozenset({"elsewhere"}))]
    candidate = repeated(p, folds=folds).candidates[0]
    assert [(f["repository_count"], f["eligible"]) for f in candidate["folds"]] == [(1, False), (2, True)]
    assert candidate["folds"][0]["proposing_pairs"] == ["pair-beta"]


@pytest.mark.parametrize(
    "fixed",
    [
        "def f(x):\n    cleanse(x)\n    return x",
        "def f(x):\n    y = cleanse(x)\n    y = 'constant'\n    return y",
        "def f(x):\n    if is_safe_url(x):\n        pass\n    redirect(x)",
    ],
)
def test_learn_mechanisms_unrelated_calls_are_not_candidates(fixed):
    before = "def f(x):\n    redirect(x)" if "redirect" in fixed else "def f(x):\n    return x"
    family = "untrusted_destination" if "redirect" in fixed else "output_encoding"
    assert repeated(pair(before, fixed, family=family)).candidates == []


def test_learn_mechanisms_skips_and_determinism():
    p = pair("def f(x):\n    return x", "def f(x):\n    return cleanse(x)")
    assert repeated(p) == repeated(p)
    assert repeated(replace(p, fixed="def broken(")).record["skips"]["unparseable"] == 2
    assert repeated(replace(p, language="ruby")).record["skips"]["unsupported_language"] == 2
    assert (
        repeated(replace(p, fixed="def f(x):\n    for y in x:\n        cleanse(y)\n    return x")).record["skips"]["unsupported_shape"] == 2
    )


def test_learn_mechanisms_guard_must_test_sink_value():
    p = pair(
        "def f(x, u):\n    redirect(u)",
        "def f(x, u):\n    if not check(x):\n        abort()\n    redirect(u)",
        family="untrusted_destination",
    )
    assert repeated(p).candidates == []


def test_learn_mechanisms_existing_path_call_is_not_new():
    p = pair("def f(x):\n    return html.escape(x)", "def f(x):\n    y = html.escape(x)\n    return y")
    assert repeated(p).candidates == []


def test_learn_mechanisms_missing_grammar_is_counted(monkeypatch):
    monkeypatch.setattr("openultrasast.learn.mechanisms.grammar_for", lambda language: None)
    result = repeated(pair("def f(x):\n    return x", "def f(x):\n    return cleanse(x)"))
    assert result.candidates == []
    assert result.record["skips"] == {"grammar_unavailable": 2}


def test_learn_mechanisms_pair_identity_and_unread_inputs():
    from openultrasast.learn.mechanisms import pairs_from_rows

    base = {
        "repo": "owner/alpha",
        "group": "owner/alpha",
        "source": "pairs",
        "candidate": "app.py::f",
        "language": "python",
        "family": "output_encoding",
        "profile": "static",
        "unit": "pin",
    }
    rows = [{**base, "label": label, "excerpt_sha": str(label)} for label in (0, 1)]
    pairs, skips, count = pairs_from_rows(rows, lambda sha: "def f(x):\n    return x")
    assert len(pairs) == count == 1 and not skips
    assert pairs_from_rows(rows + [rows[0]], lambda sha: "code")[1] == {"ambiguous_pair": 1}
    assert pairs_from_rows(rows[:1], lambda sha: "code")[1] == {"incomplete_pair": 1}
    assert pairs_from_rows(rows, lambda sha: None)[1] == {"unreadable_excerpt": 1}
    forbidden = [{**row, "source": "population-v3"} for row in rows]
    assert pairs_from_rows(forbidden, lambda sha: pytest.fail("must not read excluded excerpts"))[1] == {"excluded_source": 2}


def memory_store(tmp_path):
    from openultrasast.plane.memory import FileStore, row_id

    store = FileStore(tmp_path / "memory")
    rows = []
    for repo in ("owner/alpha", "owner/beta", "owner/gamma"):
        for label in (0, 1):
            code = "def f(x):\n    return x" if label else "def f(x):\n    return cleanse(x)"
            sha = store.put_blob("excerpts", code.encode())
            rows.append(
                {
                    "id": row_id("example", "test", "test", f"{repo}:{label}"),
                    "kind": "example",
                    "repo": repo,
                    "pin": str(label) * 40,
                    "run": "test",
                    "task": "test",
                    "population": "pairs",
                    "split": "pairs",
                    "image": "host",
                    "candidate": "app.py::f",
                    "family": "output_encoding",
                    "language": "python",
                    "profile": "static",
                    "label": label,
                    "source": "pairs",
                    "group": repo,
                    "unit": "pin",
                    "x": {},
                    "instruments": {},
                    "excerpt_sha": sha,
                }
            )
    store.put_rows(rows)
    return store


def test_learn_mechanisms_store_cli_and_privacy(tmp_path, monkeypatch):
    from openultrasast.cli import main
    from openultrasast.learn.mechanisms import RECORD, mine_store

    store = memory_store(tmp_path)
    result = mine_store(store)
    assert result.record["complete_pairs"] == 3
    assert result.record["excerpt_bytes_read"] > 0
    assert len(result.candidates) == 1
    assert len(result.candidates[0]["folds"]) == 5
    monkeypatch.setenv("OUSAST_RESULTS", str(tmp_path / "results"))
    root = tmp_path / "repo"
    out = tmp_path / "results" / "plane" / "mining" / "candidates.jsonl"
    assert main(["learn", "mechanisms", "mine", "--memory", f"file://{tmp_path / 'memory'}", "--out", str(out), "--root", str(root)]) == 0
    record = (root / RECORD).read_text()
    assert all(repo not in record for repo in ("alpha", "beta", "gamma"))
    assert json.loads(out.read_text())["repository_count"] == 3
    assert main(["learn", "mechanisms", "mine", "--memory", f"file://{tmp_path / 'empty'}", "--out", str(out), "--root", str(root)]) == 2
    assert json.loads((root / RECORD).read_text())["status"] == "no_mineable_pairs"


def test_learn_mechanisms_output_location_rejected(tmp_path):
    from openultrasast.learn.mechanisms import MiningResult, write_result

    root = tmp_path / "repo"
    with pytest.raises(ValueError, match="outside"):
        write_result(MiningResult([], {}), root / "candidate.jsonl", root=root, results=tmp_path)
    assert not root.exists()


@pytest.mark.parametrize("signature,source", [("", "input()"), ("request", "request.get_json()")])
def test_learn_mechanisms_source_calls(signature, source):
    p = pair(f"def f({signature}):\n    return {source}", f"def f({signature}):\n    return html.escape({source})")
    assert repeated(p).candidates[0]["pattern"] == {"callee": "html.escape", "argument": 0}


def test_learn_mechanisms_inserted_log_is_not_sink_replacement():
    p = pair("def f(x):\n    yaml.load(x)", "def f(x):\n    logger.info(x)\n    yaml.safe_load(x)", family="deserialization")
    result = repeated(p)
    assert result.candidates == []
    assert result.record["skips"]["ambiguous_sink"] == 2


def test_learn_mechanisms_keyword_reordering_is_not_change():
    p = pair(
        "def f(x):\n    subprocess.run(x, shell=False, timeout=10)",
        "def f(x):\n    subprocess.run(x, timeout=10, shell=False)",
        family="injection",
    )
    assert repeated(p).candidates == []


def test_learn_mechanisms_legacy_pair_ids_are_repository_scoped(tmp_path):
    from openultrasast.learn.mechanisms import mine_store

    result = mine_store(memory_store(tmp_path))
    candidate = result.candidates[0]
    assert len(candidate["proposing_pairs"]) == 3
    assert all(len(ids) == 2 for ids in candidate["proposing_examples"].values())
    assert len({i for ids in candidate["proposing_examples"].values() for i in ids}) == 6


def test_learn_mechanisms_runtime_callable_is_unsupported():
    p = pair("def f(x, clean):\n    return x", "def f(x, clean):\n    return clean(x)")
    result = repeated(p)
    assert result.candidates == []
    assert result.record["skips"]["unsupported_shape"] == 2


def test_learn_mechanisms_language_support_is_not_pooled():
    p = pair("def f(x):\n    return x", "def f(x):\n    return cleanse(x)")
    js = pair("function f(x) { return x; }", "function f(x) { return cleanse(x); }", language="javascript", repo="owner/beta")
    assert mine_pairs([p, js]).candidates == []


def test_learn_mechanisms_guard_inside_branch_and_numbered_excerpt():
    p = pair(
        "  10  def f(x):\n  11      redirect(x)",
        "  20  def f(x):\n  21      if is_safe_url(x):\n  22          redirect(x)",
        family="untrusted_destination",
    )
    candidate = repeated(p).candidates[0]
    assert candidate["form"] == "guard" and candidate["pattern"]["predicate"] == "truthy"


@pytest.mark.skipif(importlib.util.find_spec("tree_sitter_php") is None, reason="PHP tree-sitter wheel unavailable")
def test_learn_mechanisms_php_receiver_normalization():
    p = pair("function f($x, $helper) { echo $x; }", "function f($x, $helper) { echo $helper->escape($x); }", language="php")
    assert repeated(p).candidates[0]["pattern"] == {"callee": "escape", "argument": 0}
