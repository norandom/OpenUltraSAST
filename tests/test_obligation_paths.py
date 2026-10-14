"""Bounded paths preserve file identity and call-site lines."""

import pytest

from openultrasast.semantic.obligations.paths import PathRecord, compose_paths


@pytest.mark.parametrize("depth,reached", [(0, False), (1, False), (2, True), (3, True)])
def test_depth_and_call_sites(depth, reached):
    graph = {"c.java::target": [("b.java::helper", 8)], "b.java::helper": [("a.java::doTest", 4)]}
    paths, unreached = compose_paths(
        callers=lambda p, f: graph.get(f"{p}::{f}", []), entries={"a.java::doTest"}, targets=[("c.java", "target")], max_depth=depth
    )
    assert bool(paths) == reached
    assert unreached == ([] if reached else ["c.java::target"])
    if reached:
        assert paths == [PathRecord((("a.java::doTest", 4), ("b.java::helper", 8), ("c.java::target", None)), "a.java::doTest", True)]


def test_entry_dedupe_cycles_fan_out_and_file_identity():
    graph = {"c.java::save": [("b.java::helper", 8), ("a.java::doTest", 4), ("a.java::doTest", 4)], "b.java::helper": [("c.java::save", 5)]}
    kwargs = dict(
        callers=lambda p, f: graph.get(f"{p}::{f}", []),
        entries={"a.java::doTest"},
        targets=[("c.java", "save"), ("other.java", "save"), ("a.java", "doTest"), ("c.java", "save")],
    )
    paths, unreached = compose_paths(**kwargs)
    assert len(paths) == 2 and unreached == ["other.java::save"]
    assert any(p.hops == (("a.java::doTest", None),) for p in paths)
    assert compose_paths(**kwargs, fan_out=1)[1] == ["c.java::save", "other.java::save"]


@pytest.mark.parametrize("key,value", [("max_depth", -1), ("fan_out", 0)])
def test_invalid_bounds(key, value):
    with pytest.raises(ValueError):
        compose_paths(callers=lambda p, f: [], entries=set(), targets=[], **{key: value})


def test_records_are_consumed_by_the_checker():
    from types import SimpleNamespace

    from openultrasast.semantic.facts import load_facts
    from openultrasast.semantic.ir import parse_file
    from openultrasast.semantic.obligations.check import check_obligations
    from openultrasast.semantic.obligations.dominance import OrderDominance
    from openultrasast.semantic.obligations.facts import load_obligation_facts

    text = "def entry(title):\n    return Book.query.filter_by(book_title=title).first()\n"
    paths, _ = compose_paths(callers=lambda p, f: [], entries={"app.py::entry"}, targets=[("app.py", "entry")])
    result = check_obligations(
        irs={"app.py": (parse_file("app.py", text, "python"), text)},
        entries=[
            SimpleNamespace(path="app.py", function_name="entry", access_level="unknown", kind="route", access_evidence=["fixture entry"])
        ],
        facts=load_obligation_facts(),
        flow_facts=load_facts(),
        policy=None,
        paths=paths,
        dominance=OrderDominance({"app.py": text}),
        store_shapes=(),
        min_siblings=3,
        assume_entries_protected=True,
    )
    (finding,) = result.findings
    assert finding.operation.function == "entry" and finding.label == "unguarded_path"


def test_callers_are_looked_up_once_per_node_and_never_without_entries():
    from openultrasast.semantic.obligations.paths import compose_paths

    calls: list[str] = []
    graph = {"a.py::leaf": [("a.py::mid", 3)], "a.py::mid": [("web.py::view", 9), ("a.py::other", 4)], "a.py::other": [("a.py::mid", 5)]}

    def callers(path, function):
        calls.append(f"{path}::{function}")
        return graph.get(f"{path}::{function}", [])

    paths, unreached = compose_paths(callers=callers, entries={"web.py::view"}, targets=[("a.py", "leaf"), ("a.py", "mid")], max_depth=3)
    assert [p.hops[0][0] for p in paths] == ["web.py::view"] * len(paths) and len(paths) >= 2 and unreached == []
    assert len(calls) == len(set(calls))  # once per node across both targets
    calls.clear()
    paths, unreached = compose_paths(callers=callers, entries=set(), targets=[("a.py", "leaf")])
    assert paths == [] and unreached == ["a.py::leaf"] and calls == []
