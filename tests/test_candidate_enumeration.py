"""Candidates come from the semantic IR, shaped by family (constrained-detector 1.1, Req 1.1, 1.2, 1.4-1.6).

The detector stops searching. Something deterministic decides what it looks at, which makes that enumerator a hard
ceiling on recall — measured before this was built at 12.1% for the pattern ruleset against 96.6% for the IR. The
ordering is part of the contract: the batches a later task forms, and therefore the sequence of model calls, must
be determined by the input alone.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_obligation_operations import APP  # noqa: E402

from openultrasast.learning.families import load_families  # noqa: E402

INJECTION = (
    "from flask import request\n"
    "import os\n"
    "import sqlite3\n\n\n"
    "@app.route('/run')\n"
    "def run():\n"
    "    raw = request.args.get('cmd')\n"
    "    command = 'echo ' + raw\n"
    "    os.system(command)\n"
    "    return 'ok'\n"
)


def _region(path: str = "app.py", function: str | None = "run"):  # type: ignore[no-untyped-def]
    from openultrasast.learning.detectors import Region

    return Region(path=path, function=function)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    (tmp_path / name).write_text(text)
    return tmp_path


def test_a_call_site_candidate_carries_what_the_model_needs_to_judge_it(tmp_path: Path) -> None:
    from openultrasast.learning.candidates import enumerate_candidates

    root = _write(tmp_path, "app.py", INJECTION)
    result = enumerate_candidates(root, _region(), "injection", taxonomy=load_families())
    assert result.reason == ""
    sites = {item.name: item for item in result.candidates}
    assert "os.system" in sites or "system" in sites, sorted(sites)
    sink = sites.get("os.system") or sites["system"]
    assert sink.kind == "call" and sink.function == "run" and sink.path == "app.py"
    assert sink.line == 10  # `from flask` 1, imports 2-3, blanks, decorator 6, def 7, raw 8, command 9
    assert sink.arg_texts == ("command",)
    # the chain the IR resolved, nearest first: command <- 'echo ' + raw <- request.args.get('cmd')
    assert any("raw" in step for step in sink.binding_chain), sink.binding_chain
    assert any("request" in step for step in sink.binding_chain), sink.binding_chain
    assert sink.id in {"app.py:10:os.system", "app.py:10:system"}


def test_the_family_decides_which_kinds_are_candidates() -> None:
    from openultrasast.learning.candidates import FAMILY_SHAPE

    taxonomy = load_families()
    assert set(FAMILY_SHAPE) == {family.id for family in taxonomy.families}, "every family says what carries its bug"
    assert FAMILY_SHAPE["injection"] == ("call",)
    assert FAMILY_SHAPE["access_control"] == ("operation",)
    assert "bind" in FAMILY_SHAPE["config_secrets"]
    assert "call" in FAMILY_SHAPE["prototype"]


def test_access_control_candidates_are_operations_with_the_guards_in_scope(tmp_path: Path) -> None:
    """An absence bug has no sink. Its candidate is the operation, and what the model needs is what guards it."""
    from openultrasast.learning.candidates import enumerate_candidates

    root = _write(tmp_path, "app.py", APP)
    guarded = enumerate_candidates(root, _region(function="guarded"), "access_control", taxonomy=load_families())
    assert guarded.reason == "" and guarded.candidates
    assert all(item.kind == "operation" for item in guarded.candidates)
    assert any("login_required" in guard for item in guarded.candidates for guard in item.guards)
    # `leaky` and `constrained` both constrain by `filter_by`; what separates them is where the constraining value
    # came from, and that is the binding chain the IR resolved — the work the model used to do by grepping.
    leaky = enumerate_candidates(root, _region(function="leaky"), "access_control", taxonomy=load_families())
    constrained = enumerate_candidates(root, _region(function="constrained"), "access_control", taxonomy=load_families())
    leaky_site = next(item for item in leaky.candidates if item.name.endswith("filter_by"))
    good_site = next(item for item in constrained.candidates if item.name.endswith("filter_by"))
    assert "user_id=owner" in leaky_site.arg_texts and "user_id=user_id" in good_site.arg_texts
    assert any("request.args.get" in step for step in leaky_site.binding_chain), leaky_site.binding_chain
    assert any("request.user.id" in step for step in good_site.binding_chain), good_site.binding_chain


def test_a_side_the_parser_rejects_yields_no_candidates_and_says_why(tmp_path: Path) -> None:
    from openultrasast.learning.candidates import enumerate_candidates

    root = _write(tmp_path, "app.py", "def broken(:\n    pass\n")
    result = enumerate_candidates(root, _region(function="broken"), "injection", taxonomy=load_families())
    assert result.candidates == () and result.reason == "unsupported_language"


def test_a_labeled_function_with_nothing_to_judge_says_no_candidate(tmp_path: Path) -> None:
    from openultrasast.learning.candidates import enumerate_candidates

    root = _write(tmp_path, "app.py", "def empty():\n    return 1\n")
    result = enumerate_candidates(root, _region(function="empty"), "injection", taxonomy=load_families())
    assert result.candidates == () and result.reason == "no_candidate"


def test_the_bound_is_a_constant_and_the_overflow_is_counted(tmp_path: Path) -> None:
    from openultrasast.learning.candidates import MAX_CANDIDATES_PER_CALL, enumerate_candidates

    # one call per line, so the arithmetic is the bound and not the fixture
    body = "\n".join(f"    sink_{index}(value)" for index in range(MAX_CANDIDATES_PER_CALL + 5))
    root = _write(tmp_path, "app.py", f"def many(value):\n{body}\n")
    result = enumerate_candidates(root, _region(function="many"), "injection", taxonomy=load_families())
    assert len(result.candidates) == MAX_CANDIDATES_PER_CALL
    assert result.discarded == 5


def test_enumerating_twice_returns_an_identical_sequence(tmp_path: Path) -> None:
    """The batches, and therefore the sequence of model calls, are determined by the input alone (Req 2.4)."""
    from openultrasast.learning.candidates import enumerate_candidates

    root = _write(tmp_path, "app.py", APP)
    taxonomy = load_families()
    first = enumerate_candidates(root, _region(function="constrained"), "injection", taxonomy=taxonomy)
    second = enumerate_candidates(root, _region(function="constrained"), "injection", taxonomy=taxonomy)
    assert [item.id for item in first.candidates] == [item.id for item in second.candidates]
    assert [item.id for item in first.candidates] == sorted({item.id for item in first.candidates}, key=_order(first))


def _order(result):  # type: ignore[no-untyped-def]
    index = {item.id: (item.path, item.line, item.name) for item in result.candidates}
    return lambda identifier: index[identifier]


def test_a_region_without_a_function_enumerates_the_whole_file(tmp_path: Path) -> None:
    from openultrasast.learning.candidates import enumerate_candidates

    root = _write(tmp_path, "app.py", APP)
    whole = enumerate_candidates(root, _region(function=None), "injection", taxonomy=load_families())
    named = enumerate_candidates(root, _region(function="leaky"), "injection", taxonomy=load_families())
    assert len(whole.candidates) >= len(named.candidates)
    assert {item.function for item in whole.candidates} > {"leaky"}


@pytest.mark.parametrize("family", ["injection", "path", "deserialization", "untrusted_destination", "config_secrets"])
def test_every_family_shape_enumerates_something_on_a_file_that_has_it(tmp_path: Path, family: str) -> None:
    from openultrasast.learning.candidates import enumerate_candidates

    root = _write(tmp_path, "app.py", INJECTION)
    result = enumerate_candidates(root, _region(), family, taxonomy=load_families())
    assert result.reason in {"", "no_candidate"}
    if family in {"injection", "path", "deserialization", "untrusted_destination"}:
        assert result.candidates, f"{family} takes call sites and this file has three"
