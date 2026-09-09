"""contributor-scan task 1.1: regions come from the code, not from a label (Req 2).

A contributor cannot tell the tool which function is interesting -- that is the whole question they are
asking. Pair scoring could rely on a labelled function; a repository scan cannot. Regions therefore come from
entry points, with a file-level fallback that says so, and each region carries only the families its shape and
language actually admit.
"""

from __future__ import annotations


def _entry(path="api/users.py", function="update_password", access="public", boundary="network"):  # type: ignore[no-untyped-def]
    from openultrasast.mapping import EntryPointRecord

    return EntryPointRecord(
        path=path,
        line=10,
        end_line=40,
        function_name=function,
        name=function,
        kind="route",
        access_level=access,
        trust_boundary=boundary,
        access_evidence=[],
        conditions=[],
        provenance="decorator",
        rationale="",
    )


def _target(path="api/users.py", language="python"):  # type: ignore[no-untyped-def]
    from openultrasast.preprocess import FileTarget

    return FileTarget(
        path=path,
        absolute_path=f"/repo/{path}",
        language=language,
        loc=100,
        tags=[],
        has_fuzz_entry_point=False,
        static_hints=[],
        reachability_hints=[],
    )


def test_an_entry_point_becomes_a_region() -> None:
    from openultrasast.model.regions import regions_for

    regions = regions_for([_entry()], [_target()])
    assert len(regions) == 1
    assert regions[0].path == "api/users.py" and regions[0].function == "update_password"
    assert regions[0].source == "entry_point"


def test_a_file_with_no_entry_point_still_gets_a_region_that_says_so() -> None:
    """Req 2.2: a fallback is fine; a fallback that pretends to be an entry point is not."""
    from openultrasast.model.regions import regions_for

    regions = regions_for([], [_target(path="lib/util.py")])
    assert len(regions) == 1
    assert regions[0].function is None
    assert regions[0].source == "file_fallback"


def test_regions_carry_only_families_their_language_has_specs_for() -> None:
    """Req 2.3. Asking every family of every region is the unbounded version of this."""
    from openultrasast.model.regions import regions_for

    python = regions_for([_entry()], [_target()])[0]
    assert "injection" in python.families
    # C has no dominance or config facts; a C region must not claim them.
    c_region = regions_for([], [_target(path="src/x.c", language="c")])[0]
    assert "access_control" not in c_region.families
    assert "config_secrets" not in c_region.families


def test_an_absence_family_is_only_offered_where_there_is_a_handler() -> None:
    """An obligation needs a reachable operation. A library file with no entry point has no handler to
    be inconsistent about, so offering access_control there is asking a question the arbiter cannot answer."""
    from openultrasast.model.regions import regions_for

    handler = regions_for([_entry()], [_target()])[0]
    library = regions_for([], [_target(path="lib/util.py")])[0]
    assert "access_control" in handler.families
    assert "access_control" not in library.families


def test_public_entry_points_outrank_internal_ones() -> None:
    """Ranking uses what EntryPointRecord already carries rather than inventing a signal."""
    from openultrasast.model.regions import regions_for

    entries = [_entry(path="a.py", function="internal", access="local-only"), _entry(path="b.py", function="exposed", access="public")]
    targets = [_target(path="a.py"), _target(path="b.py")]
    ranked = regions_for(entries, targets)
    assert [r.function for r in ranked] == ["exposed", "internal"], "highest risk first"
    assert ranked[0].rank > ranked[1].rank


def test_the_order_is_total_so_two_runs_agree() -> None:
    from openultrasast.model.regions import regions_for

    entries = [_entry(path=f"{c}.py", function=f"h{i}") for i, c in enumerate("abc")]
    targets = [_target(path=f"{c}.py") for c in "abc"]
    assert regions_for(entries, targets) == regions_for(entries, targets)


def test_a_file_with_an_entry_point_is_not_also_a_fallback_region() -> None:
    """Otherwise every handler is scanned twice and the budget is spent on duplicates."""
    from openultrasast.model.regions import regions_for

    regions = regions_for([_entry()], [_target()])
    assert len(regions) == 1


def test_an_unsupported_language_yields_no_region() -> None:
    from openultrasast.model.regions import regions_for

    assert regions_for([], [_target(path="x.rb", language="ruby")]) == ()
