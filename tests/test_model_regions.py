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
    handlers = [r for r in regions if r.source == "entry_point"]
    assert len(handlers) == 1
    assert handlers[0].path == "api/users.py" and handlers[0].function == "update_password"


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
    ranked = [r for r in regions_for(entries, targets) if r.source == "entry_point"]
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
    assert not [r for r in regions if r.source == "file_fallback"]


def test_a_function_scoped_file_still_gets_its_module_body_asked_about() -> None:
    """contributor-scan 2.5. Settings, route registration and globals are in no function.

    A file whose regions are all function-scoped cannot see them -- every query filters by function name --
    and a file-level region beside them would report every handler's findings a second time. So the module
    body gets a region of its own, which partitions the file rather than overlapping it. VAmPI's
    `host='0.0.0.0'` sits in `if __name__ == '__main__':` and was reported nowhere without this.
    """
    from openultrasast.model.regions import MODULE_SCOPE, regions_for

    regions = regions_for([_entry()], [_target()])

    module = [r for r in regions if r.function == MODULE_SCOPE]
    assert len(module) == 1, "exactly one module region per function-scoped file"
    assert module[0].path == "api/users.py"
    assert module[0].source == "module_scope"
    assert module[0].rank < min(r.rank for r in regions if r.source == "entry_point")


def test_a_file_level_region_is_not_given_a_second_module_region() -> None:
    """A file-level region already covers the module body; a second one would duplicate it."""
    from openultrasast.model.regions import MODULE_SCOPE, regions_for

    regions = regions_for([], [_target(path="config.py")])

    assert [r.function for r in regions] == [None]
    assert not [r for r in regions if r.function == MODULE_SCOPE]


def test_the_main_guard_marker_is_translated_to_module_scope() -> None:
    """`__main__` is what the mapper emits for `if __name__ == '__main__':`, not a function that exists.

    Sent to the engine as a function name it matched nothing at all, which is why a module-level setting
    could be reported zero times while looking like a scanned file.
    """
    from openultrasast.model.regions import MODULE_SCOPE, regions_for

    regions = regions_for([_entry(path="app.py", function="__main__", access="local-only")], [_target(path="app.py")])

    assert MODULE_SCOPE in {r.function for r in regions}
    assert "__main__" not in {r.function for r in regions}


def test_an_unsupported_language_yields_no_region() -> None:
    from openultrasast.model.regions import regions_for

    assert regions_for([], [_target(path="x.rb", language="ruby")]) == ()


def test_nameless_entry_points_do_not_duplicate_a_file_already_covered() -> None:
    """The mapper can emit several entry points for one file, some with no function name.

    On a ten-line Flask file it produced three: `ping`, and two nameless ones. Turning each into a region
    scanned the same file three times and multiplied the Joern invocations by three for no new coverage.
    A nameless entry point is the file; if a named region already covers that file, it adds nothing.
    """
    from openultrasast.model.regions import regions_for

    entries = [
        _entry(function="ping", access="public"),
        _entry(function=None, access="local-only"),
        _entry(function=None, access="public"),
    ]
    regions = regions_for(entries, [_target()])
    assert [r.function for r in regions if r.source == "entry_point"] == ["ping"]
    # The module region partitions the file rather than duplicating the handler, so it is not a second pass.
    assert not [r for r in regions if r.function is None]


def test_a_file_with_only_nameless_entry_points_still_gets_one_region() -> None:
    from openultrasast.model.regions import regions_for

    regions = regions_for([_entry(function=None), _entry(function=None)], [_target()])
    assert [r.function for r in regions] == [None], "two nameless entries are one file-level region"


def test_two_named_handlers_in_one_file_are_two_regions() -> None:
    """Deduping must not collapse genuinely distinct handlers."""
    from openultrasast.model.regions import regions_for

    regions = regions_for([_entry(function="a"), _entry(function="b")], [_target()])
    assert sorted(r.function for r in regions if r.source == "entry_point") == ["a", "b"]


def test_a_module_body_is_not_offered_the_handler_families() -> None:
    """`if __name__ == '__main__':` is not an endpoint, whatever the mapper labelled it.

    Carrying `access_control` into a module region entailed a missing authorization check on a main guard --
    a finding with no possible remediation, on the first repository the region existed.
    """
    from openultrasast.model.regions import MODULE_SCOPE, regions_for

    regions = regions_for([_entry(path="app.py", function="__main__", access="local-only")], [_target(path="app.py")])
    module = next(r for r in regions if r.function == MODULE_SCOPE)

    assert "access_control" not in module.families
    assert "config_secrets" in module.families, "settings are exactly what module bodies carry"
    assert module.source == "module_scope"


def test_a_project_that_declares_nothing_is_not_penalised() -> None:
    """contributor-scan 2.10: silence is not exclusion.

    `declared_sources` returns None for a repository with no build files this can read, and every region
    stays shipped. A tool that quietly deprioritised code because it could not parse a Makefile would be
    worse than one that ignores the question.
    """
    from openultrasast.model.regions import regions_for

    regions = regions_for([_entry()], [_target()], shipped=None)

    assert all(region.shipped for region in regions)


def test_what_the_project_does_not_ship_ranks_below_what_it_does() -> None:
    """libpng's twenty-five entry points were all `main()` in example programs and test tools."""
    from openultrasast.model.regions import regions_for

    entries = [_entry(path="lib.py", function="handler", access="public"), _entry(path="example.py", function="main", access="public")]
    targets = [_target(path="lib.py"), _target(path="example.py")]

    regions = regions_for(entries, targets, shipped=frozenset({"lib.py"}))

    ordered = [(r.path, r.shipped) for r in regions]
    assert ordered[0] == ("lib.py", True), "shipped code comes first whatever the rank says"
    assert ("example.py", False) in ordered, "not shipped is not unscanned"
