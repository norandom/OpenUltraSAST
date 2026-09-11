"""The `[[layout]]` facts: which paths are somebody else's code, which are tests -- rows, not constants."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_layout_rows_load_and_match() -> None:
    from openultrasast.model.layout import is_test_path, is_vendored, layout_facts

    rows = layout_facts("php")
    assert [r.id for r in rows] == ["php_composer_and_wordpress"]
    assert is_vendored("includes/vendor/whichbrowser/parser/data/profiles.php", rows)
    assert is_vendored("vendor/autoload.php", rows)
    assert not is_vendored("classes/class.mail.php", rows)
    assert is_test_path("test-mail.php", rows) and is_test_path("tests/unit/MailTest.php", rows)
    assert is_test_path("classes/FooTest.php", rows)
    assert not is_test_path("classes/class.mail.php", rows) and not is_test_path("includes/testimonials.php", rows)


def test_a_layout_row_without_an_id_is_refused(tmp_path: Path) -> None:
    from openultrasast.semantic.facts import FactLoadError, load_facts

    (tmp_path / "php.toml").write_text('[[layout]]\nvendored = ["vendor/"]\n')
    with pytest.raises(FactLoadError):
        load_facts(tmp_path)


def test_vendored_trees_leave_the_targets(tmp_path: Path) -> None:
    """A bundled library is a separate unit -- analysed as one or not at all, never as part of the project
    that bundles it. Measured before the row: 207 of WP Statistics's 357 PHP files were vendored."""
    from openultrasast.preprocess import preprocess_repository

    (tmp_path / "classes").mkdir()
    (tmp_path / "classes" / "a.php").write_text("<?php\n")
    (tmp_path / "includes" / "vendor" / "lib").mkdir(parents=True)
    (tmp_path / "includes" / "vendor" / "lib" / "b.php").write_text("<?php\n")
    _, targets = preprocess_repository(tmp_path)
    assert sorted(t.path for t in targets) == ["classes/a.php"]


def test_vendored_directories_are_named_shallowest_first(tmp_path: Path) -> None:
    from openultrasast.model.layout import vendored_directories

    (tmp_path / "includes" / "vendor" / "x" / "vendor").mkdir(parents=True)
    (tmp_path / "vendor").mkdir()
    (tmp_path / "src").mkdir()
    assert vendored_directories(tmp_path) == ("includes/vendor", "vendor")


def test_test_regions_are_not_product_and_order_last() -> None:
    """In scope -- a test that reaches a sink still names the sink -- but after the product's regions."""
    from openultrasast.model.layout import with_layout
    from openultrasast.model.regions import ScanRegion

    product = ScanRegion(path="classes/class.mail.php", function="_delete_files", language="php", families=("path",), rank=0.3, source="x")
    test = ScanRegion(path="test-mail.php", function="hook_mwform_admin_mail", language="php", families=("path",), rank=0.3, source="x")
    declared = ScanRegion(path="tests/fixture.php", function="f", language="php", families=("path",), rank=0.3, source="x", shipped=True)
    out = {r.path: r.shipped for r in with_layout([product, test])}
    assert out == {"classes/class.mail.php": True, "test-mail.php": False}
    assert with_layout([declared])[0].shipped is False, (
        "a test path is a test path; only a manifest that lists it as a source would say otherwise, and it is applied first"
    )


def test_the_scan_hands_the_vendored_trees_to_the_build(tmp_path: Path) -> None:
    from openultrasast.model.regions import ScanRegion
    from openultrasast.model.scan import ScanBudget, scan_repository

    (tmp_path / "vendor").mkdir()
    seen: dict[str, object] = {}

    class _Backend:
        def available(self) -> bool:
            return True

        def build(self, root, *, language="", exclude=()):  # type: ignore[no-untyped-def]
            from openultrasast.cpg.backend import CpgResult

            seen["exclude"] = tuple(exclude)
            return CpgResult(cpg_path=Path("cpg.bin"), run=lambda q, p: [], run_batch=lambda q, r: {rid: [] for rid in r})

    region = ScanRegion(path="a.php", function="f", language="php", families=("injection",), rank=0.5, source="x")
    scan_repository(tmp_path, [region], backend=_Backend(), budget=ScanBudget(max_model_calls=0))
    assert seen["exclude"] == ("vendor",)
