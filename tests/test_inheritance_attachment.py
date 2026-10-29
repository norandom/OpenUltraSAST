"""Task 8.4 -- inheritance and base-declaration attachment (Req 3.5).

Base-type operations and entries attach only through repository-defined
descendant relations; ambiguous inheritance stays incomplete; unrelated
same-name classes never receive attachments (the mage-ai shape).
"""

from __future__ import annotations

from openultrasast.semantic.obligations.abstract_domain import Completeness
from openultrasast.semantic.obligations.resolution import (
    SymbolIndex,
    ancestors_of,
    descendants_of,
    inherited_method,
)

JAVA_BASE = (
    "src/Base.java",
    "public class Base { public void run(String command) { } }",
    "java",
)
JAVA_SUB = (
    "src/Sub.java",
    "public class Sub extends Base { public void handle() { } }",
    "java",
)
JAVA_UNRELATED = (
    "src/Other.java",
    "public class Unrelated { public void run(String command) { } }",
    "java",
)
JAVA_CHAIN = (
    "src/Chain.java",
    "public class A extends B { } class B extends C { } class C { public void audit(String request) { } }",
    "java",
)
JAVA_CYCLE = (
    "src/Cycle.java",
    "public class P extends Q { } class Q extends P { }",
    "java",
)
PHP_BASE_A = (
    "a/Base.php",
    "<?php class Base { public function run($command) { } }",
    "php",
)
PHP_BASE_B = (
    "b/Base.php",
    "<?php class Base { public function run($command) { } }",
    "php",
)


def _index(*files: tuple[str, str, str]) -> SymbolIndex:
    return SymbolIndex.build(files)


def test_ancestors_walk_the_transitive_chain_nearest_first() -> None:
    index = _index(JAVA_CHAIN)

    assert ancestors_of(index, "src/Chain.java", "A") == ("B", "C")


def test_ancestors_survive_inheritance_cycles_without_hanging() -> None:
    index = _index(JAVA_CYCLE)

    assert ancestors_of(index, "src/Cycle.java", "P") == ("Q",)


def test_descendants_cover_only_repo_defined_descendants() -> None:
    index = _index(JAVA_BASE, JAVA_SUB, JAVA_UNRELATED)

    assert descendants_of(index, "Base") == (("src/Sub.java", "Sub"),)


def test_inherited_method_resolves_complete_on_a_unique_base() -> None:
    index = _index(JAVA_BASE, JAVA_SUB, JAVA_UNRELATED)

    target_set = inherited_method(index, "Base", "run", arity=1)

    assert [symbol.enclosing_type for symbol in target_set.targets] == ["Base"]
    assert target_set.completeness == Completeness(is_complete=True)


def test_inherited_method_is_absent_when_no_base_declares_it() -> None:
    index = _index(JAVA_BASE, JAVA_SUB, JAVA_UNRELATED)

    target_set = inherited_method(index, "Base", "handle", arity=None)

    assert target_set.targets == ()
    assert target_set.completeness == Completeness(is_complete=False, reasons=("resolution:no_candidate",))


def test_inherited_method_keeps_ambiguous_bases_as_incomplete_candidates() -> None:
    index = _index(PHP_BASE_A, PHP_BASE_B)

    target_set = inherited_method(index, "Base", "run", arity=None)

    assert len(target_set.targets) == 2
    assert {symbol.module for symbol in target_set.targets} == {"a/Base.php", "b/Base.php"}
    assert target_set.completeness == Completeness(is_complete=False, reasons=("resolution:inheritance_ambiguous_across_modules",))


def test_inherited_method_narrows_overloads_by_arity() -> None:
    overloaded_base = (
        "src/Ops.java",
        "public class Ops { public void go() { } public void go(String payload) { } }",
        "java",
    )
    index = _index(overloaded_base)

    target_set = inherited_method(index, "Ops", "go", arity=1)

    assert [symbol.signature for symbol in target_set.targets] == [("payload",)]
    assert target_set.completeness == Completeness(is_complete=True)


def test_unrelated_same_name_classes_never_receive_base_attachments() -> None:
    index = _index(JAVA_BASE, JAVA_SUB, JAVA_UNRELATED)

    target_set = inherited_method(index, "Base", "run", arity=1)
    unrelated = index.by_name["run"]

    assert all(symbol.enclosing_type == "Base" for symbol in target_set.targets)
    assert ("src/Other.java", "Unrelated") not in descendants_of(index, "Base")
    assert any(symbol.enclosing_type == "Unrelated" and symbol.module == "src/Other.java" for symbol in unrelated)
