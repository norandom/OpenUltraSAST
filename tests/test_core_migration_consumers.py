"""Final consumer closure for detection-core migration task 10.6."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import core_migration_inventory as migration_inventory
import pytest
from consumer_migration_evidence import (
    CONSUMER_TERMINAL_EVIDENCE,
    REVIEWED_SUCCESSOR_MODULES,
    ConsumerEvidenceError,
    ReviewedSuccessorModule,
    load_consumer_terminal_evidence,
    load_reviewed_successor_modules,
    migrated_pytest_node_ids,
)
from core_migration_boundary import inspect_legacy_boundary
from core_migration_inventory import REPO, LegacyInventoryError, MigrationDisposition, load_migration_inventory, validate_inventory_sources
from core_migration_scope import boundary_python

INVENTORY = REPO / "tests/fixtures/detection_core/v1/migration_inventory.json"


def test_complete_original_inventory_is_terminal() -> None:
    inventory = load_migration_inventory(INVENTORY)

    assert inventory.entries
    assert all(entry.disposition is not MigrationDisposition.OPEN for entry in inventory.entries)


def test_terminal_evidence_exactly_binds_every_task_10_6_entry() -> None:
    inventory = load_migration_inventory(INVENTORY)
    evidence_ids = tuple(CONSUMER_TERMINAL_EVIDENCE)
    evidence_id_set = set(evidence_ids)
    selected = tuple(entry for entry in inventory.entries if entry.entry_id in evidence_id_set)
    entries = {entry.entry_id: entry for entry in selected}

    assert len(entries) == len(evidence_ids) == 155
    assert tuple(entry.entry_id for entry in selected) == evidence_ids
    assert all(entries[entry_id].disposition.value == evidence.disposition for entry_id, evidence in CONSUMER_TERMINAL_EVIDENCE.items())
    validate_inventory_sources(inventory, root=REPO)


def test_migrated_evidence_owns_exact_bounded_pytest_nodes() -> None:
    migrated = tuple(evidence for evidence in CONSUMER_TERMINAL_EVIDENCE.values() if evidence.disposition == "v2_migrated")
    selectors = migrated_pytest_node_ids()

    assert len(migrated) == 40
    assert len(selectors) == 37
    assert all(evidence.pytest_node_id == f"{evidence.successor_path}::{evidence.probe_symbol}" for evidence in migrated)
    assert all(selector in selectors for selector in (evidence.pytest_node_id for evidence in migrated))
    assert all((REPO / selector.partition("::")[0]).read_bytes() for selector in selectors)


def test_successor_module_authority_is_exact_nonzero_and_digest_matched() -> None:
    migrated_paths = {evidence.successor_path for evidence in CONSUMER_TERMINAL_EVIDENCE.values() if evidence.disposition == "v2_migrated"}

    assert len(REVIEWED_SUCCESSOR_MODULES) == 18
    assert set(REVIEWED_SUCCESSOR_MODULES) == migrated_paths
    for relative, reviewed in REVIEWED_SUCCESSOR_MODULES.items():
        content = (REPO / relative).read_bytes()
        assert content, f"module authority instrument must read nonzero bytes from {relative}"
        assert hashlib.sha256(content).hexdigest() == reviewed.sha256


def _mutated_authority(tmp_path: Path, mutation: str) -> Path:
    document = json.loads((REPO / "tests/fixtures/detection_core/v1/consumer_terminal_evidence.json").read_bytes())
    modules = document["successor_modules"]
    if mutation == "missing":
        modules.pop()
    elif mutation == "extra":
        modules.append({"path": "tests/forged_successor.py", "sha256": "f" * 64})
    elif mutation == "duplicate":
        modules.append(dict(modules[-1]))
    elif mutation == "conflicting_path":
        modules.append({**modules[-1], "sha256": "f" * 64})
    elif mutation == "duplicate_digest":
        modules[1]["sha256"] = modules[0]["sha256"]
    else:
        raise AssertionError(f"unknown mutation: {mutation}")
    target = tmp_path / f"consumer_terminal_evidence-{mutation}.json"
    target.write_text(json.dumps(document), encoding="utf-8")
    return target


def _write_authority(tmp_path: Path, document: object, name: str = "consumer_terminal_evidence.json") -> Path:
    target = tmp_path / name
    target.write_text(json.dumps(document), encoding="utf-8")
    return target


@pytest.mark.parametrize(
    "invalid_path",
    (
        "",
        "/tests/test_arm_regression.py",
        "C:/tests/test_arm_regression.py",
        "C:tests/test_arm_regression.py",
        "C:\\tests\\test_arm_regression.py",
        "tests\\test_arm_regression.py",
        "./tests/test_arm_regression.py",
        "tests/./test_arm_regression.py",
        "tests/../tests/test_arm_regression.py",
        "tests/../../outside.py",
        "tests//test_arm_regression.py",
        "tests/test_arm_regression.py/.",
        "tests/test_arm_regression.py\0forged",
    ),
)
def test_migrated_successor_paths_require_exact_canonical_repo_relative_posix(tmp_path: Path, invalid_path: str) -> None:
    document = json.loads((REPO / "tests/fixtures/detection_core/v1/consumer_terminal_evidence.json").read_bytes())
    migrated = next(entry for entry in document["entries"] if entry["disposition"] == "v2_migrated")
    migrated["successor_path"] = invalid_path
    migrated["pytest_node_id"] = f"{invalid_path}::{migrated['probe_symbol']}"

    with pytest.raises(ConsumerEvidenceError, match="canonical repository-relative POSIX path"):
        load_consumer_terminal_evidence(_write_authority(tmp_path, document))


@pytest.mark.parametrize(
    "invalid_path",
    (
        "/tests/test_arm_regression.py",
        "C:/tests/test_arm_regression.py",
        "C:tests/test_arm_regression.py",
        "tests\\test_arm_regression.py",
        "tests/./test_arm_regression.py",
        "tests/../tests/test_arm_regression.py",
        "tests/../../outside.py",
        "tests//test_arm_regression.py",
        "tests/test_arm_regression.py\0forged",
    ),
)
def test_reviewed_module_paths_require_exact_canonical_repo_relative_posix(tmp_path: Path, invalid_path: str) -> None:
    document = json.loads((REPO / "tests/fixtures/detection_core/v1/consumer_terminal_evidence.json").read_bytes())
    original = document["successor_modules"][0]["path"]
    document["successor_modules"][0]["path"] = invalid_path
    for entry in document["entries"]:
        if entry["successor_path"] == original:
            entry["successor_path"] = invalid_path
            entry["pytest_node_id"] = f"{invalid_path}::{entry['probe_symbol']}"

    with pytest.raises(ConsumerEvidenceError, match="canonical repository-relative POSIX path"):
        load_reviewed_successor_modules(_write_authority(tmp_path, document))


@pytest.mark.parametrize("mutation", ("missing", "extra", "duplicate", "conflicting_path", "duplicate_digest"))
def test_successor_module_authority_rejects_set_and_identity_drift(tmp_path: Path, mutation: str) -> None:
    with pytest.raises(ConsumerEvidenceError, match="successor module"):
        load_reviewed_successor_modules(_mutated_authority(tmp_path, mutation))


def test_migrated_row_outside_module_authority_is_rejected(tmp_path: Path) -> None:
    evidence_path = REPO / "tests/fixtures/detection_core/v1/consumer_terminal_evidence.json"
    document = json.loads(evidence_path.read_bytes())
    migrated = next(entry for entry in document["entries"] if entry["disposition"] == "v2_migrated")
    migrated["successor_path"] = "tests/forged_successor.py"
    migrated["pytest_node_id"] = f"tests/forged_successor.py::{migrated['probe_symbol']}"
    target = tmp_path / "consumer_terminal_evidence.json"
    target.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ConsumerEvidenceError, match="exactly cover migrated rows"):
        load_consumer_terminal_evidence(target)


def test_clean_reviewed_successor_module_is_accepted() -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == _TERMINAL_BINDING_ENTRY_ID)

    validate_inventory_sources(replace(inventory, entries=(entry,)), root=REPO)


def _install_reviewed_module(monkeypatch: pytest.MonkeyPatch, relative: str, content: bytes) -> None:
    monkeypatch.setattr(
        migration_inventory,
        "REVIEWED_SUCCESSOR_MODULES",
        {relative: ReviewedSuccessorModule(relative, hashlib.sha256(content).hexdigest())},
    )


def test_reviewed_successor_safe_reader_accepts_nested_real_directories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    relative = "tests/nested/reviewed.py"
    content = b"VALUE = 1\n"
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_bytes(content)
    _install_reviewed_module(monkeypatch, relative, content)

    tree = migration_inventory._read_reviewed_successor_module(relative, root=tmp_path)

    assert isinstance(tree, ast.Module)


def test_reviewed_successor_safe_reader_rejects_nul_before_filesystem_access() -> None:
    with pytest.raises(LegacyInventoryError, match="not canonical"):
        migration_inventory._canonical_relative_parts("tests/reviewed.py\0forged")


def test_reviewed_successor_safe_reader_refuses_fifo_without_blocking(tmp_path: Path) -> None:
    relative = "tests/reviewed.py"
    target = tmp_path / relative
    target.parent.mkdir()
    os.mkfifo(target)
    assert target.is_fifo(), "FIFO refusal instrument must create the special file it exercises"
    program = (
        "from pathlib import Path\n"
        "from core_migration_inventory import LegacyInventoryError, _read_file_beneath_root\n"
        f"root = Path({str(tmp_path)!r})\n"
        "try:\n"
        f"    _read_file_beneath_root({relative!r}, root=root)\n"
        "except LegacyInventoryError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(2)\n"
    )
    try:
        completed = subprocess.run(
            (sys.executable, "-c", program),
            cwd=REPO,
            env={**os.environ, "PYTHONPATH": "src:tests"},
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("reviewed successor FIFO open blocked past the two-second bound")
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("target_location", ("outside", "inside"))
def test_reviewed_successor_safe_reader_rejects_final_file_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_location: str
) -> None:
    relative = "tests/reviewed.py"
    content = b"VALUE = 1\n"
    tests = tmp_path / "tests"
    tests.mkdir()
    target = (tmp_path.parent / f"{tmp_path.name}-outside.py") if target_location == "outside" else (tests / "target.py")
    target.write_bytes(content)
    (tmp_path / relative).symlink_to(target)
    _install_reviewed_module(monkeypatch, relative, content)

    with pytest.raises(LegacyInventoryError, match="not a symlink-free file beneath the supplied root"):
        migration_inventory._read_reviewed_successor_module(relative, root=tmp_path)


@pytest.mark.parametrize("target_location", ("outside", "inside"))
def test_reviewed_successor_safe_reader_rejects_intermediate_directory_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_location: str
) -> None:
    relative = "linked/reviewed.py"
    content = b"VALUE = 1\n"
    target = (tmp_path.parent / f"{tmp_path.name}-outside") if target_location == "outside" else (tmp_path / "real")
    target.mkdir()
    (target / "reviewed.py").write_bytes(content)
    (tmp_path / "linked").symlink_to(target, target_is_directory=True)
    _install_reviewed_module(monkeypatch, relative, content)

    with pytest.raises(LegacyInventoryError, match="not a symlink-free file beneath the supplied root"):
        migration_inventory._read_reviewed_successor_module(relative, root=tmp_path)


@pytest.mark.parametrize("root_kind", ("missing", "file", "symlink"))
def test_reviewed_successor_safe_reader_rejects_non_directory_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_kind: str) -> None:
    relative = "tests/reviewed.py"
    content = b"VALUE = 1\n"
    real_root = tmp_path / "real-root"
    real_root.mkdir()
    supplied_root = tmp_path / "supplied-root"
    if root_kind == "file":
        supplied_root.write_bytes(b"not a directory")
    elif root_kind == "symlink":
        supplied_root.symlink_to(real_root, target_is_directory=True)
    _install_reviewed_module(monkeypatch, relative, content)

    with pytest.raises(LegacyInventoryError, match="supplied root is not a real directory"):
        migration_inventory._read_reviewed_successor_module(relative, root=supplied_root)


@pytest.mark.parametrize("failure", ("missing", "unreadable", "zero"))
def test_reviewed_successor_safe_reader_rejects_unusable_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    relative = "tests/reviewed.py"
    expected = b"VALUE = 1\n"
    target = tmp_path / relative
    target.parent.mkdir()
    if failure != "missing":
        target.write_bytes(b"" if failure == "zero" else expected)
    if failure == "unreadable":
        target.chmod(0)
    _install_reviewed_module(monkeypatch, relative, expected)

    message = "nonzero bytes" if failure == "zero" else "not readable"
    with pytest.raises(LegacyInventoryError, match=message):
        migration_inventory._read_reviewed_successor_module(relative, root=tmp_path)


def test_migrated_owner_binding_cannot_disappear(tmp_path: Path) -> None:
    inventory = load_migration_inventory(INVENTORY)
    migrated = {entry_id for entry_id, evidence in CONSUMER_TERMINAL_EVIDENCE.items() if evidence.disposition == "v2_migrated"}
    entry = next(item for item in inventory.entries if item.entry_id in migrated and item.symbol.startswith("test_"))
    source = (REPO / entry.path).read_text(encoding="utf-8").replace(f"def {entry.symbol}(", f"def removed_{entry.symbol}(", 1)
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="module digest"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


def test_retired_operational_owner_cannot_be_reintroduced(tmp_path: Path) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.owner_boundary == "operational-tooling")
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_text("import json\ndef main():\n    return json.dumps({})\n", encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="retired consumer capability remains live"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


@pytest.mark.parametrize(
    ("entry_id", "source"),
    (
        (
            "887c9abe9a6d827c39655c6835fb0c2471be035914e2bbff888a4cd54635b8e0",
            "from openultrasast.core._legacy_factpack import LegacyFactPack\n",
        ),
        (
            "36e5d60b410bf7f9c676a5da9e95718cab95dadfbf61cda0d0e2f24b56cf3c92",
            "class TraceRecord:\n    def canonical(self):\n        return record()\n",
        ),
        (
            "a8685de9229906307386c537ff096b385bff727e270744ccc3dd02978a7d5b2a",
            "def test_budget_gate_returns_no_go():\n    return admission_report()\n",
        ),
    ),
)
def test_retired_module_or_dotted_capability_cannot_be_reintroduced(tmp_path: Path, entry_id: str, source: str) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == entry_id)
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="retired consumer capability"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


def test_dead_syntax_cannot_stand_in_for_migrated_test_semantics(tmp_path: Path) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == "6fe48be48004f15cf1157b77a2ca88c7a0fb2f6bb649c71aa656f3a62c17c53b")
    constants = "fact_set_digest", "id", "instrument", "judgment", "stage_funnel", "status"
    source = f"def test_summarize_arm_publishes_budget_result_and_masks_repositories():\n    if False:\n        dumps({constants!r})\n"
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="module digest"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


def test_pass_only_migrated_successor_cannot_claim_semantic_closure(tmp_path: Path) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == "6fe48be48004f15cf1157b77a2ca88c7a0fb2f6bb649c71aa656f3a62c17c53b")
    source = """from benchmarks.valid import arm_regression

def test_summarize_arm_publishes_budget_result_and_masks_repositories():
    if False:
        dumps(("fact_set_digest", "id", "instrument", "judgment", "stage_funnel", "status"))
    pass
"""
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="module digest"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


@pytest.mark.parametrize(
    "replacement_body",
    (
        "return True",
        "assert True",
        "pytest.skip('not semantic execution')",
        "len(())",
        "if False:\n        arm_regression.summarize_arm(None)\n    return True",
    ),
)
def test_arbitrary_behavior_cannot_certify_migrated_semantics(tmp_path: Path, replacement_body: str) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == "6fe48be48004f15cf1157b77a2ca88c7a0fb2f6bb649c71aa656f3a62c17c53b")
    source = f"""import pytest
from benchmarks.valid import arm_regression

def test_summarize_arm_publishes_budget_result_and_masks_repositories():
    if False:
        dumps(("fact_set_digest", "id", "instrument", "judgment", "stage_funnel", "status"))
    {replacement_body}
"""
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="module digest"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


def test_rebound_semantic_import_cannot_certify_real_migrated_owner(tmp_path: Path) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == "6fe48be48004f15cf1157b77a2ca88c7a0fb2f6bb649c71aa656f3a62c17c53b")
    source = (
        (REPO / entry.path)
        .read_text(encoding="utf-8")
        .replace(
            "from benchmarks.valid import arm_regression",
            "from benchmarks.valid import arm_regression as rebound_arm_regression",
        )
    )
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="module digest"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


_TERMINAL_BINDING_ENTRY_ID = "6fe48be48004f15cf1157b77a2ca88c7a0fb2f6bb649c71aa656f3a62c17c53b"
_TERMINAL_BINDING_TEST = "test_summarize_arm_publishes_budget_result_and_masks_repositories"


@pytest.mark.parametrize(
    "later_binding",
    (
        f"{_TERMINAL_BINDING_TEST} = lambda: None",
        f"{_TERMINAL_BINDING_TEST}: object = None",
        f"{_TERMINAL_BINDING_TEST} += ()",
        f"del {_TERMINAL_BINDING_TEST}",
        f"from builtins import len as {_TERMINAL_BINDING_TEST}",
        f"{_TERMINAL_BINDING_TEST} = wrapper({_TERMINAL_BINDING_TEST})",
        "arm_regression = object()",
        "pytestmark = pytest.mark.skip(reason='disabled')",
        f"{_TERMINAL_BINDING_TEST}.pytestmark = pytest.mark.xfail(reason='disabled')",
    ),
)
def test_reviewed_migrated_bindings_must_remain_terminal(tmp_path: Path, later_binding: str) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == _TERMINAL_BINDING_ENTRY_ID)
    source = (REPO / entry.path).read_text(encoding="utf-8") + f"\n{later_binding}\n"
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="module digest"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


@pytest.mark.parametrize(
    "namespace_mutation",
    (
        f"vars()[{_TERMINAL_BINDING_TEST!r}] = lambda: None",
        f"sys.modules[__name__].{_TERMINAL_BINDING_TEST} = lambda: None",
        f"object.__setattr__(sys.modules[__name__], {_TERMINAL_BINDING_TEST!r}, lambda: None)",
        f"vars({_TERMINAL_BINDING_TEST})['pytestmark'] = pytest.mark.skip(reason='disabled')",
        f"{_TERMINAL_BINDING_TEST}.__dict__['pytestmark'] = pytest.mark.xfail(reason='disabled')",
    ),
)
def test_exact_module_bytes_reject_unbounded_namespace_mutations(tmp_path: Path, namespace_mutation: str) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == _TERMINAL_BINDING_ENTRY_ID)
    original = (REPO / entry.path).read_bytes()
    assert original, "namespace-mutation RED instrument must read nonzero successor bytes"
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_bytes(original + f"\n{namespace_mutation}\n".encode())

    with pytest.raises(LegacyInventoryError, match="module digest"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


def test_terminal_ast_diagnostics_remain_defense_in_depth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == _TERMINAL_BINDING_ENTRY_ID)
    original = (REPO / entry.path).read_bytes()
    assert original, "defense-in-depth instrument must read nonzero successor bytes"
    changed = original + f"\n{_TERMINAL_BINDING_TEST} = lambda: None\n".encode()
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_bytes(changed)
    reviewed = dict(REVIEWED_SUCCESSOR_MODULES)
    reviewed[entry.path] = ReviewedSuccessorModule(entry.path, hashlib.sha256(changed).hexdigest())
    monkeypatch.setattr(migration_inventory, "REVIEWED_SUCCESSOR_MODULES", reviewed)

    with pytest.raises(LegacyInventoryError, match="terminal binding"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


def test_even_safely_overwritten_byte_change_requires_explicit_review(tmp_path: Path) -> None:
    inventory = load_migration_inventory(INVENTORY)
    entry = next(item for item in inventory.entries if item.entry_id == _TERMINAL_BINDING_ENTRY_ID)
    source = (
        (REPO / entry.path)
        .read_text(encoding="utf-8")
        .replace(
            f"def {_TERMINAL_BINDING_TEST}(",
            f"{_TERMINAL_BINDING_TEST} = None\n\ndef {_TERMINAL_BINDING_TEST}(",
            1,
        )
    )
    target = tmp_path / entry.path
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="module digest"):
        validate_inventory_sources(replace(inventory, entries=(entry,)), root=tmp_path)


def test_reviewed_parametrize_decorators_remain_collectable() -> None:
    inventory = load_migration_inventory(INVENTORY)
    selected_paths = {"tests/test_hunter_arm.py", "tests/test_push_admission.py"}
    selected = tuple(
        entry
        for entry in inventory.entries
        if entry.entry_id in CONSUMER_TERMINAL_EVIDENCE and CONSUMER_TERMINAL_EVIDENCE[entry.entry_id].successor_path in selected_paths
    )

    assert selected
    validate_inventory_sources(replace(inventory, entries=selected), root=REPO)
    decorators = [
        decorator
        for path in selected_paths
        for node in ast.parse((REPO / path).read_bytes(), filename=path).body
        if isinstance(node, ast.FunctionDef) and f"{path}::{node.name}" in migrated_pytest_node_ids()
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr == "parametrize"
    ]
    assert len(decorators) == 2


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("path", "tests/forged_successor.py"),
        ("capability_anchors", ["definition:forged_owner"]),
        ("disposition", "retired"),
    ),
)
def test_terminal_evidence_rejects_frozen_identity_or_disposition_drift(tmp_path: Path, field: str, replacement: object) -> None:
    evidence_path = REPO / "tests/fixtures/detection_core/v1/consumer_terminal_evidence.json"
    document = json.loads(evidence_path.read_bytes())
    entry = next(item for item in document["entries"] if field != "disposition" or item["disposition"] == "v2_migrated")
    entry[field] = replacement
    forged = tmp_path / "consumer_terminal_evidence.json"
    forged.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ConsumerEvidenceError):
        load_consumer_terminal_evidence(forged)


def test_authoritative_boundary_includes_task_source_files() -> None:
    paths = {path.relative_to(REPO).as_posix(): path for path in boundary_python(REPO)}

    for relative in ("tests/consumer_migration_evidence.py", "tests/test_core_migration_consumers.py"):
        assert relative in paths
        assert paths[relative].read_bytes()


def test_nonzero_repository_scope_has_no_forbidden_consumers() -> None:
    inventory = load_migration_inventory(INVENTORY)
    paths = boundary_python(REPO)
    report = inspect_legacy_boundary(
        paths,
        frozen_inventory=inventory,
        candidate_inventory=inventory,
        expected_scope=paths,
        root=REPO,
    )

    assert report.files_read == len(paths) > 0
    assert report.bytes_read > 0
    assert report.scanned_scope_paths == report.expected_scope_paths
    assert report.consumer_legacy_import_sites == ()
    assert report.consumer_legacy_writer_sites == ()
    assert report.forbidden_dynamic_sites == ()
