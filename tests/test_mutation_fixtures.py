"""Mutation fixtures: stage-1 same-line patterns must miss the aliased sink (requirement 8.2)."""

from pathlib import Path

from openultrasast.benchmark import BenchmarkRun, evaluate_benchmark, load_benchmark_manifest, resolve_benchmark_source
from openultrasast.findings import StaticFinding, quick_scan_findings
from openultrasast.gate import LANGUAGE_MANIFESTS
from openultrasast.preprocess import preprocess_repository
from openultrasast.rank import rank_targets

MANIFEST = Path("benchmarks/manifests/mutation-python.toml")


def _quick_scan(target: Path) -> list[StaticFinding]:
    _, targets = preprocess_repository(target)
    return quick_scan_findings(target, targets, rank_targets(targets))


def test_stage1_misses_aliased_os_system_mutation() -> None:
    manifest = load_benchmark_manifest(MANIFEST)
    target = resolve_benchmark_source(MANIFEST, manifest)
    planted = [item for item in manifest.expected if item.rule_id is None]
    assert planted, "mutation manifest must document a stage-1 miss without rule_id"
    expected = planted[0]
    assert expected.sink == "run_cmd"
    assert expected.line is not None

    source = (target / expected.path).read_text()
    lines = source.splitlines()
    assert "os.system" in source
    assert "os.system(" not in lines[expected.line - 1]
    assert "run_cmd(" in lines[expected.line - 1]

    findings = _quick_scan(target)
    on_line = [finding for finding in findings if finding.path == expected.path and finding.line == expected.line]
    assert on_line == [], f"stage-1 hit the mutation on {expected.path}:{expected.line}: {on_line}"

    run = BenchmarkRun(benchmark_run_id="mutation", root=Path("/tmp/mutation"), manifest=manifest)
    result = evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id=None, scan_run_dir=None)
    missed = {(miss.path, miss.cwe, miss.rule_id) for miss in result.misses}
    assert (expected.path, expected.cwe, None) in missed


def test_mutation_fixture_is_outside_stage1_gate_corpus() -> None:
    listed = {name for names in LANGUAGE_MANIFESTS.values() for name in names}
    assert "mutation-python" not in listed
