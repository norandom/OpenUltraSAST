"""Split-sink fixtures: stage-1 pattern scan must miss planted sinks (requirement 8.1)."""

from pathlib import Path

import pytest

from openultrasast.benchmark import (
    BenchmarkManifest,
    BenchmarkRun,
    ExpectedFinding,
    evaluate_benchmark,
    load_benchmark_manifest,
    resolve_benchmark_source,
)
from openultrasast.findings import StaticFinding, quick_scan_findings
from openultrasast.gate import LANGUAGE_MANIFESTS
from openultrasast.preprocess import preprocess_repository
from openultrasast.rank import rank_targets

MANIFEST_DIR = Path("benchmarks/manifests")
SPLIT_SINK_MANIFESTS = (
    "split-sink-c",
    "split-sink-java",
    "split-sink-javascript",
    "split-sink-python",
)


def _quick_scan(target: Path) -> list[StaticFinding]:
    _, targets = preprocess_repository(target)
    return quick_scan_findings(target, targets, rank_targets(targets))


def _planted_split_sinks(manifest: BenchmarkManifest) -> list[ExpectedFinding]:
    return [item for item in manifest.expected if item.rule_id is None]


@pytest.mark.parametrize("name", SPLIT_SINK_MANIFESTS)
def test_stage1_misses_planted_split_sink(name: str) -> None:
    manifest_path = MANIFEST_DIR / f"{name}.toml"
    manifest = load_benchmark_manifest(manifest_path)
    target = resolve_benchmark_source(manifest_path, manifest)
    planted = _planted_split_sinks(manifest)
    assert planted, f"{name} must document a stage-1 miss without rule_id"

    findings = _quick_scan(target)
    run = BenchmarkRun(benchmark_run_id="split-sink", root=Path("/tmp/split-sink"), manifest=manifest)
    result = evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id=None, scan_run_dir=None)
    missed = {(miss.path, miss.cwe, miss.rule_id) for miss in result.misses}

    for expected in planted:
        assert expected.line is not None
        assert expected.sink
        source = (target / expected.path).read_text()
        lines = source.splitlines()
        sink_line = lines[expected.line - 1]
        assert expected.sink.lower() in sink_line.lower(), f"{name} planted sink {expected.sink!r} missing on line {expected.line}"
        prior = "\n".join(lines[: expected.line - 1]).lower()
        assert any(token in prior for token in ("query", "sql")), f"{name} must assign the payload before the sink line"
        on_line = [finding for finding in findings if finding.path == expected.path and finding.line == expected.line]
        assert on_line == [], f"{name} stage-1 hit the planted split-sink on {expected.path}:{expected.line}: {on_line}"
        assert (expected.path, expected.cwe, None) in missed, (
            f"{name} evaluate_benchmark must record a miss for {expected.path}:{expected.line}"
        )


def test_split_sink_fixtures_are_outside_stage1_gate_corpus() -> None:
    listed = {name for names in LANGUAGE_MANIFESTS.values() for name in names}
    leaked = [name for name in SPLIT_SINK_MANIFESTS if name in listed]
    assert leaked == [], "split-sink fixtures must not join LANGUAGE_MANIFESTS (stage-1 90% smoke gate)"
