from __future__ import annotations

import json
import tomllib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .findings import StaticFinding


@dataclass(frozen=True)
class BenchmarkSource:
    type: str
    path: str


@dataclass(frozen=True)
class ExpectedFinding:
    cwe: str
    vulnerability_class: str
    path: str
    evidence: str
    rule_id: str | None = None
    line: int | None = None
    function: str | None = None
    sink: str | None = None


@dataclass(frozen=True)
class BenchmarkManifest:
    name: str
    language: str
    frameworks: list[str]
    setup: list[str]
    source: BenchmarkSource
    modes: list[str]
    expected: list[ExpectedFinding]
    known_noise: list[str]
    baselines: list[str]


@dataclass(frozen=True)
class BaselineFinding:
    tool: str
    finding_id: str
    path: str
    line: int | None
    rule_id: str | None
    cwe: str | None
    vulnerability_class: str | None
    evidence: str


@dataclass(frozen=True)
class BenchmarkMiss:
    cwe: str
    vulnerability_class: str
    path: str
    evidence: str
    reason: str


@dataclass(frozen=True)
class BenchmarkBaselineDelta:
    tool: str
    matched_expected_total: int
    missed_expected_total: int
    extra_findings_total: int


@dataclass(frozen=True)
class BenchmarkCalibrationRecord:
    cwe: str
    vulnerability_class: str
    path: str
    evidence: str
    failed_stage: str
    next_improvement_candidate: str
    reason: str


@dataclass(frozen=True)
class BenchmarkFalsePositive:
    finding_id: str
    path: str
    line: int | None
    reason: str


@dataclass(frozen=True)
class BenchmarkMetrics:
    expected_findings_total: int
    actual_findings_total: int
    matched_findings_total: int
    missed_findings_total: int
    false_positive_findings_total: int
    recall: float | None
    precision: float | None
    runtime_seconds: float | None
    model_usage: dict[str, object]
    artifact_links: dict[str, str]


@dataclass(frozen=True)
class BenchmarkRun:
    benchmark_run_id: str
    root: Path
    manifest: BenchmarkManifest


@dataclass(frozen=True)
class BenchmarkResult:
    benchmark_run_id: str
    benchmark_name: str
    language: str
    mode: str
    scan_id: str | None
    scan_run_dir: str | None
    metrics: BenchmarkMetrics
    misses: list[BenchmarkMiss]
    false_positives: list[BenchmarkFalsePositive]
    baseline_deltas: list[BenchmarkBaselineDelta]
    calibration_records: list[BenchmarkCalibrationRecord]


def load_benchmark_manifest(path: Path) -> BenchmarkManifest:
    payload = tomllib.loads(path.read_text())
    source = payload.get("source", {})
    expected = payload.get("expected", [])
    return BenchmarkManifest(
        name=str(payload["name"]),
        language=str(payload["language"]),
        frameworks=[str(item) for item in payload.get("frameworks", [])],
        setup=[str(item) for item in payload.get("setup", [])],
        source=BenchmarkSource(type=str(source.get("type", "local")), path=str(source["path"])),
        modes=[str(item) for item in payload.get("modes", [])],
        expected=[
            ExpectedFinding(
                cwe=str(item["cwe"]),
                vulnerability_class=str(item.get("class", item.get("vulnerability_class", "unknown"))),
                path=str(item["path"]),
                evidence=str(item.get("evidence", "")),
                rule_id=str(item["rule_id"]) if "rule_id" in item else None,
                line=int(item["line"]) if "line" in item else None,
                function=str(item["function"]) if "function" in item else None,
                sink=str(item["sink"]) if "sink" in item else None,
            )
            for item in expected
        ],
        known_noise=[str(item) for item in payload.get("known_noise", [])],
        baselines=[str(item) for item in payload.get("baselines", [])],
    )


def resolve_benchmark_source(manifest_path: Path, manifest: BenchmarkManifest) -> Path:
    if manifest.source.type != "local":
        raise ValueError(f"unsupported benchmark source type: {manifest.source.type}")
    source = Path(manifest.source.path)
    if not source.is_absolute():
        source = manifest_path.parent / source
    return source.resolve()


def create_benchmark_run(target: Path, manifest: BenchmarkManifest) -> BenchmarkRun:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    benchmark_run_id = f"{timestamp}-{uuid4().hex[:8]}"
    root = target.resolve() / ".openultrasast" / "benchmarks" / benchmark_run_id
    root.mkdir(parents=True, exist_ok=False)
    return BenchmarkRun(benchmark_run_id=benchmark_run_id, root=root, manifest=manifest)


def load_findings(path: Path) -> list[StaticFinding]:
    payload = json.loads(path.read_text())
    return [StaticFinding(**item) for item in payload.get("findings", [])]


def load_baseline_findings(manifest_path: Path, manifest: BenchmarkManifest) -> list[BaselineFinding]:
    baseline_findings: list[BaselineFinding] = []
    for baseline in manifest.baselines:
        path = Path(baseline)
        if not path.is_absolute():
            path = manifest_path.parent / path
        if not path.exists():
            continue
        payload = json.loads(path.read_text())
        items = payload.get("findings", payload if isinstance(payload, list) else [])
        for item in items:
            baseline_findings.append(
                BaselineFinding(
                    tool=str(item.get("tool", path.stem)),
                    finding_id=str(item.get("finding_id", item.get("id", ""))),
                    path=str(item.get("path", "")),
                    line=int(item["line"]) if "line" in item and item["line"] is not None else None,
                    rule_id=str(item["rule_id"]) if "rule_id" in item else None,
                    cwe=str(item["cwe"]) if "cwe" in item else None,
                    vulnerability_class=str(item.get("class", item.get("vulnerability_class", ""))) or None,
                    evidence=str(item.get("evidence", "")),
                )
            )
    return baseline_findings


def evaluate_benchmark(
    *,
    run: BenchmarkRun,
    mode: str,
    findings: list[StaticFinding],
    scan_id: str | None,
    scan_run_dir: Path | None,
    runtime_seconds: float | None = None,
    baseline_findings: list[BaselineFinding] | None = None,
) -> BenchmarkResult:
    matched_finding_indexes: set[int] = set()
    misses: list[BenchmarkMiss] = []
    for expected in run.manifest.expected:
        match_index = _matching_finding_index(expected, findings, matched_finding_indexes)
        if match_index is None:
            misses.append(_miss(expected))
        else:
            matched_finding_indexes.add(match_index)

    false_positives = [_false_positive(finding) for index, finding in enumerate(findings) if index not in matched_finding_indexes]
    baseline_deltas = _baseline_deltas(run.manifest.expected, baseline_findings or [])
    calibration_records = [_calibration_record(miss) for miss in misses]
    expected_total = len(run.manifest.expected)
    actual_total = len(findings)
    missed_total = len(misses)
    matched_total = expected_total - missed_total
    false_positive_total = len(false_positives)
    recall = matched_total / expected_total if expected_total else None
    precision = matched_total / actual_total if actual_total else None
    return BenchmarkResult(
        benchmark_run_id=run.benchmark_run_id,
        benchmark_name=run.manifest.name,
        language=run.manifest.language,
        mode=mode,
        scan_id=scan_id,
        scan_run_dir=str(scan_run_dir) if scan_run_dir else None,
        metrics=BenchmarkMetrics(
            expected_findings_total=expected_total,
            actual_findings_total=actual_total,
            matched_findings_total=matched_total,
            missed_findings_total=missed_total,
            false_positive_findings_total=false_positive_total,
            recall=recall,
            precision=precision,
            runtime_seconds=runtime_seconds,
            model_usage={},
            artifact_links=_artifact_links(scan_run_dir),
        ),
        misses=misses,
        false_positives=false_positives,
        baseline_deltas=baseline_deltas,
        calibration_records=calibration_records,
    )


def write_benchmark_artifacts(run: BenchmarkRun, manifest_path: Path, result: BenchmarkResult) -> None:
    (run.root / "benchmark_manifest.toml").write_text(manifest_path.read_text())
    (run.root / "benchmark_result.json").write_text(json.dumps(_jsonable(asdict(result)), indent=2, sort_keys=True) + "\n")
    (run.root / "calibration_records.json").write_text(
        json.dumps(_jsonable([asdict(record) for record in result.calibration_records]), indent=2, sort_keys=True) + "\n"
    )
    (run.root / "external_baseline_deltas.json").write_text(
        json.dumps(_jsonable([asdict(delta) for delta in result.baseline_deltas]), indent=2, sort_keys=True) + "\n"
    )


def _matching_finding_index(expected: ExpectedFinding, findings: list[StaticFinding], used_indexes: set[int]) -> int | None:
    for index, finding in enumerate(findings):
        if index in used_indexes:
            continue
        if _matches_expected(expected, finding):
            return index
    return None


def _matches_expected(expected: ExpectedFinding, finding: StaticFinding) -> bool:
    expected_path = expected.path.strip("*")
    if expected.rule_id and not finding.finding_id.startswith(f"{expected.rule_id}:"):
        return False
    if expected.line is not None and finding.line != expected.line:
        return False
    if expected_path and expected_path not in finding.path:
        return False
    if expected.function and finding.function_name != expected.function:
        return False
    if expected.sink and _normalize(expected.sink) not in _finding_text(finding):
        return False
    if expected.evidence and not _evidence_matches(expected.evidence, finding):
        return False
    return _cwe_matches(expected.cwe, finding)


def _miss(expected: ExpectedFinding) -> BenchmarkMiss:
    return BenchmarkMiss(
        cwe=expected.cwe,
        vulnerability_class=expected.vulnerability_class,
        path=expected.path,
        evidence=expected.evidence,
        reason="no OpenUltraSAST finding matched the expected benchmark vulnerability",
    )


def _false_positive(finding: StaticFinding) -> BenchmarkFalsePositive:
    return BenchmarkFalsePositive(
        finding_id=finding.finding_id,
        path=finding.path,
        line=finding.line,
        reason="finding did not match any expected benchmark vulnerability",
    )


def _baseline_deltas(expected_findings: list[ExpectedFinding], baseline_findings: list[BaselineFinding]) -> list[BenchmarkBaselineDelta]:
    tools = sorted({finding.tool for finding in baseline_findings})
    deltas: list[BenchmarkBaselineDelta] = []
    for tool in tools:
        tool_findings = [finding for finding in baseline_findings if finding.tool == tool]
        matched_indexes: set[int] = set()
        matched_expected_total = 0
        for expected in expected_findings:
            match_index = _matching_baseline_index(expected, tool_findings, matched_indexes)
            if match_index is not None:
                matched_indexes.add(match_index)
                matched_expected_total += 1
        deltas.append(
            BenchmarkBaselineDelta(
                tool=tool,
                matched_expected_total=matched_expected_total,
                missed_expected_total=len(expected_findings) - matched_expected_total,
                extra_findings_total=len(tool_findings) - len(matched_indexes),
            )
        )
    return deltas


def _matching_baseline_index(expected: ExpectedFinding, findings: list[BaselineFinding], used_indexes: set[int]) -> int | None:
    for index, finding in enumerate(findings):
        if index in used_indexes:
            continue
        if _baseline_matches_expected(expected, finding):
            return index
    return None


def _baseline_matches_expected(expected: ExpectedFinding, finding: BaselineFinding) -> bool:
    expected_path = expected.path.strip("*")
    if expected.rule_id and finding.rule_id and finding.rule_id != expected.rule_id:
        return False
    if expected.line is not None and finding.line is not None and finding.line != expected.line:
        return False
    if expected_path and expected_path not in finding.path:
        return False
    if finding.cwe and finding.cwe.lower() != expected.cwe.lower():
        return False
    return not (expected.sink and expected.sink.lower() not in _normalize(finding.evidence))


def _calibration_record(miss: BenchmarkMiss) -> BenchmarkCalibrationRecord:
    return BenchmarkCalibrationRecord(
        cwe=miss.cwe,
        vulnerability_class=miss.vulnerability_class,
        path=miss.path,
        evidence=miss.evidence,
        failed_stage="benchmark_ground_truth_matching",
        next_improvement_candidate="rules_or_language_hunter",
        reason=miss.reason,
    )


def _artifact_links(scan_run_dir: Path | None) -> dict[str, str]:
    if scan_run_dir is None:
        return {}
    return {
        "findings": str(scan_run_dir / "findings.json"),
        "manifest": str(scan_run_dir / "manifest.json"),
        "report": str(scan_run_dir / "report.md"),
        "sarif": str(scan_run_dir / "report.sarif"),
    }


def _cwe_matches(cwe: str, finding: StaticFinding) -> bool:
    text = _finding_text(finding)
    cwe_lower = cwe.lower()
    if "cwe-" not in text:
        return True
    return cwe_lower in text


def _evidence_matches(evidence: str, finding: StaticFinding) -> bool:
    tokens = [token for token in _normalize(evidence).split() if len(token) > 2]
    if not tokens:
        return True
    text = _finding_text(finding)
    return any(token in text for token in tokens)


def _finding_text(finding: StaticFinding) -> str:
    parts = [
        finding.finding_id,
        finding.title,
        finding.rationale,
        finding.function_name or "",
        " ".join(finding.tags),
        " ".join(finding.reachability_conditions),
    ]
    return _normalize(" ".join(parts))


def _normalize(value: str) -> str:
    normalized = value.lower().replace("memcpy", "memcpy memory copy")
    normalized = normalized.replace("copies", "copy")
    return " ".join(normalized.replace("-", " ").replace("_", " ").split())


def _jsonable(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value
