from __future__ import annotations

import json
import os
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_VECTOR_STORE = "json-local"


@dataclass(frozen=True)
class ModelConfig:
    ranker: str | None = None
    hunter: str | None = None
    verifier: str | None = None
    patcher: str | None = None


@dataclass(frozen=True)
class EmbeddingConfig:
    model: str | None = None
    store: str = DEFAULT_VECTOR_STORE


@dataclass(frozen=True)
class SandboxConfig:
    network: bool = False
    workspace_readonly: bool = True
    memory_mb: int = 2048
    timeout_seconds: int = 300
    pids_limit: int = 512


@dataclass(frozen=True)
class DynamicConfig:
    enabled: bool = False
    network_scope: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceConfig:
    minimum_report_verified: str = "static_corroboration"
    minimum_exploit: str = "crash_reproduced"
    minimum_patch: str = "root_cause_explained"


@dataclass(frozen=True)
class StaticAnalysisConfig:
    sarif_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScoreConfig:
    k: float = 60.0
    min_score: int = 80
    block_severity_reachable: int = 5
    blocking: bool = False


@dataclass(frozen=True)
class RulesetConfig:
    # Emission floors that replace "every regex match becomes a finding". The
    # defaults (0.0) emit everything, keeping output byte-identical by default.
    min_emit_priority: float = 0.0
    min_emit_precision: float = 0.0


@dataclass(frozen=True)
class ResolvedConfig:
    models: ModelConfig = ModelConfig()
    embeddings: EmbeddingConfig = EmbeddingConfig()
    sandbox: SandboxConfig = SandboxConfig()
    dynamic: DynamicConfig = DynamicConfig()
    evidence: EvidenceConfig = EvidenceConfig()
    static_analysis: StaticAnalysisConfig = StaticAnalysisConfig()
    score: ScoreConfig = ScoreConfig()
    ruleset: RulesetConfig = RulesetConfig()
    runs_dir: str = ".openultrasast/runs"


def load_config(config_path: Path | None = None) -> ResolvedConfig:
    data: dict[str, object] = {}
    if config_path is not None and config_path.exists():
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)

    return ResolvedConfig(
        models=_load_models(data.get("models", {})),
        embeddings=_load_embeddings(data.get("embeddings", {})),
        sandbox=_load_sandbox(data.get("sandbox", {})),
        dynamic=_load_dynamic(data.get("dynamic", {})),
        evidence=_load_evidence(data.get("evidence", {})),
        static_analysis=_load_static_analysis(data.get("static_analysis", {})),
        score=_load_score(data.get("score", {})),
        ruleset=_load_ruleset_config(data.get("ruleset", {})),
        runs_dir=os.environ.get("OPENULTRASAST_RUNS_DIR", ".openultrasast/runs"),
    )


def write_resolved_config(config: ResolvedConfig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(config), indent=2, sort_keys=True) + "\n")


def _section(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _load_models(value: object) -> ModelConfig:
    data = _section(value)
    return ModelConfig(
        ranker=_string(data.get("ranker")),
        hunter=_string(data.get("hunter")),
        verifier=_string(data.get("verifier")),
        patcher=_string(data.get("patcher")),
    )


def _load_embeddings(value: object) -> EmbeddingConfig:
    data = _section(value)
    return EmbeddingConfig(model=_string(data.get("model")), store=_string(data.get("store")) or DEFAULT_VECTOR_STORE)


def _load_sandbox(value: object) -> SandboxConfig:
    data = _section(value)
    return SandboxConfig(
        network=bool(data.get("network", False)),
        workspace_readonly=bool(data.get("workspace_readonly", True)),
        memory_mb=_int_value(data.get("memory_mb"), 2048),
        timeout_seconds=_int_value(data.get("timeout_seconds"), 300),
        pids_limit=_int_value(data.get("pids_limit"), 512),
    )


def _load_dynamic(value: object) -> DynamicConfig:
    data = _section(value)
    scope = data.get("network_scope", [])
    if not isinstance(scope, list):
        scope = []
    return DynamicConfig(enabled=bool(data.get("enabled", False)), network_scope=tuple(str(item) for item in scope))


def _load_evidence(value: object) -> EvidenceConfig:
    data = _section(value)
    return EvidenceConfig(
        minimum_report_verified=str(data.get("minimum_report_verified", "static_corroboration")),
        minimum_exploit=str(data.get("minimum_exploit", "crash_reproduced")),
        minimum_patch=str(data.get("minimum_patch", "root_cause_explained")),
    )


def _int_value(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int | str | bytes | bytearray):
        return int(value)
    return default


def _load_static_analysis(value: object) -> StaticAnalysisConfig:
    data = _section(value)
    paths = data.get("sarif_paths", [])
    if not isinstance(paths, list):
        paths = []
    return StaticAnalysisConfig(sarif_paths=tuple(str(item) for item in paths))


def _load_score(value: object) -> ScoreConfig:
    data = _section(value)
    return ScoreConfig(
        k=_float_value(data.get("k"), 60.0),
        min_score=_int_value(data.get("min_score"), 80),
        block_severity_reachable=_int_value(data.get("block_severity_reachable"), 5),
        blocking=bool(data.get("blocking", False)),
    )


def _load_ruleset_config(value: object) -> RulesetConfig:
    data = _section(value)
    return RulesetConfig(
        min_emit_priority=_float_value(data.get("min_emit_priority"), 0.0),
        min_emit_precision=_float_value(data.get("min_emit_precision"), 0.0),
    )


def _float_value(value: object, default: float) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default
