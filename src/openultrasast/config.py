from __future__ import annotations

import json
import logging
import os
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from openultrasast.contracts import Contract

DEFAULT_VECTOR_STORE = "json-local"

# Retirement notes (harnessx-removal Req 1.3, 3.3). A key that asked for a retired LLM capability fails and names
# the replacement, never a silent downgrade; the old budget section only warns. Every line below that names the
# removed plane carries its retirement date, which the reference-search test holds the rest of the tree to.
_RETIRED_ON = "retired 2026-09-30 with HarnessX"
_PLANE_RUN = "`ousast plane run`, see ops/ax/README.md"
_RETIRED_PANELS = (
    f"LLM fusion panels were retired; fusion is deterministic; independent LLM agreement is the plane's `agree` task ({_PLANE_RUN})"
)
# Keys that loaded but were never read (retired 2026-10-02, legacy cleanup): accepting them silently would let
# a user believe they configure something.
_UNREAD_ON = "retired 2026-10-02 because nothing ever read it"
_UNREAD_DYNAMIC = "no dynamic or deep tier exists; deep mode will define its own keys when it is built"
_UNREAD_EVIDENCE = "evidence tiers come from the program model's ladder (model/ladder.py), not from configuration"
_UNREAD_VARIANTS = "the structural variant search it configured was deleted with semantic/variants.py"
RETIRED_KEYS: dict[tuple[str, str], str] = {
    ("models", "verifier"): f"{_RETIRED_ON}: LLM verification runs on the plane (`verify` + `agree`, {_PLANE_RUN})",
    ("fusion", "panel_model"): f"{_RETIRED_ON}: {_RETIRED_PANELS}",
    ("fusion", "decider_model"): f"{_RETIRED_ON}: {_RETIRED_PANELS}",
    ("models", "patcher"): f"{_UNREAD_ON}: no patching stage calls a model",
    ("dynamic", "enabled"): f"{_UNREAD_ON}: {_UNREAD_DYNAMIC}",
    ("dynamic", "network_scope"): f"{_UNREAD_ON}: {_UNREAD_DYNAMIC}",
    ("evidence", "minimum_report_verified"): f"{_UNREAD_ON}: {_UNREAD_EVIDENCE}",
    ("evidence", "minimum_exploit"): f"{_UNREAD_ON}: {_UNREAD_EVIDENCE}",
    ("evidence", "minimum_patch"): f"{_UNREAD_ON}: {_UNREAD_EVIDENCE}",
    ("variants", "enabled"): f"{_UNREAD_ON}: {_UNREAD_VARIANTS}",
    ("variants", "max_mechanisms"): f"{_UNREAD_ON}: {_UNREAD_VARIANTS}",
}
RETIRED_SECTION = "harnessx"  # retired 2026-09-30: loads with one warning and is otherwise ignored (Req 3.3)
RETIRED_SECTION_WARNING = (
    "`[harnessx]` is ignored (retired 2026-09-30): HarnessX was removed; agentic work runs on the ax plane "
    "with per-task budgets, see ops/ax/README.md"
)


class RetiredConfigError(ValueError):
    """A config key asked for a capability that was retired; the message names its replacement."""


def _check_retired(data: dict[str, object]) -> None:
    problems = []
    for (section, key), reason in RETIRED_KEYS.items():
        table = data.get(section)
        if isinstance(table, dict) and key in table:
            problems.append(f"`[{section}] {key}` was {reason}. Remove the key.")
    if problems:
        raise RetiredConfigError("\n".join(problems))
    if RETIRED_SECTION in data:
        logging.getLogger("openultrasast.config").warning(RETIRED_SECTION_WARNING)


def load_dotenv(path: Path | None = None, *, force: bool = False) -> None:
    """Load KEY=VALUE lines from .env into os.environ. Stdlib only; never overrides."""
    if not force and (os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("OPENULTRASAST_SKIP_DOTENV")):
        return
    env_path = path if path is not None else Path(".env")
    if not env_path.is_file():
        return
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass(frozen=True)
class ModelConfig:
    ranker: str | None = None
    hunter: str | None = None
    judge: str | None = None  # second, independent judgement before anything is published as proven
    chat_base_url: str | None = None  # chat endpoint; independent of the embedding endpoint
    chat_api_key_env: str | None = None  # environment variable holding that endpoint's key
    # Whether the chat model reasons before answering. Off by default because that is what the committed
    # baseline was measured under: the provider silently ignores `temperature` while thinking, so thinking was
    # disabled to make `temperature: 0` mean something. It did not — the measured run-to-run disagreement came
    # from the agentic path, not the decoder — which is why the model layer arbitrates instead of averaging.
    thinking: bool = False


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
class HardeningConfig:
    # Release-readiness controls. redact_secrets masks credentials in traces/reports;
    # max_findings caps the reported finding count for bounded CI runs (0 = unlimited).
    redact_secrets: bool = True
    max_findings: int = 0


@dataclass(frozen=True)
class FusionConfig:
    # Two-panel fusion adjudication for triggered findings (standard mode). Deterministic
    # panels and reconciler; high_assurance forces fusion on every finding.
    enabled: bool = True
    high_assurance: bool = False


@dataclass(frozen=True)
class ComplexityConfig:
    # Stage-2 map size and hunter attention. Small defaults keep PR/nightly map work cheap.
    top_k: int = 20
    max_hunter_hotspots: int = 8


@dataclass(frozen=True)
class RegressConfig:
    # Stage-3 candidate cap and optional per-language sandbox image pins. Isolation limits stay on SandboxConfig.
    max_candidates: int = 5
    images: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ModelLayerConfig:
    # contributor-scan: the model layer in MAP. Named for the LAYER, not the model: `ModelConfig` is already
    # the `[models]` block (hunter, judge, endpoint) and two meanings of one name is how you get a scan that
    # silently reads the wrong settings. Additive -- without a CPG engine the scan is unchanged.
    enabled: bool = True
    # A TOTAL for the run, not a per-region cap. Conservative by default: a first scan of an unfamiliar
    # repository should not be able to run away with someone's budget before they have decided they want it.
    max_model_calls: int = 100
    max_regions: int = 300


@dataclass(frozen=True)
class ObligationsConfig:
    # authorization-obligations: the obligation checker in MAP (standard/deep only).
    enabled: bool = True
    min_siblings: int = 3
    policy_path: str = ".openultrasast/obligations.toml"


@dataclass(frozen=True)
class PushConfig(Contract):
    """Inert experimental push settings; configuring them does not install a hook.

    The 2 GiB local cache cap is a storage budget, not a performance promise. The
    eventual cache evicts unleased entries; deadline and cleanup are separate costs.
    No endpoint, fetch, engine download or capability admission is enabled here.
    """

    comparison_base: str | None = None
    deadline_seconds: float = 30.0
    cancellation_allowance_seconds: float = 2.0
    cache_max_bytes: int = 2 * 1024**3
    mode: Literal["advisory", "blocking"] = "advisory"
    incomplete_coverage_policy: Literal["allow", "block"] = "allow"

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.deadline_seconds <= 0 or self.cancellation_allowance_seconds <= 0 or self.cache_max_bytes <= 0:
            raise ValueError("push deadlines, cancellation allowance and cache limit must be positive")


@dataclass(frozen=True)
class ResolvedConfig:
    models: ModelConfig = ModelConfig()
    embeddings: EmbeddingConfig = EmbeddingConfig()
    sandbox: SandboxConfig = SandboxConfig()
    static_analysis: StaticAnalysisConfig = StaticAnalysisConfig()
    score: ScoreConfig = ScoreConfig()
    ruleset: RulesetConfig = RulesetConfig()
    fusion: FusionConfig = FusionConfig()
    hardening: HardeningConfig = HardeningConfig()
    complexity: ComplexityConfig = ComplexityConfig()
    regress: RegressConfig = RegressConfig()
    obligations: ObligationsConfig = ObligationsConfig()
    model: ModelLayerConfig = ModelLayerConfig()
    push: PushConfig = PushConfig()
    runs_dir: str = ".openultrasast/runs"


def load_config(config_path: Path | None = None, *, dotenv: bool = True) -> ResolvedConfig:
    if dotenv:
        load_dotenv()
    data: dict[str, object] = {}
    if config_path is not None and config_path.exists():
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
    _check_retired(data)

    return ResolvedConfig(
        models=_load_models(data.get("models", {})),
        embeddings=_load_embeddings(data.get("embeddings", {})),
        sandbox=_load_sandbox(data.get("sandbox", {})),
        static_analysis=_load_static_analysis(data.get("static_analysis", {})),
        score=_load_score(data.get("score", {})),
        ruleset=_load_ruleset_config(data.get("ruleset", {})),
        fusion=_load_fusion(data.get("fusion", {})),
        hardening=_load_hardening(data.get("hardening", {})),
        complexity=_load_complexity(data.get("complexity", {})),
        regress=_load_regress(data.get("regress", {})),
        obligations=_load_obligations(data.get("obligations", {})),
        model=_load_model(data.get("model", {})),
        push=PushConfig.from_payload(data.get("push", {})),
        runs_dir=os.environ.get("OPENULTRASAST_RUNS_DIR", ".openultrasast/runs"),
    )


def config_payload(config: ResolvedConfig) -> dict[str, object]:
    """Reproducible resolved settings, including the separate experimental push policy."""
    return asdict(config)


def write_resolved_config(config: ResolvedConfig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config_payload(config), indent=2, sort_keys=True) + "\n")


def _section(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _load_models(value: object) -> ModelConfig:
    data = _section(value)
    return ModelConfig(
        ranker=_string(data.get("ranker")),
        hunter=_string(data.get("hunter")),
        judge=_string(data.get("judge")),
        chat_base_url=_string(data.get("chat_base_url")),
        chat_api_key_env=_string(data.get("chat_api_key_env")),
        thinking=bool(data.get("thinking", False)),
    )


def _load_embeddings(value: object) -> EmbeddingConfig:
    data = _section(value)
    return EmbeddingConfig(
        model=_string(data.get("model")) or _string(os.environ.get("OPENROUTER_EMBEDDING_MODEL")),
        store=_string(data.get("store")) or DEFAULT_VECTOR_STORE,
    )


def _load_sandbox(value: object) -> SandboxConfig:
    data = _section(value)
    return SandboxConfig(
        network=bool(data.get("network", False)),
        workspace_readonly=bool(data.get("workspace_readonly", True)),
        memory_mb=_int_value(data.get("memory_mb"), 2048),
        timeout_seconds=_int_value(data.get("timeout_seconds"), 300),
        pids_limit=_int_value(data.get("pids_limit"), 512),
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


def _load_hardening(value: object) -> HardeningConfig:
    data = _section(value)
    return HardeningConfig(
        redact_secrets=bool(data.get("redact_secrets", True)),
        max_findings=_int_value(data.get("max_findings"), 0),
    )


def _load_fusion(value: object) -> FusionConfig:
    data = _section(value)
    return FusionConfig(
        enabled=bool(data.get("enabled", True)),
        high_assurance=bool(data.get("high_assurance", False)),
    )


def _load_complexity(value: object) -> ComplexityConfig:
    data = _section(value)
    return ComplexityConfig(
        top_k=_int_value(data.get("top_k"), 20),
        max_hunter_hotspots=_int_value(data.get("max_hunter_hotspots"), 8),
    )


def _load_regress(value: object) -> RegressConfig:
    data = _section(value)
    return RegressConfig(
        max_candidates=_int_value(data.get("max_candidates"), 5),
        images=_string_map(data.get("images")),
    )


def _string_map(value: object) -> tuple[tuple[str, str], ...]:
    data = _section(value)
    images: list[tuple[str, str]] = []
    for key, item in data.items():
        pinned = _string(item)
        if pinned is not None:
            images.append((str(key), pinned))
    return tuple(sorted(images))


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


def _load_model(value: object) -> ModelLayerConfig:
    data = _section(value)
    return ModelLayerConfig(
        enabled=bool(data.get("enabled", ModelLayerConfig.enabled)),
        max_model_calls=_int_value(data.get("max_model_calls"), ModelLayerConfig.max_model_calls),
        max_regions=_int_value(data.get("max_regions"), ModelLayerConfig.max_regions),
    )


def _load_obligations(value: object) -> ObligationsConfig:
    data = _section(value)
    return ObligationsConfig(
        enabled=bool(data.get("enabled", True)),
        min_siblings=_int_value(data.get("min_siblings"), 3),
        policy_path=str(data.get("policy_path", ".openultrasast/obligations.toml")),
    )
