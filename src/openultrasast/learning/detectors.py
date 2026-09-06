"""Per-family detector configurations and the runner that uses them (learning-harness, Req 6.1-6.5).

A detector is a configuration, not code: a system prompt, an evidence checklist, the curated tools it
may call, its step and cost budget, and the hard negatives and counterexamples earlier rounds left it.
Round zero writes one directory per family from the same prompt, so the baseline is controlled, and a
round rewrites exactly one directory and bumps that family's version. Every other family is frozen by
construction, because a round can only touch the directory it targets.

The runner gives a detector the whole file rather than an excerpt around a hotspot, since context loss
is a documented cause of misjudging patched code, and tags each finding with exactly one family and the
configuration version that produced it, so a finding can always be traced back to what made it.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..findings import StaticFinding
from ..tool_hunter import HUNTER_TOOLS, ChatClient, run_tool_hunter
from .families import FamilyTaxonomy

MAX_PROMPT_CHARS = 8000  # prompt plus checklist; unbounded prompts are the documented signature of overfitting
GENERALIST = "unknown"  # the family every region also runs, so a bug outside the taxonomy is still looked for
CURATED_TOOLS = tuple(str(schema["function"]["name"]) for schema in HUNTER_TOOLS)  # type: ignore[index]
_REQUIRED = ("prompt.md", "family.toml")


class DetectorConfigError(ValueError):
    """Raised when a detector configuration is missing, over its cap, or names something outside the closed sets."""


@dataclass(frozen=True)
class FamilyConfig:
    family: str
    version: str
    prompt: str
    checklist: str
    tools: tuple[str, ...]
    max_steps: int
    max_cost_usd: float
    max_chars: int
    hard_negatives: tuple[Mapping[str, object], ...] = ()
    counterexamples: tuple[Mapping[str, object], ...] = ()

    @property
    def detector_id(self) -> str:
        return f"{self.family}@{self.version}"


@dataclass(frozen=True)
class Region:
    """A place a detector is pointed at: one file, optionally one function, and the families admitted for it."""

    path: str
    function: str | None = None
    families: tuple[str, ...] = ()


def load_family_configs(configs_dir: Path, taxonomy: FamilyTaxonomy) -> dict[str, FamilyConfig]:
    """Every configuration under ``configs_dir``. A directory that is not a family, or a broken one, fails loud."""
    known = {family.id for family in taxonomy.families}
    configs: dict[str, FamilyConfig] = {}
    for directory in sorted(path for path in configs_dir.iterdir() if path.is_dir()) if configs_dir.is_dir() else []:
        if directory.name not in known:
            raise DetectorConfigError(f"{directory}: {directory.name!r} is not a family; expected one of {', '.join(sorted(known))}")
        configs[directory.name] = _load_one(directory)
    return configs


def _load_one(directory: Path) -> FamilyConfig:
    for name in _REQUIRED:
        if not (directory / name).is_file():
            raise DetectorConfigError(f"{directory}: {name} is required")
    try:
        settings = tomllib.loads((directory / "family.toml").read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise DetectorConfigError(f"{directory / 'family.toml'}: not valid TOML: {exc}") from exc
    version = str(settings.get("version", "")).strip()
    if not version:
        raise DetectorConfigError(f"{directory}: version is required")
    prompt = (directory / "prompt.md").read_text(encoding="utf-8").strip()
    checklist = _read_optional(directory / "checklist.md")
    if len(prompt) + len(checklist) > MAX_PROMPT_CHARS:
        raise DetectorConfigError(
            f"{directory}: prompt and checklist length {len(prompt) + len(checklist)} exceeds the cap of {MAX_PROMPT_CHARS}"
        )
    tools = tuple(str(name) for name in settings.get("tools", []) or ())
    if not tools:
        raise DetectorConfigError(f"{directory}: tools is required and must not be empty; a detector with no tools reports nothing")
    unknown_tools = [name for name in tools if name not in CURATED_TOOLS]
    if unknown_tools:
        raise DetectorConfigError(f"{directory}: unknown tool(s) {', '.join(unknown_tools)}; expected from {', '.join(CURATED_TOOLS)}")
    return FamilyConfig(
        family=directory.name,
        version=version,
        prompt=prompt,
        checklist=checklist,
        tools=tools,
        max_steps=int(settings.get("max_steps", 4)),
        max_cost_usd=float(settings.get("max_cost_usd", 0.5)),
        max_chars=int(settings.get("max_chars", 4000)),
        hard_negatives=_read_jsonl(directory / "hard_negatives.jsonl"),
        counterexamples=_read_jsonl(directory / "counterexamples.jsonl"),
    )


def run_family_detector(root: Path, region: Region, config: FamilyConfig, *, client: ChatClient, model: str) -> list[StaticFinding]:
    """One family's detector over one region. Findings carry that family and the configuration that found them."""
    return run_tool_hunter(
        root,
        [],
        client=client,
        model=model,
        max_steps=config.max_steps,
        system_prompt=config.prompt,
        user_prompt=_question(region, config),
        context_files=(region.path,),
        tools=config.tools,
        max_chars=config.max_chars,
        tags=(f"family:{config.family}", f"detector:{config.detector_id}"),
    )


def run_region_detectors(
    root: Path, region: Region, configs: Mapping[str, FamilyConfig], *, client: ChatClient, model: str
) -> list[StaticFinding]:
    """Every family the classifier admitted for this region, plus the generalist (Req 6.3)."""
    wanted = [family for family in region.families if family in configs and family != GENERALIST]
    if GENERALIST in configs:
        wanted.append(GENERALIST)
    findings: list[StaticFinding] = []
    for family in wanted:
        findings.extend(run_family_detector(root, region, configs[family], client=client, model=model))
    return findings


def write_default_configs(
    configs_dir: Path, taxonomy: FamilyTaxonomy, *, prompt: str, version: str, tools: Sequence[str] | None = None
) -> dict[str, Path]:
    """Round zero: one directory per family from the same prompt, so the baseline is controlled (Req 8.1)."""
    written: dict[str, Path] = {}
    for family in taxonomy.families:
        directory = configs_dir / family.id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "prompt.md").write_text(f"{prompt}\n\nFamily: {family.id}. {family.description}\n", encoding="utf-8")
        (directory / "checklist.md").write_text("- name the file, the line and why the code is reachable\n", encoding="utf-8")
        selected = list(tools) if tools is not None else list(CURATED_TOOLS)
        (directory / "family.toml").write_text(
            f'version = "{version}"\ntools = {json.dumps(selected)}\nmax_steps = 4\nmax_cost_usd = 0.5\nmax_chars = 4000\n',
            encoding="utf-8",
        )
        for name in ("hard_negatives.jsonl", "counterexamples.jsonl"):
            if not (directory / name).exists():
                (directory / name).write_text("", encoding="utf-8")
        written[family.id] = directory
    return written


def _question(region: Region, config: FamilyConfig) -> str:
    where = f"{region.path}::{region.function}" if region.function else region.path
    parts = [f"Look for {config.family} problems in {where}. The whole file follows."]
    if config.checklist:
        parts.append(f"Evidence checklist:\n{config.checklist}")
    if config.hard_negatives:
        parts.append("Known non-issues, do not report these:\n" + "\n".join(_line(item) for item in config.hard_negatives))
    if config.counterexamples:
        parts.append("Worked examples:\n" + "\n".join(_line(item) for item in config.counterexamples))
    parts.append("Reply with a JSON array of objects with path, line, title and rationale, after using a tool.")
    return "\n\n".join(parts)


def _line(item: Mapping[str, object]) -> str:
    return "- " + "; ".join(f"{key}: {value}" for key, value in sorted(item.items()))


def _read_optional(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip() if path.is_file() else ""


def _read_jsonl(path: Path) -> tuple[Mapping[str, object], ...]:
    if not path.is_file():
        return ()
    rows: list[Mapping[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DetectorConfigError(f"{path}: not valid JSON lines: {exc}") from exc
        if isinstance(payload, dict):
            rows.append(payload)
    return tuple(rows)


__all__ = [
    "CURATED_TOOLS",
    "GENERALIST",
    "MAX_PROMPT_CHARS",
    "DetectorConfigError",
    "FamilyConfig",
    "Region",
    "load_family_configs",
    "run_family_detector",
    "run_region_detectors",
    "write_default_configs",
]
