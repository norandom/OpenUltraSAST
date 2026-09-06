"""What a round proposes, and who may propose it (learning-harness, Req 9.1, 9.2, 5.4, 7.6).

A proposer is handed facts, never scores it is about to be judged on: the misses and leaks of one family
on the train split, what each run actually did, and the hypotheses this family already tried and lost.
Self-diagnosis from free narrative confabulates; structured facts are what make a proposal answerable.

A proposal is one hypothesis, one lever, and one file inside one family's directory. The narrowness is
the safety property: a round can only touch what it targets, so every other family is frozen by
construction rather than by promise, and the verifier code and the corpus stay outside every write root.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from ..harness_ext import has_harnessx
from .detectors import MAX_PROMPT_CHARS, FamilyConfig
from .journal import LearningJournal
from .scoring import PairFamilyScore

Lever = Literal["tool", "checklist", "counterexample", "memory", "prompt"]
LEVERS: tuple[Lever, ...] = ("tool", "checklist", "counterexample", "memory", "prompt")
# The only files a round may write, one per lever. Anything else is a proposal reaching beyond its family.
EDITABLE_FILES: dict[Lever, str] = {
    "tool": "family.toml",
    "checklist": "checklist.md",
    "counterexample": "counterexamples.jsonl",
    "memory": "hard_negatives.jsonl",
    "prompt": "prompt.md",
}


@dataclass(frozen=True)
class PairFact:
    """What one pair did, in terms a proposer can act on."""

    pair: str
    outcome: str
    runs: tuple[str, ...] = ()
    other_findings: int = 0
    rung: str = "suspicion"

    def to_dict(self) -> dict[str, object]:
        return {
            "pair": self.pair,
            "outcome": self.outcome,
            "runs": list(self.runs),
            "other_findings": self.other_findings,
            "rung": self.rung,
        }


@dataclass(frozen=True)
class FailureFacts:
    family: str
    config: FamilyConfig
    misses: tuple[PairFact, ...] = ()
    leaks: tuple[PairFact, ...] = ()
    rejected: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "config_version": self.config.version,
            "tools": list(self.config.tools),
            "misses": [item.to_dict() for item in self.misses],
            "leaks": [item.to_dict() for item in self.leaks],
            "rejected": list(self.rejected),
        }


@dataclass(frozen=True)
class Proposal:
    hypothesis: str
    lever: Lever
    change: Mapping[str, str]  # file name inside the family directory -> its new contents
    predicted_affected: tuple[str, ...] = ()
    predicted_at_risk: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "hypothesis": self.hypothesis,
            "lever": self.lever,
            "change": dict(self.change),
            "predicted_affected": list(self.predicted_affected),
            "predicted_at_risk": list(self.predicted_at_risk),
        }


class Proposer(Protocol):
    def propose(self, facts: FailureFacts) -> Proposal | None: ...


def build_failure_facts(
    scores: Sequence[PairFamilyScore],
    *,
    family: str,
    config: FamilyConfig,
    journal: LearningJournal,
    train_pairs: set[str],
) -> FailureFacts:
    """The facts of one family's failures on the train split. A holdout pair never appears here (Req 5.4)."""
    mine = [item for item in scores if item.family == family and item.pair in train_pairs and item.outcome != "unscorable"]
    return FailureFacts(
        family=family,
        config=config,
        misses=tuple(_fact(item, item.other_findings_vuln) for item in mine if item.outcome in {"both_silent", "reversed"}),
        leaks=tuple(_fact(item, item.other_findings_fixed) for item in mine if item.outcome in {"both_flagged", "reversed"}),
        rejected=journal.rejected_buffer(family),
    )


def refuse_proposal(proposal: Proposal, config: FamilyConfig) -> str | None:
    """None when the proposal is one legal change to its own family; otherwise why it is refused."""
    if proposal.lever not in LEVERS:
        return f"unknown lever {proposal.lever!r}; expected one of {', '.join(LEVERS)}"
    if len(proposal.change) != 1:
        return f"a round changes one file, not {len(proposal.change)}"
    name, content = next(iter(proposal.change.items()))
    if "/" in name or "\\" in name or name.startswith("."):
        return f"{name!r} reaches outside the family directory"
    if name != EDITABLE_FILES[proposal.lever]:
        return f"{name!r} is not the file the {proposal.lever!r} lever writes ({EDITABLE_FILES[proposal.lever]})"
    if name == "prompt.md" and len(content) + len(config.checklist) > MAX_PROMPT_CHARS:
        return f"the proposed prompt exceeds the cap of {MAX_PROMPT_CHARS} characters"
    if name == "checklist.md" and len(content) + len(config.prompt) > MAX_PROMPT_CHARS:
        return f"the proposed checklist exceeds the cap of {MAX_PROMPT_CHARS} characters"
    return None


def apply_proposal(proposal: Proposal, directory: Path) -> None:
    """Write the one file, inside the one directory. Callers snapshot first so a rejection can revert."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in proposal.change.items():
        (directory / name).write_text(content, encoding="utf-8")


def write_roots(configs_dir: Path, family: str) -> tuple[Path, ...]:
    """Everything a round may write: exactly one family's directory, and never the verifiers or the corpus."""
    return (configs_dir / family,)


@dataclass
class ScriptedProposer:
    """A fixed sequence of proposals, for tests and for the first offline rounds."""

    proposals: list[Proposal] = field(default_factory=list)
    used: int = 0

    def propose(self, facts: FailureFacts) -> Proposal | None:
        del facts
        if self.used >= len(self.proposals):
            return None
        self.used += 1
        return self.proposals[self.used - 1]


MetaAgentCall = Callable[..., str]


@dataclass
class HarnessXProposer:
    """The meta-agent, with write access limited to a copy of the family directory it is targeting.

    It never edits the live tree. The round snapshots the family directory *after* a proposal exists, so a proposer
    that wrote in place would have changed the configuration before there was anything to restore, and a rejection
    could not put it back. The agent works in a scratch copy and the proposal is the diff of that copy, which also
    means the one-file rule and the lever whitelist are enforced on what the agent actually did rather than on what
    it claimed (Req 9.1, 9.2, 5.4).
    """

    configs_dir: Path
    model: str
    # The vendor the meta-agent talks to. Hard-coding anthropic here sent it to a provider with no key configured
    # while the detector was talking to DeepSeek, and the round journalled that as "no proposal".
    provider: str = "anthropic"
    reason: str = ""
    agent: MetaAgentCall | None = None  # injected in tests; None composes MetaAgent behind harness_ext

    def write_roots(self, family: str) -> tuple[Path, ...]:
        return write_roots(self.configs_dir, family)

    def propose(self, facts: FailureFacts) -> Proposal | None:
        call = self.agent
        if call is None:
            if not has_harnessx():
                self.reason = "harnessx_unavailable"
                return None
            try:
                call = _meta_agent_call(self.provider)
            except Exception:  # noqa: BLE001 — a proposer that cannot start proposes nothing and says so
                self.reason = "harnessx_unavailable"
                return None
        family_dir = self.configs_dir / facts.family
        with tempfile.TemporaryDirectory(prefix="ousast-propose-") as scratch:
            workspace = Path(scratch) / facts.family
            shutil.copytree(family_dir, workspace)
            before = _directory_text(workspace)
            try:
                hypothesis = call(workspace=workspace, facts=facts, model=self.model)
            except (TypeError, AttributeError, ImportError):
                # "we called the agent wrong" is not "the agent declined", and folding one into the other is how a
                # broken composition reads as a quiet round for as long as nobody looks.
                raise
            except Exception as exc:  # noqa: BLE001 — an agent that failed proposed nothing, and the round says why
                self.reason = f"meta_agent_failed: {type(exc).__name__}"
                return None
            after = _directory_text(workspace)
        changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
        if not changed:
            self.reason = "no_change_proposed"
            return None
        if len(changed) > 1:
            self.reason = f"a round changes one file, not {len(changed)}: {', '.join(changed)}"
            return None
        name = changed[0]
        lever: Lever | None = next((key for key, filename in EDITABLE_FILES.items() if filename == name), None)
        if lever is None or name not in after:
            self.reason = f"{name!r} is not a file any lever writes"
            return None
        self.reason = ""
        return Proposal(
            hypothesis=str(hypothesis or "").strip() or f"meta-agent edit to {name}",
            lever=lever,
            change={name: after[name]},
            predicted_affected=tuple(item.pair for item in facts.misses),
            predicted_at_risk=tuple(item.pair for item in facts.leaks),
        )


def _directory_text(directory: Path) -> dict[str, str]:
    """Every readable file directly inside ``directory``, by name. Nested paths are not a lever's business."""
    out: dict[str, str] = {}
    for path in sorted(directory.iterdir()) if directory.is_dir() else []:
        if path.is_file():
            try:
                out[path.name] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
    return out


def _meta_agent_class() -> type:
    """`MetaAgent` behind `harness_ext`. A seam, so the argument contract can be pinned without the extra."""
    from ..harness_ext import require_harnessx

    require_harnessx()
    from harnessx.meta_harness.agent import MetaAgent  # type: ignore[import-not-found]

    return MetaAgent  # type: ignore[no-any-return]


def _model_config(model: str, provider: str = "anthropic") -> object:
    """`MetaAgent(inner_model=...)` takes a `ModelConfig`, never a model name; the name goes to the provider."""
    from ..harness_ext import build_provider, require_harnessx

    require_harnessx()
    from harnessx.core.model_config import ModelConfig  # type: ignore[import-not-found]

    return ModelConfig(main=build_provider(model, provider))


def _meta_agent_call(provider: str = "anthropic") -> MetaAgentCall:
    """Compose `MetaAgent.evolve` behind `harness_ext`, writing only inside the scratch copy.

    `evolve` is a coroutine and returns a HarnessX config path; what this proposer takes from it is the state of the
    workspace afterwards, so the return value is only used for the hypothesis line.
    """
    from ..harness_ext import require_harnessx

    require_harnessx()

    def call(*, workspace: Path, facts: FailureFacts, model: str) -> str:
        import asyncio

        trajectories = workspace.parent / "trajectories"
        trajectories.mkdir(parents=True, exist_ok=True)
        (trajectories / "facts.json").write_text(facts_prompt(facts), encoding="utf-8")
        agent = _meta_agent_class()(inner_model=_model_config(model, provider), allowed_write_roots=(workspace,))
        output = workspace.parent / "meta-out"
        output.mkdir(parents=True, exist_ok=True)
        asyncio.run(agent.evolve(current_config=workspace, trajectories_dir=trajectories, output_dir=output))
        return f"meta-agent round for {facts.family}"

    return call


def _fact(score: PairFamilyScore, other: int) -> PairFact:
    return PairFact(pair=score.pair, outcome=score.outcome, runs=score.runs, other_findings=other, rung=score.rung)


def facts_prompt(facts: FailureFacts) -> str:
    """The facts as the proposer sees them: structured, and free of anything it will be judged on."""
    return json.dumps(facts.to_dict(), indent=2, sort_keys=True)


__all__ = [
    "EDITABLE_FILES",
    "LEVERS",
    "FailureFacts",
    "HarnessXProposer",
    "Lever",
    "PairFact",
    "Proposal",
    "Proposer",
    "ScriptedProposer",
    "apply_proposal",
    "build_failure_facts",
    "facts_prompt",
    "refuse_proposal",
    "write_roots",
]
