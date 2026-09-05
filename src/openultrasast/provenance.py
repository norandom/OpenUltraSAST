"""Deterministic provenance fingerprint: does this tree look agent-authored?

pair-corpus-honesty Requirement 6. Signals are files and directories that agent
tooling leaves behind, generation markers in text, and git co-author trailers
over a bounded commit sample. No model is consulted. ``synthetic`` is never
produced by a scan; it is a catalog declaration only.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

PROVENANCE_VALUES = ("human", "agent", "mixed", "synthetic")
AGENT_SHARE_THRESHOLD = 0.85  # VibeApps method: >=85% of sampled commits carry an agent signal
DEFAULT_SAMPLE_COMMITS = 200

_AGENT_PATHS = (
    ".claude",
    "CLAUDE.md",
    "AGENTS.md",
    ".cursor",
    ".cursorrules",
    ".windsurf",
    ".windsurfrules",
    ".github/copilot-instructions.md",
    ".codex",
    ".jules",
    ".kiro",
    ".opencode",
)
_MARKERS = (
    ("Generated with Claude Code", "marker:claude-code"),
    ('<meta name="author" content="Lovable"', "marker:lovable"),
    ("lovable.dev", "marker:lovable"),
    ("bolt.new", "marker:bolt"),
    ("Made with Cursor", "marker:cursor"),
)
_TRAILER_RE = re.compile(
    r"^(?:co-authored-by|generated-by|signed-off-by):\s*.*?(claude|codex|copilot|cursor|devin|jules|gemini|windsurf|aider|openai)\b",
    re.IGNORECASE | re.MULTILINE,
)
_GENERATED_RE = re.compile(r"generated with (claude code|codex|cursor|copilot|devin|jules)", re.IGNORECASE)
_MARKER_FILES = ("index.html", "README.md", "readme.md", "package.json")


@dataclass(frozen=True)
class Provenance:
    value: str
    signals: tuple[str, ...]
    sampled_commits: int = 0
    agent_commits: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "signals": list(self.signals),
            "sampled_commits": self.sampled_commits,
            "agent_commits": self.agent_commits,
        }


def fingerprint(root: Path, *, git: bool = True, sample_commits: int = DEFAULT_SAMPLE_COMMITS) -> Provenance:
    """Classify ``root`` from deterministic signals only. Never raises into a scan."""
    signals: list[str] = []
    for relative in _AGENT_PATHS:
        if (root / relative).exists():
            signals.append(f"path:{relative}")
    for name in _MARKER_FILES:
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")[:200_000]
        except OSError:
            continue
        for needle, label in _MARKERS:
            if needle in text and label not in signals:
                signals.append(label)
    sampled = agent = 0
    if git:
        sampled, agent, git_signal = _git_trailers(root, sample_commits)
        if git_signal:
            signals.append(git_signal)
    if sampled and agent / sampled >= AGENT_SHARE_THRESHOLD:
        value = "agent"
    elif any(not signal.startswith("git:") for signal in signals) or agent:
        value = "mixed"
    else:
        value = "human"
    return Provenance(value=value, signals=tuple(signals), sampled_commits=sampled, agent_commits=agent)


def _git_trailers(root: Path, sample_commits: int) -> tuple[int, int, str]:
    """(sampled, agent-signalled, signal-label). Missing git is a signal, not an error."""
    if sample_commits <= 0:
        return 0, 0, ""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "log", f"-{sample_commits}", "--format=%H%x00%B%x1e"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 0, 0, "git:unavailable"
    if completed.returncode != 0:
        return 0, 0, "git:unavailable"
    entries = [entry for entry in completed.stdout.split("\x1e") if entry.strip()]
    sampled = len(entries)
    agent = sum(1 for entry in entries if _TRAILER_RE.search(entry) or _GENERATED_RE.search(entry))
    if not sampled:
        return 0, 0, "git:no-commits"
    return sampled, agent, f"git:trailers {agent}/{sampled}"
