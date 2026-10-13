"""The hunt as a DSPy program: a signature over the feature row, three repository tools, and the answer check.

The program sees only the unmasked feature columns of a change, rendered in a fixed order, plus the changed
hunks. Its answer is the classifier's structure (family from the closed list, confidence, rationale, cited
lines). DSPy proposes instructions and demonstrations; the acceptance rule in `accept.py` decides, outside DSPy.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import dspy
import pydantic

from .. import hunter_tools
from ..model.endpoint import _PRICES, DEEPSEEK_BASE_URL, DEFAULT_DETECTOR_MODEL
from ..model.taxonomy import FAMILY_IDS

BASELINE_INSTRUCTION = (
    "You are a security reviewer looking at one pushed change. Use read_file, grep_repo and find_refs to check "
    "whether the changed code introduces a vulnerability that an attacker could reach. Report only what the code "
    "shows: a path, a line, the family from the list, your confidence between 0 and 1, a one-sentence rationale and "
    "the lines you relied on. Report nothing when the change is ordinary."
)

# Input name -> (feature column, renderer). Order is the order the model sees them in; masked columns are absent.
INPUTS: tuple[tuple[str, str, str], ...] = (
    ("change_summary", "", "The files and functions the push touched."),
    ("hunks", "feature.diff.hunks", "Changed line ranges per file at head, as [start, end] pairs."),
    ("function_text", "feature.source.span", "The enclosing function at head, numbered lines."),
    ("callers", "feature.source.callers", "Where the enclosing function is called from: path and line."),
    ("entry_points", "feature.source.entry_points", "In-repository entry points that reach the file."),
    ("roles", "feature.semantic.roles", "Identifiers known as sources, sinks or sanitizers in this function."),
    ("def_use", "feature.semantic.def_use", "Assignments and calls inside the function, with lines."),
    ("obligations", "feature.semantic.obligations", "Checks the code is expected to perform before an operation."),
    ("families", "feature.taxonomy.families", "The closed list of vulnerability families with one-line definitions."),
)


class Finding(pydantic.BaseModel):
    """One suspicion in the classifier's answer structure."""

    path: str
    line: int
    family: str
    confidence: float = 0.5
    rationale: str = ""
    cited_lines: list[int] = pydantic.Field(default_factory=list)


def signature_for(mask: Iterable[str] = ()) -> type[dspy.Signature]:
    """The hunt signature with every unmasked input, in the fixed order, and the findings output."""
    dropped = set(mask)
    fields: dict[str, Any] = {}
    for name, column, desc in INPUTS:
        producer = column.split(".")[1] if column else ""
        if name in dropped or column in dropped or (producer and producer in dropped):
            continue
        fields[name] = (str, dspy.InputField(desc=desc))
    fields["findings"] = (list[Finding], dspy.OutputField(desc="JSON list; empty when the change is ordinary"))
    return dspy.Signature(fields, BASELINE_INSTRUCTION)


def numbered(lines: Sequence[str], start: int, end: int) -> str:
    """Lines start..end (1-based, inclusive) with their numbers, so cited lines can be checked."""
    return "\n".join(f"{number:>5}  {lines[number - 1]}" for number in range(max(start, 1), min(end, len(lines)) + 1))


def render_rows(
    change: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], texts: Mapping[str, Sequence[str]], *, mask: Iterable[str] = ()
) -> dict[str, str]:
    """Render one change's candidate rows into the signature's inputs. Masked inputs are not produced at all."""
    signature = signature_for(mask)
    wanted = set(signature.input_fields)
    out: dict[str, str] = {}
    if "change_summary" in wanted:
        touched = sorted({(row["path"], str(row.get("feature.source.function") or "<module>")) for row in rows})
        out["change_summary"] = "\n".join(f"{path}::{function}" for path, function in touched) or "(nothing readable)"
    if "hunks" in wanted:
        hunks = {row["path"]: row.get("feature.diff.hunks") for row in rows if row.get("feature.diff.hunks")}
        out["hunks"] = json.dumps(hunks, sort_keys=True) if hunks else "(no hunks)"
    if "function_text" in wanted:
        blocks = []
        for row in rows:
            span = row.get("feature.source.span")
            lines = texts.get(row["path"])
            if span and lines:
                blocks.append(f"# {row['path']}::{row.get('feature.source.function')}\n{numbered(lines, span[0], span[1])}")
        out["function_text"] = "\n\n".join(blocks) or "(no function text)"
    for name, column, _ in INPUTS[3:]:
        if name not in wanted:
            continue
        values = {f"{row['path']}::{row.get('feature.source.function') or '<module>'}": row.get(column) for row in rows}
        values = {key: value for key, value in values.items() if value not in (None, [], {})}
        if name == "families":  # one list for the whole change, not one per row
            families = next((value for value in values.values()), None)
            out[name] = "\n".join(f"{f['id']}: {f['definition']}" for f in families) if families else "(no families)"
        else:
            out[name] = json.dumps(values, sort_keys=True) if values else "(none)"
    return out


def shown_lines(inputs: Mapping[str, str]) -> dict[str, set[int]]:
    """The numbered lines the model was shown per path, parsed back from `function_text`."""
    shown: dict[str, set[int]] = {}
    current = None
    for line in inputs.get("function_text", "").splitlines():
        if line.startswith("# ") and "::" in line:
            current = line[2:].split("::", 1)[0]
        elif current and line[:5].strip().isdigit():
            shown.setdefault(current, set()).add(int(line[:5]))
    return shown


def check(findings: Iterable[Finding | Mapping[str, Any]], inputs: Mapping[str, str]) -> list[dict[str, Any]]:
    """Apply the answer rules: a family outside the closed list, or a cited line the model was not shown, scores
    against the program by becoming `unknown` with a reason. Nothing is dropped, so the metric sees it."""
    shown = shown_lines(inputs)
    allowed = {family for family in FAMILY_IDS if family != "unknown"}
    out = []
    for item in findings:
        data = item.model_dump() if isinstance(item, pydantic.BaseModel) else dict(item)
        reasons = []
        if data.get("family") not in allowed:
            reasons.append("family_not_in_list")
        cited = [int(line) for line in data.get("cited_lines") or []]
        if cited and not set(cited) <= shown.get(data.get("path", ""), set()):
            reasons.append("cited_line_not_shown")
        if reasons:
            data["reported_family"] = data.get("family")
            data["family"] = "unknown"
            data["unknown_reason"] = ",".join(reasons)
        out.append(data)
    return out


def repository_tools(root: Path, *, max_chars: int = 4000, max_matches: int = 50) -> list[dspy.Tool]:
    """The three tools the shipped hunter has, bound to one checkout and clamped to it."""
    root = Path(root)

    def read_file(path: str) -> str:
        """Read a file of the repository by its relative path, numbered lines."""
        return hunter_tools.read_file(root, path, max_chars=max_chars)

    def grep_repo(pattern: str) -> str:
        """Search the repository for a regular expression; returns path:line: text, one per line."""
        rows = hunter_tools.grep_repo(root, pattern, max_matches=max_matches)
        return "\n".join(f"{row.get('path')}:{row.get('line')}: {row.get('text', '')}" for row in rows) or "(no matches)"

    def find_refs(symbol: str) -> str:
        """Find where a symbol is referenced in the repository; returns path:line per reference."""
        rows = hunter_tools.find_refs(root, symbol)
        return "\n".join(f"{row.get('path')}:{row.get('line')}" for row in rows) or "(no references)"

    return [dspy.Tool(read_file), dspy.Tool(grep_repo), dspy.Tool(find_refs)]


class HuntProgram(dspy.Module):
    """One hunt over one change. With tools it is a bounded ReAct loop; without, one prediction (tests, dry runs)."""

    def __init__(self, *, mask: Iterable[str] = (), tools: Sequence[dspy.Tool] = (), max_iters: int = 8) -> None:
        super().__init__()
        self.mask = tuple(sorted(set(mask)))
        signature = signature_for(self.mask)
        self.hunt = dspy.ReAct(signature, tools=list(tools), max_iters=max_iters) if tools else dspy.Predict(signature)

    def forward(self, **inputs: str) -> dspy.Prediction:
        prediction = self.hunt(**inputs)
        findings = check(getattr(prediction, "findings", []) or [], inputs)
        return dspy.Prediction(findings=findings, raw=getattr(prediction, "findings", []))


def program_id(program: dspy.Module, *, mask: Iterable[str] = ()) -> str:
    """Content address of a program: its saved state plus the mask, so two identical programs share an id."""
    state = program.dump_state()
    payload = json.dumps({"state": state, "mask": sorted(set(mask))}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_lm(
    model: str = DEFAULT_DETECTOR_MODEL, *, cache_dir: Path | None = None, temperature: float = 0.0, max_tokens: int = 4096
) -> dspy.LM:
    """The research-side model client: DSPy's LM over the DeepSeek endpoint, prices registered from our table.

    The key is read from the environment only; it is never written anywhere. A cache directory per run keeps a
    replay of every response next to the run's artifact."""
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        raise RuntimeError("DEEPSEEK_API_KEY is not set")
    if cache_dir is not None:
        os.environ["DSPY_CACHEDIR"] = str(cache_dir)
    try:
        import litellm

        prices = _PRICES.get(model)
        if prices is not None:
            litellm.register_model(
                {
                    f"openai/{model}": {
                        "input_cost_per_token": prices.input_per_m / 1_000_000,
                        "output_cost_per_token": prices.output_per_m / 1_000_000,
                        "litellm_provider": "openai",
                        "mode": "chat",
                    }
                }
            )
    except Exception as error:  # noqa: BLE001  (a missing price only means cost is reported as unknown)
        print(f"price registration skipped: {type(error).__name__}", flush=True)
    return dspy.LM(f"openai/{model}", api_base=DEEPSEEK_BASE_URL, api_key=key, temperature=temperature, max_tokens=max_tokens, cache=True)
