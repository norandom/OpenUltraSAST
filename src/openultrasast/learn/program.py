"""The decision engine's program: a declared language-model classifier with local memory (design 4.1, Req 3.1).

DSPy-style and in-house. The **signature** (:data:`SIGNATURE`) declares what goes in -- the candidate's code
excerpt, its allow-listed signals, its inferred roles, its family -- and what comes out: ``verdict``
(``vulnerable | not_vulnerable | unsure``), ``family``, ``confidence`` in [0, 1] and a ``rationale`` of at most three
sentences citing at least one line of the code. The **modules** are ``Retrieve -> Classify(k)``:

- the prompt is the instruction plus the compiled demonstrations -- a prefix that is byte-identical for every
  candidate, so the provider's prefix cache hits -- then the retrieved examples, then the candidate;
- sample 1 runs at temperature 0, samples 2..k at 0.7; an answer that does not parse, or cites no line in range, is
  asked once more at temperature 0 and otherwise becomes ``unsure`` with ``parse_failed`` -- never ``not_vulnerable``;
- the raw score is ``s = mean_j p_j`` (``p_j`` the confidence of a ``vulnerable`` answer, one minus it for
  ``not_vulnerable``, 0.5 for ``unsure``); the verdict is the majority (ties are ``unsure``), and a majority
  ``unsure`` can never BLOCK.

Signals reach the prompt only through :func:`.schema.validate_x` (no ``EXCLUDED_FIELDS``, no free text) and the input
profile (``ProgramSpec.inputs``, default ``v1``: the engine instrument is withheld from prompts and from the retrieval
distance, see :data:`.schema.INPUT_PROFILES`); a missing
instrument is shown in words. Every model call goes through :class:`Caller`: a response cache keyed by
``sha256(model, Model parameters digest, messages, temperature, sample, json_object)`` stored as
``responses/<sha>.json``, so a rerun on the same inputs replays at $0 and reproduces byte for byte. Before a call the
rendered example and demonstration ids are checked against the evaluation boundary
(:func:`.retrieve.assert_boundary`).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from ..plane.budget import cost_of, prices_from
from ..plane.memory import MemoryStore
from .examples import Example
from .folds import Fold
from .retrieve import Retrieval, Target, assert_boundary, demonstrations_for, retrieve
from .schema import DEFAULT_INPUTS, features_for, instruments_for, validate_x, withheld

VERDICTS = ("vulnerable", "not_vulnerable", "unsure")
UNSURE = "unsure"
TEMPERATURES = (0.0, 0.7)
MAX_OUTPUT_TOKENS = 300
CHARS_PER_TOKEN = 4.0
STATE_WORDS = {"none": "no coverage", "failed": "failed", "not_applicable": "not applicable"}
_LINE_NUMBER = re.compile(r"^\s*(\d+)  ")


class ReplayMiss(RuntimeError):
    """A replay-only run (no client) met a request that is not in the response cache."""


@dataclass(frozen=True)
class Field:
    name: str
    direction: str  # in | out
    type: str
    bound: str


@dataclass(frozen=True)
class Signature:
    fields: tuple[Field, ...]

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps([asdict(f) for f in self.fields], sort_keys=True).encode()).hexdigest()


SIGNATURE = Signature(
    (
        Field("code", "in", "excerpt", "numbered lines, <= 80 lines and 4,000 characters; a delta adds the diff (<= 40 lines)"),
        Field(
            "signals",
            "in",
            "record",
            "the allow-listed features the input profile shows, as name: value lines; a missing instrument in words",
        ),
        Field("roles", "in", "roles", "inferred roles of the function: role, operation, line, origin"),
        Field("family", "in", "family", "the candidate's family, or unknown"),
        Field("verdict", "out", "enum", "vulnerable | not_vulnerable | unsure"),
        Field("family", "out", "family", "one of the families, or none"),
        Field("confidence", "out", "float", "[0, 1]: the probability that the verdict is right"),
        Field("rationale", "out", "text", "at most 3 sentences; cites at least one line number of code (cited_lines)"),
    )
)

# The answer contract is part of the signature, not of the searched instruction: a proposed instruction that leaves it
# out still gets it (``render_prefix``), so every prompt asks for JSON (DeepSeek's JSON mode refuses a prompt that
# never says "json") and every answer can parse.
ANSWER_FORMAT = (
    'Answer with one JSON object: {"verdict": "vulnerable" | "not_vulnerable" | "unsure", "family": <family or\n'
    '"none">, "confidence": <probability in [0, 1] that your verdict is right>, "rationale": <at most 3 sentences>,\n'
    '"cited_lines": [<line numbers of the code that support the verdict>]}. Cite at least one line. Say "unsure"\n'
    "when the code does not decide it."
)
BASELINE_INSTRUCTION = (
    "You decide whether a function contains an exploitable security vulnerability of the given family.\n"
    "You see the function's code (numbered lines), the signals static instruments emitted for it, and the roles\n"
    "inferred for its calls. Signals are evidence, not verdicts: rules over-report, and a missing instrument is not a\n"
    "negative. Similar labelled functions from other repositories follow as examples; reason about this code.\n" + ANSWER_FORMAT
)


# --- rendering ---------------------------------------------------------------------------------------------------------


def render_signals(x: Mapping[str, Any], instruments: Mapping[str, Mapping[str, Any]], profile: str, inputs: str = DEFAULT_INPUTS) -> str:
    """``name: value`` per feature of an instrument that ran; ``<instrument>: no coverage | failed | not applicable``
    otherwise. The record is validated first: an unknown, label or identity field never reaches a prompt. An
    instrument the input profile withholds (:data:`.schema.INPUT_PROFILES`; v1: the engine) is not rendered at all --
    neither its state nor its values -- though the stored record keeps it."""
    validate_x(x, instruments, profile)
    hidden = withheld(inputs)
    lines: list[str] = []
    for name in instruments_for(profile):
        if name == "language" or name in hidden:
            continue
        state = str(instruments[name]["state"])
        if state != "ran":
            lines.append(f"{name}: {STATE_WORDS[state]}")
            continue
        for spec in features_for(profile):
            if spec.instrument == name and spec.name not in hidden:
                value = x[spec.name]
                lines.append(f"{spec.name}: {'null' if value is None else json.dumps(value)}")
    return "\n".join(lines)


def render_roles(roles: Sequence[Mapping[str, Any]]) -> str:
    if not roles:
        return "none inferred"
    keys = ("role", "kind", "operation", "line", "origin")
    return "\n".join(", ".join(f"{k}={r[k]}" for k in keys if k in r and k != "path") for r in roles)


def _case(
    code: str,
    x: Mapping[str, Any],
    instruments: Mapping[str, Mapping[str, Any]],
    roles: Sequence[Mapping[str, Any]],
    family: str,
    profile: str,
    language: str,
    inputs: str = DEFAULT_INPUTS,
) -> str:
    signals = render_signals(x, instruments, profile, inputs)
    return f"Family: {family}\nLanguage: {language}\nCode:\n{code.rstrip()}\nSignals:\n{signals}\nRoles:\n{render_roles(roles)}"


def label_word(label: int) -> str:
    return "vulnerable" if label == 1 else "not_vulnerable"


@dataclass(frozen=True)
class Demo:
    """A compiled demonstration: an example of ``C_boot`` with the rationale the program gave without seeing its label."""

    example_id: str
    excerpt_sha: str
    label: int
    family: str
    verdict: str
    confidence: float
    rationale: str
    cited_lines: tuple[int, ...]
    alternate: Demo | None = None

    def as_dict(self) -> dict[str, Any]:
        out = {k: v for k, v in asdict(self).items() if k != "alternate"}
        out["cited_lines"] = list(self.cited_lines)
        out["alternate"] = self.alternate.as_dict() if self.alternate is not None else None
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Demo:
        alt = data.get("alternate")
        return cls(
            str(data["example_id"]), str(data["excerpt_sha"]), int(data["label"]), str(data["family"]), str(data["verdict"]),
            float(data["confidence"]), str(data["rationale"]), tuple(int(n) for n in data.get("cited_lines") or ()),
            cls.from_dict(alt) if isinstance(alt, Mapping) else None,
        )  # fmt: skip


@dataclass(frozen=True)
class ProgramSpec:
    """What a compiled program fixes: instruction, demonstrations, model and sampling, retrieval settings."""

    instruction: str = BASELINE_INSTRUCTION
    demos: tuple[Demo, ...] = ()
    profile: str = "static"
    model: str = "deepseek-flash"
    k: int = 1
    k_ret: int = 6
    lam: float = 0.5
    n1: int = 40
    priors: str = "off"
    inputs: str = DEFAULT_INPUTS  # the input profile: which instruments the classifier never sees (v1: the engine)
    max_output_tokens: int = MAX_OUTPUT_TOKENS


@dataclass(frozen=True)
class Candidate:
    """A candidate as the program sees it: retrieval's target and the rendered (bounded, redacted) excerpt."""

    target: Target
    code: str
    language: str
    roles: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class Prompt:
    messages: list[dict[str, object]]
    example_ids: tuple[str, ...]
    demo_ids: tuple[str, ...]
    valid_lines: frozenset[int]

    @property
    def prefix(self) -> str:
        return str(self.messages[0]["content"])

    @property
    def estimated_tokens(self) -> int:
        return round(sum(len(str(m["content"])) for m in self.messages) / CHARS_PER_TOKEN)


def line_numbers(code: str) -> frozenset[int]:
    """The source line numbers a rendered excerpt shows (the diff part has none)."""
    return frozenset(int(m.group(1)) for line in code.split("\ndiff:\n", 1)[0].splitlines() if (m := _LINE_NUMBER.match(line)))


ExcerptText = Callable[[str], str | None]


def render_prefix(spec: ProgramSpec, demos: Sequence[Demo], examples: Mapping[str, Example], excerpt_text: ExcerptText) -> str:
    """The instruction and the demonstrations: identical for every candidate of one program and fold."""
    instruction = spec.instruction.strip()
    parts = [instruction if ANSWER_FORMAT in instruction else f"{instruction}\n{ANSWER_FORMAT}"]
    for number, demo in enumerate(demos, 1):
        example = examples[demo.example_id]
        code = excerpt_text(demo.excerpt_sha) or ""
        answer = {"verdict": demo.verdict, "family": demo.family, "confidence": demo.confidence, "rationale": demo.rationale,
                  "cited_lines": list(demo.cited_lines)}  # fmt: skip
        parts.append(
            f"Demonstration {number}:\n"
            + _case(code, example.x, example.instruments, example.roles, example.family, spec.profile, example.language, spec.inputs)
            + f"\nAnswer: {json.dumps(answer, sort_keys=True)}"
        )
    return "\n\n".join(parts)


def render(
    spec: ProgramSpec,
    candidate: Candidate,
    retrieved: Sequence[Example],
    demos: Sequence[Demo],
    examples: Mapping[str, Example],
    excerpt_text: ExcerptText,
) -> Prompt:
    """The prompt: [system: instruction + demonstrations] [user: retrieved examples (with their labels) + the candidate
    (without one)]."""
    blocks = []
    for number, example in enumerate(retrieved, 1):
        code = excerpt_text(example.excerpt_sha) or ""
        blocks.append(
            f"Example {number} (label: {label_word(example.label)}):\n"
            + _case(code, example.x, example.instruments, example.roles, example.family, spec.profile, example.language, spec.inputs)
        )
    t = candidate.target
    blocks.append(
        "Candidate:\n" + _case(candidate.code, t.x, t.instruments, candidate.roles, t.family, spec.profile, candidate.language, spec.inputs)
    )
    messages: list[dict[str, object]] = [
        {"role": "system", "content": render_prefix(spec, demos, examples, excerpt_text)},
        {"role": "user", "content": "\n\n".join(blocks)},
    ]
    return Prompt(messages, tuple(e.id for e in retrieved), tuple(d.example_id for d in demos), line_numbers(candidate.code))


# --- parsing -----------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Answer:
    verdict: str
    family: str
    confidence: float
    rationale: str
    cited_lines: tuple[int, ...]
    parse_failed: bool = False

    @property
    def p(self) -> float:
        """The answer's probability that the candidate is vulnerable."""
        if self.verdict == "vulnerable":
            return self.confidence
        if self.verdict == "not_vulnerable":
            return 1.0 - self.confidence
        return 0.5


PARSE_FAILED = Answer(UNSURE, "none", 0.0, "", (), parse_failed=True)


def parse_answer(content: str | None, valid_lines: frozenset[int], families: Sequence[str] = ()) -> Answer | None:
    """The answer, or ``None`` when it does not parse: not one JSON object, a verdict outside the vocabulary, a
    confidence outside [0, 1], no rationale, or no cited line inside the excerpt."""
    from ..provider.openrouter import OpenRouterError, parse_json_content

    try:
        data = parse_json_content(content or "")
    except OpenRouterError:
        return None
    if not isinstance(data, dict) or data.get("verdict") not in VERDICTS:
        return None
    confidence = data.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, int | float) or not 0.0 <= float(confidence) <= 1.0:
        return None
    rationale = data.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        return None
    cited = data.get("cited_lines")
    lines = (
        tuple(sorted({int(n) for n in cited if isinstance(n, int) and not isinstance(n, bool) and n in valid_lines}))
        if isinstance(cited, list)
        else ()
    )
    if not lines:
        return None
    family = data.get("family")
    family = family if isinstance(family, str) and (not families or family in families or family == "none") else "none"
    return Answer(str(data["verdict"]), family, round(float(confidence), 6), rationale.strip()[:600], lines)


# --- calls and the response cache --------------------------------------------------------------------------------------


def request_key(
    model: str, params_digest: str, messages: Sequence[Mapping[str, object]], temperature: float, sample: str, json_object: bool
) -> str:
    canonical = {"json_object": json_object, "messages": list(messages), "model": model, "params": params_digest, "sample": sample,
                 "temperature": temperature}  # fmt: skip
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def params_digest(parameters: Mapping[str, Any] | None) -> str:
    return hashlib.sha256(json.dumps(dict(parameters or {}), sort_keys=True).encode()).hexdigest()


@dataclass
class Caller:
    """Every model call of a program run: cached by request in ``responses/<sha>.json`` (and in memory), replayed at
    $0. ``client`` is a metered client (``plane.budget.MeteredClient``); ``None`` is replay-only."""

    client: Any
    model: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    store: MemoryStore | None = None
    calls: int = 0
    replayed: int = 0
    keys: list[str] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=lambda: {"prompt_tokens": 0, "prompt_cache_hit_tokens": 0, "completion_tokens": 0})
    _memory: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def params_digest(self) -> str:
        return params_digest(self.parameters)

    def _cached(self, key: str) -> dict[str, Any] | None:
        if key in self._memory:
            return self._memory[key]
        if self.store is not None:
            data = self.store.get_blob("responses", key, verify=False)
            if data is not None:
                return dict(json.loads(data))
        return None

    def ask(self, messages: list[dict[str, object]], *, temperature: float, sample: str, json_object: bool = True) -> str:
        key = request_key(self.model, self.params_digest, messages, temperature, sample, json_object)
        self.keys.append(key)
        entry = self._cached(key)
        if entry is not None:
            self.replayed += 1
        else:
            if self.client is None:
                raise ReplayMiss(f"response {key[:12]} is not cached and the run is replay-only")
            before = dict(getattr(self.client, "usage", {}) or {})
            response = self.client.complete(model=self.model, messages=messages, tools=[], json_object=json_object, temperature=temperature)
            after = dict(getattr(self.client, "usage", {}) or {})
            usage = {k: int(after.get(k, 0)) - int(before.get(k, 0)) for k in self.usage}
            entry = {"content": response.content, "model": self.model, "usage": usage}
            self.calls += 1
            if self.store is not None:
                self.store.put_blob("responses", json.dumps(entry, sort_keys=True).encode("utf-8"), name=key)
        if key not in self._memory:  # spend counts once per distinct request, the same on a replay
            for name in self.usage:
                self.usage[name] += int((entry.get("usage") or {}).get(name, 0))
        self._memory[key] = entry
        return str(entry.get("content") or "")

    def usd(self) -> float | None:
        """Spend of every response used, priced from its recorded usage: identical on a replay."""
        prices = prices_from(self.parameters) if self.parameters else None
        return None if prices is None else round(cost_of(self.usage, prices), 6)

    def cache_digest(self) -> str:
        return hashlib.sha256("\n".join(sorted(set(self.keys))).encode()).hexdigest()


# --- classify ----------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    verdict: str
    family: str
    s: float
    votes: Mapping[str, int]
    rationale: str
    cited_lines: tuple[int, ...]
    parse_failed: int
    answers: tuple[Answer, ...]
    retrieval: str = "signals_only"
    neighbours: Mapping[str, Mapping[str, int]] = field(default_factory=dict)

    @property
    def blockable(self) -> bool:
        """A majority ``unsure`` (parse failures included) can never reach BLOCK."""
        return self.verdict != UNSURE


def aggregate(answers: Sequence[Answer]) -> Decision:
    votes = {v: sum(a.verdict == v for a in answers) for v in VERDICTS}
    top = max(votes.values())
    leaders = [v for v, n in votes.items() if n == top]
    verdict = leaders[0] if len(leaders) == 1 else UNSURE
    lead = next((a for a in answers if a.verdict == verdict and not a.parse_failed), None)
    s = sum(a.p for a in answers) / len(answers) if answers else 0.5
    return Decision(
        verdict, lead.family if lead else "none", round(s, 6), votes, lead.rationale if lead else "", lead.cited_lines if lead else (),
        sum(a.parse_failed for a in answers), tuple(answers),
    )  # fmt: skip


def classify(prompt: Prompt, caller: Caller, k: int = 1, *, families: Sequence[str] = ()) -> Decision:
    """``k`` samples (the first at temperature 0, the rest at 0.7); one retry at temperature 0 per unparsable answer."""
    answers: list[Answer] = []
    for j in range(k):
        temperature = TEMPERATURES[0] if j == 0 else TEMPERATURES[1]
        answer = parse_answer(caller.ask(prompt.messages, temperature=temperature, sample=str(j)), prompt.valid_lines, families)
        if answer is None:
            retry = caller.ask(prompt.messages, temperature=TEMPERATURES[0], sample=f"{j}:retry")
            answer = parse_answer(retry, prompt.valid_lines, families) or PARSE_FAILED
        answers.append(answer)
    return aggregate(answers)


@dataclass
class Program:
    """``Retrieve -> Classify(k)`` over one memory snapshot."""

    spec: ProgramSpec
    memory: Sequence[Example]
    excerpt_text: ExcerptText
    vectors: Mapping[str, Sequence[float]] | None = None
    families: Sequence[str] = ()

    def __post_init__(self) -> None:
        self.index = {e.id: e for e in self.memory}

    def prepare(self, candidate: Candidate, fold: Fold, *, seed: int = 0) -> tuple[Prompt, Retrieval]:
        target = candidate.target
        got = retrieve(target, self.memory, fold, vectors=self.vectors, n1=self.spec.n1, k=self.spec.k_ret, lam=self.spec.lam, seed=seed,
                       priors=self.spec.priors, inputs=self.spec.inputs)  # fmt: skip
        usable = [Demo.from_dict(d) for d in demonstrations_for([d.as_dict() for d in self.spec.demos], self.index, target, fold)]
        prompt = render(self.spec, candidate, got.examples, usable, self.index, self.excerpt_text)
        assert_boundary([*prompt.example_ids, *prompt.demo_ids], self.index, target, fold, vectors=self.vectors)
        return prompt, got

    def decide(self, candidate: Candidate, fold: Fold, caller: Caller, *, seed: int = 0) -> Decision:
        prompt, got = self.prepare(candidate, fold, seed=seed)
        decision = classify(prompt, caller, self.spec.k, families=self.families)
        return replace(decision, retrieval=got.mode, neighbours=got.neighbours)


__all__ = [
    "ANSWER_FORMAT", "BASELINE_INSTRUCTION", "PARSE_FAILED", "SIGNATURE", "UNSURE", "VERDICTS", "Answer", "Caller", "Candidate",
    "Decision", "Demo",
    "Program", "ProgramSpec", "Prompt", "ReplayMiss", "aggregate", "classify", "label_word", "line_numbers",
    "params_digest", "parse_answer", "render", "render_prefix", "render_roles", "render_signals", "request_key",
]  # fmt: skip
