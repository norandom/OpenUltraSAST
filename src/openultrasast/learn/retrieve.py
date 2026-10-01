"""Retrieval from the local memory, and the evaluation boundary (learned-decision-engine design 4.2, Req 3.2, 3.4).

No model. Stage 1 ranks the eligible examples by a **Gower distance** over the allow-listed features of the active
profile, computed per instrument block so that missing is explicit, never imputed:

- both blocks ``ran``: the mean over the block's features of ``|a - b| / cap`` (ints), ``|a - b|`` (fractions;
  the one unbounded mean, ``verify.turns_mean``, over a cap of 10), ``0``/``1`` for bools and enums; ``null`` in
  both is ``0``, in one is ``1``;
- different states (``ran`` vs ``none``/``failed``/``not_applicable``, or ``failed`` vs ``none``): ``1``; the
  same non-``ran`` state: ``0``;
- ``D`` is the uniform mean over the profile's blocks; prior features are dropped with ``priors = "off"``, and the blocks
  of instruments the input profile withholds (``inputs``, default ``v1``: the engine) are left out entirely.

Ties break by ``sha256(example id + seed)``; the first ``n1 = 40`` go to stage 2, a cosine re-rank of the code
embeddings, ``r = lam (1 - D) + (1 - lam) cos``. Without the target's vector the whole retrieval is
``signals_only``; an example without a vector scores ``cos = 1 - D`` (its signal similarity, so it keeps its
stage-1 standing). The **balance rule** then takes ``k_ret = 6``: at most ``k/2`` per label, at most 2 per
repository group, at most 2 from other families while the candidate's family has examples left; ``short`` when
the pool cannot fill it.

**The boundary.** :func:`eligible` is the only way an example enters a prompt -- retrieved examples and compiled
demonstrations alike: not the target's group, not a group the fold evaluates, not the held-out source, not the
held-out framework, and (outside deployment) not a near-duplicate of the target (cosine >= 0.98). The program
repeats the check on the ids it actually rendered (:func:`assert_boundary`).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .embeddings import cosine
from .examples import Example
from .folds import Fold
from .labels import repo_name
from .schema import DEFAULT_INPUTS, UNBOUNDED_FLOATS, FeatureSpec, features_for, instruments_for, withheld

N1 = 40
K_RET = 6
LAM = 0.5
NEAR_DUPLICATE_COS = 0.98
UNBOUNDED_CAP = 10.0
PER_GROUP = 2


class BoundaryViolation(AssertionError):
    """An example or demonstration outside the evaluation boundary reached a prompt."""


@dataclass(frozen=True)
class Target:
    """What retrieval knows of a candidate: its group (for the boundary), family, record and excerpt vector."""

    group: str
    family: str
    profile: str
    x: Mapping[str, Any]
    instruments: Mapping[str, Mapping[str, Any]]
    vector: Sequence[float] | None = None

    @classmethod
    def of(cls, example: Example, vector: Sequence[float] | None = None) -> Target:
        return cls(example.group, example.family, example.profile, example.x, example.instruments, vector)


def _blocks(profile: str, priors: str) -> list[tuple[str, list[FeatureSpec]]]:
    specs = [s for s in features_for(profile) if not (s.prior and priors == "off")]
    blocks = [(name, [s for s in specs if s.instrument == name]) for name in instruments_for(profile)]
    return [(name, block) for name, block in blocks if block]


def _feature_distance(spec: FeatureSpec, a: Any, b: Any) -> float:
    if a is None and b is None:
        return 0.0
    if a is None or b is None:
        return 1.0
    if spec.type == "int":
        return min(1.0, abs(int(a) - int(b)) / float(spec.cap or 1))
    if spec.type == "float":
        cap = UNBOUNDED_CAP if spec.name in UNBOUNDED_FLOATS else 1.0
        return min(1.0, abs(float(a) - float(b)) / cap)
    return 0.0 if a == b else 1.0


def gower(
    a_x: Mapping[str, Any],
    a_instruments: Mapping[str, Mapping[str, Any]],
    b_x: Mapping[str, Any],
    b_instruments: Mapping[str, Mapping[str, Any]],
    profile: str,
    *,
    priors: str = "off",
    inputs: str = DEFAULT_INPUTS,
) -> float:
    """The per-instrument Gower distance of two records of ``profile`` (module docstring), in [0, 1]. The blocks of
    instruments the input profile withholds (v1: the engine) are not compared, so neighbours cannot carry them."""
    hidden = withheld(inputs)
    total, blocks = 0.0, [(name, specs) for name, specs in _blocks(profile, priors) if name not in hidden]
    for name, specs in blocks:
        sa, sb = a_instruments.get(name, {}).get("state", "none"), b_instruments.get(name, {}).get("state", "none")
        if sa != sb:
            total += 1.0
        elif sa == "ran":
            total += sum(_feature_distance(s, a_x.get(s.name), b_x.get(s.name)) for s in specs) / len(specs)
    return total / len(blocks) if blocks else 0.0


def ineligible(example: Example, target: Target, fold: Fold, *, cos: float | None = None) -> str | None:
    """Why ``example`` may not enter ``target``'s prompt under ``fold``, or ``None`` when it may."""
    if example.group and example.group == target.group:
        return "target group"
    if example.group in fold.eval_groups:
        return "evaluated group"
    if fold.held_source is not None and example.source == fold.held_source:
        return "held-out source"
    if fold.held_framework is not None and fold.held_framework in example.frameworks:
        return "held-out framework"
    if fold.phase != "deployment" and cos is not None and cos >= NEAR_DUPLICATE_COS:
        return "near duplicate"
    return None


def eligible(example: Example, target: Target, fold: Fold, *, cos: float | None = None) -> bool:
    return ineligible(example, target, fold, cos=cos) is None


@dataclass(frozen=True)
class Retrieval:
    examples: tuple[Example, ...]
    mode: str  # signals+embeddings | signals_only
    balance: str  # ok | short
    near_duplicates: int
    pool: int  # eligible examples before stage 1
    without_vector: int

    @property
    def neighbours(self) -> dict[str, dict[str, int]]:
        """Counts by label and family (never identities), for the decision row."""
        labels: dict[str, int] = {}
        families: dict[str, int] = {}
        for example in self.examples:
            labels[str(example.label)] = labels.get(str(example.label), 0) + 1
            families[example.family] = families.get(example.family, 0) + 1
        return {"label": dict(sorted(labels.items())), "family": dict(sorted(families.items()))}


def _tie(example_id: str, seed: int) -> str:
    return hashlib.sha256(f"{example_id}{seed}".encode()).hexdigest()


def balance(ranked: Sequence[Example], family: str, k: int = K_RET) -> tuple[list[Example], str]:
    """Take up to ``k`` in rank order: <= k/2 per label, <= 2 per group, <= 2 other families while the target's family
    has examples left; then, if short, fill from other families under the label and group caps."""
    per_label, other_cap = k // 2, min(2, k)
    taken: list[Example] = []
    labels: dict[int, int] = {}
    groups: dict[str, int] = {}

    def fits(example: Example) -> bool:
        return labels.get(example.label, 0) < per_label and groups.get(example.group, 0) < PER_GROUP

    def take(example: Example) -> None:
        taken.append(example)
        labels[example.label] = labels.get(example.label, 0) + 1
        groups[example.group] = groups.get(example.group, 0) + 1

    others = 0
    for example in ranked:
        if len(taken) == k:
            break
        if example.family != family and others >= other_cap:
            continue
        if fits(example):
            others += example.family != family
            take(example)
    for example in ranked:
        if len(taken) == k:
            break
        if example.id not in {e.id for e in taken} and fits(example):
            take(example)
    pool_labels = {e.label for e in ranked}
    short = len(taken) < k or any(labels.get(lab, 0) < min(2, per_label) for lab in (0, 1) if lab in pool_labels)
    return taken, "short" if short else "ok"


def retrieve(
    target: Target,
    pool: Iterable[Example],
    fold: Fold,
    *,
    vectors: Mapping[str, Sequence[float]] | None = None,
    n1: int = N1,
    k: int = K_RET,
    lam: float = LAM,
    seed: int = 0,
    priors: str = "off",
    inputs: str = DEFAULT_INPUTS,
) -> Retrieval:
    """The ``k`` balanced examples for ``target`` from the eligible part of ``pool`` (module docstring)."""
    candidates = [e for e in pool if e.profile == target.profile and eligible(e, target, fold)]
    scored = sorted(
        ((gower(target.x, target.instruments, e.x, e.instruments, target.profile, priors=priors, inputs=inputs), e) for e in candidates),
        key=lambda pair: (pair[0], _tie(pair[1].id, seed)),
    )[:n1]
    mode = "signals+embeddings" if target.vector is not None and vectors else "signals_only"
    near = without = 0
    reranked: list[tuple[float, str, Example]] = []
    for distance, example in scored:
        similarity = 1.0 - distance
        vector = (vectors or {}).get(example.excerpt_sha) if mode != "signals_only" else None
        if mode != "signals_only" and target.vector is not None and vector is not None:
            cos = cosine(target.vector, vector)
            if not eligible(example, target, fold, cos=cos):
                near += 1
                continue
            score = lam * similarity + (1 - lam) * cos
        else:
            without += mode != "signals_only"
            score = similarity
        reranked.append((-score, _tie(example.id, seed), example))
    ranked = [example for _, _, example in sorted(reranked, key=lambda t: (t[0], t[1]))]
    chosen, state = balance(ranked, target.family, k)
    return Retrieval(tuple(chosen), mode, state, near, len(candidates), without)


def assert_boundary(
    ids: Iterable[str], examples: Mapping[str, Example], target: Target, fold: Fold, *, vectors: Mapping[str, Sequence[float]] | None = None
) -> None:
    """Raise :class:`BoundaryViolation` when any rendered id is unknown or ineligible for ``target`` under ``fold``."""
    for example_id in ids:
        example = examples.get(example_id)
        if example is None:
            raise BoundaryViolation(f"rendered example {example_id[:12]} is not in the memory snapshot")
        vector = (vectors or {}).get(example.excerpt_sha)
        cos = cosine(target.vector, vector) if target.vector is not None and vector is not None else None
        why = ineligible(example, target, fold, cos=cos)
        if why is not None:
            raise BoundaryViolation(f"rendered example {example_id[:12]} is outside the boundary of {fold.name}: {why}")


def demonstrations_for(
    demos: Sequence[Mapping[str, Any]], examples: Mapping[str, Example], target: Target, fold: Fold
) -> list[Mapping[str, Any]]:
    """The compiled demonstrations usable for ``target``: an ineligible one is swapped for its alternate when that
    is eligible, and dropped otherwise (leave-one-framework-out on a demonstration's framework)."""
    out: list[Mapping[str, Any]] = []
    for demo in demos:
        example = examples.get(str(demo["example_id"]))
        if example is not None and eligible(example, target, fold):
            out.append(demo)
            continue
        alternate = demo.get("alternate")
        alt = examples.get(str(alternate.get("example_id"))) if isinstance(alternate, Mapping) else None
        if isinstance(alternate, Mapping) and alt is not None and eligible(alt, target, fold):
            out.append(alternate)
    return out


def deployment_fold(repository: str, groups: Iterable[str]) -> tuple[Fold, str | None]:
    """The boundary of a deployed scan: a repository that is a corpus group excludes its own cases."""
    name = repo_name(repository) if repository else ""
    if name and name in set(groups):
        return Fold(
            "deployment", "deployment", frozenset({name}), phase="deployment"
        ), "repository is in the corpus: its own cases excluded"
    return Fold("deployment", "deployment", frozenset(), phase="deployment"), None


def seed_memory(examples: Iterable[Example], case_group: str, fold: Fold | None = None) -> list[Example]:
    """The examples a plane Run case may be seeded with: none of its own group (nor of the fold's evaluated groups,
    held source or framework). The host filters; the sandbox never sees the rest."""
    target = Target(case_group, "", "", {}, {})
    boundary = fold or Fold("deployment", "seed", frozenset(), phase="deployment")
    return [e for e in examples if e.group != case_group and eligible(e, target, boundary)]


__all__ = [
    "K_RET", "LAM", "N1", "NEAR_DUPLICATE_COS", "BoundaryViolation", "Retrieval", "Target", "assert_boundary", "balance",
    "demonstrations_for", "deployment_fold", "eligible", "gower", "ineligible", "retrieve", "seed_memory",
]  # fmt: skip
