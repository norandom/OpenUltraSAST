"""What may raise a claim above suspicion, keyed by family (learning-harness, Req 7.1, 7.3, 7.4).

A detector's claim is a suspicion until something other than the model agrees with it. What counts as
agreement depends on the family: a canary oracle observed in the sandbox, corroboration from a static
checker, or nothing at all. A family whose verifier does not exist yet reports at suspicion rather than
pretending, and that is the honest default rather than a gap.

The canary oracle is a function over a sandbox result, so the sandbox keeps deciding what happened and
this module only says what would count. Exit codes are not oracles: a crash and a demonstrated
injection are different evidence, and one family's oracle must not silently answer for another.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, Protocol

from ..findings import StaticFinding
from ..sandbox import SandboxResult
from .families import Family

Rung = Literal["suspicion", "static_corroboration", "proven"]
VerifierKind = Literal["canary", "static", "none"]


@dataclass(frozen=True)
class Verification:
    """What a verifier saw, and how high it lets the claim go."""

    rung: Rung
    reason: str
    oracle_output: str = ""


class Verifier(Protocol):
    @property
    def kind(self) -> VerifierKind: ...

    def verify(self, claim: StaticFinding, *, root: Path, language: str) -> Verification: ...


def token_oracle(token: str) -> Callable[[SandboxResult], bool]:
    """The oracle a canary snippet is written against: the token appears only if the vulnerability fired."""

    def fired(result: SandboxResult) -> bool:
        return token in result.stdout or token in result.stderr

    return fired


@dataclass(frozen=True)
class NoVerifier:
    """Nothing can confirm this family yet, so the claim stays where the detector left it."""

    kind: VerifierKind = "none"

    def verify(self, claim: StaticFinding, *, root: Path, language: str) -> Verification:
        del claim, root, language
        return Verification(rung="suspicion", reason="no_verifier")


@dataclass(frozen=True)
class StaticVerifier:
    """Another checker looked at the same function and agrees the obligation is undischarged."""

    kind: VerifierKind = "static"

    def verify(self, claim: StaticFinding, *, root: Path, language: str) -> Verification:
        del language
        from ..hunter_tools import PathEscapesRepo, obligations

        if not claim.function_name:
            return Verification(rung="suspicion", reason="no_function")
        try:
            rows = obligations(root, path=claim.path, function=claim.function_name)
        except (PathEscapesRepo, OSError):
            return Verification(rung="suspicion", reason="checker_unavailable")
        if not rows:
            return Verification(rung="suspicion", reason="checker_disagrees")
        summary = "; ".join(f"{row.get('operation')} missing {row.get('missing')}" for row in rows)
        return Verification(rung="static_corroboration", reason="checker_agrees", oracle_output=summary)


def verifier_for(family: Family, *, canary: Verifier | None = None) -> Verifier:
    """The verifier a family declares. A canary family with no implementation registered stays at suspicion."""
    if family.verifier == "static":
        return StaticVerifier()
    if family.verifier == "canary":
        return canary if canary is not None else NoVerifier(kind="canary")
    return NoVerifier()


def apply_verification(claim: StaticFinding, verification: Verification) -> StaticFinding:
    """A copy of the claim carrying what the verifier said. The original is never mutated."""
    tags = [tag for tag in claim.tags if not tag.startswith("verifier:")] + [f"verifier:{verification.rung}"]
    return replace(claim, tags=tags, evidence_level=verification.rung)


__all__ = [
    "NoVerifier",
    "Rung",
    "StaticVerifier",
    "Verification",
    "Verifier",
    "VerifierKind",
    "apply_verification",
    "token_oracle",
    "verifier_for",
]
