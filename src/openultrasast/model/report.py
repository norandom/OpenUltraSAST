"""Reporting that cannot flatter itself (model-grounded-detection, Req 9.3, 11.1).

Three disciplines survive from the deleted publish/scoring layer, and each is here because its absence caused
a real error in this project's history rather than because it is tidy:

* **Per-slice rows, always.** A headline over mixed slices once hid that agent-written code scored 44.4%
  while the hand-written development slice scored 83.3%. `render` refuses to produce anything without rows.
* **The overfitting gap beside the headline.** The distance between the development slice and the deciding
  real-world one is stated, never left for the reader to compute. When a slice is missing the gap is
  *absent*, not zero — reading a missing measurement as "no overfitting" is the flattering failure.
* **The rung on every finding.** A finding's strength is what established it; omitting the rung invites a
  reader to treat a suspicion as a result.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..findings import StaticFinding


@dataclass(frozen=True)
class SliceRow:
    """One slice's coverage. `covered` is pairs the model *split*, not pairs it flagged."""

    slice: str
    pairs: int
    covered: int

    @property
    def rate(self) -> float:
        return self.covered / self.pairs if self.pairs else 0.0


def overfitting_gap(rows: Sequence[SliceRow], *, development: str = "", deciding: str = "") -> float | None:
    """Development-slice coverage minus the deciding slice's, or ``None`` when either is absent.

    ``None`` rather than ``0.0`` on purpose: a slice that was never measured must not read as agreement
    between them.
    """
    by_name = {row.slice: row for row in rows}
    if development not in by_name or deciding not in by_name:
        return None
    return by_name[development].rate - by_name[deciding].rate


def render(rows: Sequence[SliceRow], *, development: str = "", deciding: str = "") -> str:
    """The report. Raises when there are no per-slice rows, because a bare aggregate is the thing to prevent."""
    if not rows:
        raise ValueError("a report needs per-slice rows: there is no headline without them")

    lines = ["## Model coverage", "", "| slice | pairs | covered | coverage |", "|---|---|---|---|"]
    for row in sorted(rows, key=lambda r: r.slice):
        lines.append(f"| {row.slice} | {row.pairs} | {row.covered} | {row.rate:.0%} |")

    total_pairs = sum(row.pairs for row in rows)
    total_covered = sum(row.covered for row in rows)
    lines += ["", f"Across every slice: {total_covered}/{total_pairs} = {total_covered / total_pairs:.0%} "
                  "— read the rows above it, not this line."]

    gap = overfitting_gap(rows, development=development, deciding=deciding)
    if gap is not None:
        lines += [
            "",
            f"**Overfitting gap: {gap:+.0%}** — `{development}` (development) minus `{deciding}`, "
            f"which is the deciding real-world slice.",
        ]
    elif development or deciding:
        lines += ["", f"**Overfitting gap: not measurable** — `{development}` or `{deciding}` is absent from this run."]
    return "\n".join(lines) + "\n"


def render_findings(findings: Sequence[StaticFinding]) -> str:
    """Findings with the rung that established each one (Req 5.3)."""
    lines = ["## Findings", "", "| finding | location | rung | severity |", "|---|---|---|---|"]
    for finding in findings:
        where = f"{finding.path}:{finding.line}" if finding.line else finding.path
        lines.append(f"| {finding.title} | {where} | `{finding.rung}` | {finding.severity} |")
    return "\n".join(lines) + "\n"


__all__ = ["SliceRow", "overfitting_gap", "render", "render_findings"]
