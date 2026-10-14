"""Report model coverage for the scanned regions."""

from __future__ import annotations

from collections.abc import Sequence

__all__ = []


def coverage_rows(regions: Sequence[object]) -> list[dict[str, object]]:
    """What each family actually modelled for the languages scanned, and what it cannot decide (Req 5.6).

    Derived, not asserted: the count is the size of the fact table the arbiter used, so it cannot drift from
    what the engine really looked for. The `limits` string is authored, reviewed and committed in
    `families.toml`, because "cannot decide an overflow expressed as an index" is a statement about an
    abstraction and no table can produce it.

    Reported for every family that was OFFERED to a region, not only those that produced findings -- a family
    that ran and found nothing is exactly the case a reader is most likely to misread, and the one Req 5.6
    exists for.
    """
    from .specs import config_specs, dominance_specs, taint_specs
    from .taxonomy import load_families

    taxonomy = load_families()
    limits = {family.id: family.limits for family in taxonomy.families}
    described = {family.id: family.description for family in taxonomy.families}

    offered: dict[tuple[str, str], int] = {}
    for region in regions:
        language = str(getattr(region, "language", ""))
        for family in getattr(region, "families", ()):
            offered.setdefault((language, str(family)), 0)
            offered[(language, str(family))] += 1

    rows: list[dict[str, object]] = []
    for (language, family), region_count in sorted(offered.items()):
        modelled = _modelled_count(language, family, taint_specs, dominance_specs, config_specs)
        rows.append(
            {
                "language": language,
                "family": family,
                "regions": region_count,
                "modelled": modelled,
                "description": described.get(family, ""),
                "limits": limits.get(family, ""),
            }
        )
    return rows


def _modelled_count(language: str, family: str, taint_specs, dominance_specs, config_specs) -> int:  # type: ignore[no-untyped-def]
    """How many operations the arbiter for this family can even see in this language."""
    spec = taint_specs(language=language).get(family)
    if spec is not None:
        return len(spec.sinks)
    spec = dominance_specs(language=language).get(family)
    if spec is not None:
        return len(spec.operations)
    spec = config_specs(language=language).get(family)
    if spec is not None:
        return len(spec.settings)
    return 0
