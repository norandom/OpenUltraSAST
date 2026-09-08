"""Is a CPG engine available? (Req 4.2, 4.3)

One probe, not two: ``semantic/engines.joern_available`` already answers this and already honours the
``OPENULTRASAST_JOERN_PROBE`` override that the test matrix uses to force the absent case. The model layer
reuses it rather than growing a second, subtly different notion of "installed".
"""

from __future__ import annotations

from ..semantic.engines import joern_available


def has_cpg() -> bool:
    """True when a CPG can be built. False means every verdict degrades to ``suspicion`` with a reason."""
    return joern_available()


__all__ = ["has_cpg"]
