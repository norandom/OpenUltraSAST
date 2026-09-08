"""Propose/adjudicate/prove overlay: regex proposes, semantics adjudicates."""

from .engines import joern_available, tree_sitter_available
from .extra import grammar_for, has_semantic_extra
from .facts import FactLoadError, SemanticFacts, load_facts
from .overlay import OverlayError, OverlayRecord, adjudicate, finding_from_coverage, write_overlay
from .prove_filter import filter_promoted_hotspots

__all__ = [
    "FactLoadError",
    "OverlayError",
    "OverlayRecord",
    "SemanticFacts",
    "adjudicate",
    "filter_promoted_hotspots",
    "finding_from_coverage",
    "grammar_for",
    "has_semantic_extra",
    "joern_available",
    "load_facts",
    "tree_sitter_available",
    "write_overlay",
]
