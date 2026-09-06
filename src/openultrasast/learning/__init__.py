"""The learning harness: classified detectors improved one family at a time (learning-harness spec).

Layers left to right, and nothing imports rightward: ``families`` -> ``classify`` -> ``scoring`` ->
``split`` -> ``detectors`` and ``verifiers`` -> ``rounds`` -> ``publish``. ``pairs`` and ``benchmark``
never import this package; the corpus stores a family label as an opaque string and the classifier
validates it.
"""

from __future__ import annotations

from .families import FAMILY_IDS, VERIFIER_KINDS, FamiliesError, Family, FamilyTaxonomy, load_families

__all__ = ["FAMILY_IDS", "VERIFIER_KINDS", "FamiliesError", "Family", "FamilyTaxonomy", "load_families"]
