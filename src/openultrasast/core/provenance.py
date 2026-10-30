"""Provenance digest stamping for the detection core (Req 6).

Every analysis is stamped with the analyzer revision, fact-set, acquisition-record,
configuration, population, and per-change input digests. A result whose digests
cannot be re-derived from the named inputs is refused, never accepted.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


class ProvenanceMismatch(ValueError):
    """A recorded digest does not match the re-derived input identity."""


_DIGEST_FIELDS = (
    "analyzer_revision",
    "fact_set_digest",
    "acquisition_record_digest",
    "configuration_digest",
    "population_digest",
    "input_digest",
)


def _input_digest(change_id: str, population_digest: str) -> str:
    payload = json.dumps([population_digest, change_id], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:12]


def stamp(
    *,
    analyzer_revision: str,
    fact_set_digest: str,
    acquisition_record_digest: str,
    configuration_digest: str,
    population_digest: str,
    change_id: str,
) -> dict[str, str]:
    """The provenance stamp of one analysis (Req 6.1)."""
    return {
        "analyzer_revision": analyzer_revision,
        "fact_set_digest": fact_set_digest,
        "acquisition_record_digest": acquisition_record_digest,
        "configuration_digest": configuration_digest,
        "population_digest": population_digest,
        "input_digest": _input_digest(change_id, population_digest),
    }


def verify_stamp(recorded: Mapping[str, Any], rederived: Mapping[str, Any]) -> None:
    """Refuse when any digest cannot be re-derived (Req 6.2)."""
    for field_name in _DIGEST_FIELDS:
        if recorded.get(field_name) != rederived.get(field_name):
            raise ProvenanceMismatch(f"{field_name}: recorded {recorded.get(field_name)!r} != rederived {rederived.get(field_name)!r}")


__all__ = ["ProvenanceMismatch", "stamp", "verify_stamp"]
