"""Temporary explicit import shim for the pre-v2 fact-pack contract."""

from openultrasast.core.legacy_v1.contracts import (
    FactPackError,
    LegacyFactPack,
    admit_fact_pack,
    admit_pack_file,
    load_pack_file,
    verify_fact_pack,
)

__all__ = [
    "FactPackError",
    "LegacyFactPack",
    "admit_fact_pack",
    "admit_pack_file",
    "load_pack_file",
    "verify_fact_pack",
]
