"""Temporary explicit import shim for the pre-v2 trace contract."""

from openultrasast.core.legacy_v1.contracts import Guard, Hop, TraceRecord, Witness

__all__ = ["Guard", "Hop", "TraceRecord", "Witness"]
