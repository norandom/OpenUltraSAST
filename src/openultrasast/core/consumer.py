"""Temporary explicit import shim for the pre-v2 consumer contract."""

from openultrasast.core.legacy_v1.contracts import PushRequest, PushVerdict, consume_verdict

__all__ = ["PushRequest", "PushVerdict", "consume_verdict"]
