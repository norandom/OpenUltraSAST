#!/usr/bin/env python3
"""Thin shim: the shared harvest library lives in ``benchmarks/pairs/harvest.py``.

Kept so existing maintainer commands and tests keep working:
``python benchmarks/pairs/vfc/harvest.py --name openssl-cve-2014-0160``.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

_LIB = Path(__file__).resolve().parents[1] / "harvest.py"
_NS = runpy.run_path(str(_LIB), run_name="pair_harvest_lib")
globals().update({key: value for key, value in _NS.items() if not key.startswith("__") and key != "main"})


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--slice" not in args:
        args = ["--slice", "vfc", *args]
    return int(_NS["main"](args))


if __name__ == "__main__":
    raise SystemExit(main())
