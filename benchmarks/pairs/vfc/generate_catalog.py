#!/usr/bin/env python3
"""Thin shim: ``python benchmarks/pairs/catalog_gen.py --slice vfc``."""

from __future__ import annotations

import runpy
from pathlib import Path

_LIB = Path(__file__).resolve().parents[1] / "catalog_gen.py"


def main() -> int:
    return int(runpy.run_path(str(_LIB), run_name="catalog_gen_lib")["main"](["--slice", "vfc"]))


if __name__ == "__main__":
    raise SystemExit(main())
