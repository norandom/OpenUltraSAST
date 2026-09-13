"""Transparent engine-process timing around the production CLI (evaluation only)."""

import json
import os
import sys
import time
from pathlib import Path

from openultrasast.cli import main
from openultrasast.cpg.backend import JoernBackend

original = JoernBackend._run_bounded
trace = Path(os.environ["OUSAST_EVALUATION_TRACE"])


def measured(self, command, **kwargs):
    executable = Path(command[0]).name
    scripts = [Path(arg).name for arg in command if arg.endswith(".sc")]
    stage = (
        "overlay"
        if "overlay.sc" in scripts
        else "census"
        if "census.sc" in scripts
        else "query"
        if scripts
        else "frontend"
        if "cpg" in executable or "joern-parse" in executable
        else "input_probe"
    )
    started = time.monotonic()
    result = None
    try:
        result = original(self, command, **kwargs)
        return result
    finally:
        with trace.open("a") as stream:
            stream.write(
                json.dumps(
                    {
                        "stage": stage,
                        "seconds": time.monotonic() - started,
                        "exit_code": result.returncode if result is not None else None,
                        "receipt": result is not None,
                        "executable": executable,
                        "scripts": scripts,
                    }
                )
                + "\n"
            )


JoernBackend._run_bounded = measured
raise SystemExit(main(sys.argv[1:]))
