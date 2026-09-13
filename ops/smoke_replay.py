"""Real production replay on a controlled PHP security change and its fixed twin."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from openultrasast.config import PushConfig
from openultrasast.push.runner import replay


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("security", "fixed"), required=True)
    parser.add_argument("--deadline", type=float, default=900)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ousast-replay-smoke-") as temporary:
        root = Path(temporary) / "repo"
        root.mkdir()

        def git(*parts: str) -> str:
            return subprocess.run(["git", "-C", str(root), *parts], check=True, capture_output=True, timeout=10).stdout.decode().strip()

        git("init")
        git("config", "user.name", "Replay smoke")
        git("config", "user.email", "replay@example.invalid")
        git("config", "core.hooksPath", os.devnull)
        source = root / "api.php"
        before = '<?php\nfunction handler() {\n  $value = "fixed";\n  eval($value);\n}\nhandler();\n'
        after = before.replace('$value = "fixed";', '$value = $_GET["value"];')
        source.write_text(before)
        git("add", "api.php")
        git("commit", "-m", "fixed")
        fixed = git("rev-parse", "HEAD")
        source.write_text(after)
        git("add", "api.php")
        git("commit", "-m", "security")
        security = git("rev-parse", "HEAD")
        base, head = (fixed, security) if args.case == "security" else (security, fixed)
        # Verify readable immutable source before trusting any reported zeros.
        readable = git("show", head + ":api.php")
        assert len(readable.encode()) > 0
        source.write_text("dirty live content")
        index = (root / ".git/index").read_bytes()
        status = git("status", "--porcelain")
        artifact = Path(temporary) / "replay.json"
        start = time.monotonic()
        delivery = replay(root, base=base, head=head, artifact=artifact, config=PushConfig(deadline_seconds=args.deadline))
        payload = json.loads(artifact.read_text()) if artifact.exists() else None
        print(
            json.dumps(
                {
                    "case": args.case,
                    "source_bytes": len(readable.encode()),
                    "elapsed_seconds": time.monotonic() - start,
                    "exit_code": delivery.exit_code,
                    "report_error": delivery.error,
                    "reporting_seconds": delivery.reporting_seconds,
                    "text": delivery.text,
                    "artifact": payload,
                },
                indent=2,
            ),
            flush=True,
        )
        assert source.read_text() == "dirty live content"
        assert (root / ".git/index").read_bytes() == index
        assert git("status", "--porcelain") == status
        assert payload and payload["scans"], "production runner produced no scan evidence"
        assert delivery.result.finding_status == "none" and delivery.exit_code == 0
        if args.deadline >= 900:
            head_scan = next(r["scan"] for r in payload["scans"] if r["side"] == "head")
            assert head_scan["scope"]["ranking_mode"] == "evidence"
            if args.case == "security":
                assert any(d["candidate"]["delta"]["novelty"] in ("new", "worsened") for d in payload["admission"]["dispositions"]), (
                    "supported security control missing: inspect upstream evidence before claiming replay complete"
                )
            else:
                assert not head_scan["findings"], "fixed twin retained a modeled finding"
        print(json.dumps({"verified": True, "case": args.case}), flush=True)


if __name__ == "__main__":
    main()
