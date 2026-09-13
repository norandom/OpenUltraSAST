"""Recompute versioned eligibility from frozen results; default declarations are experimental."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from openultrasast.model.scan import ScanBudget
from openultrasast.push.eligibility import create_decision
from openultrasast.push.policy import CapabilityAdmission, CapabilityKey
from openultrasast.push.runner import _provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--declarations", type=Path)
    args = parser.parse_args()

    def read(name):
        return json.loads((args.evidence / name).read_bytes())

    profile, validation, run = read("profile.json"), read("input-validation.json"), read("run.json")
    current = _provenance(args.evidence, ScanBudget(max_model_calls=0, max_regions=500, order_by_evidence=True))
    if args.declarations:
        declarations = tuple(CapabilityAdmission.from_payload(d) for d in json.loads(args.declarations.read_bytes()))
    else:
        declarations = []
        for capability in sorted({c["capability"] for c in profile["cases"]}):
            language, framework, family = capability.split("/")
            key = CapabilityKey(
                language,
                "unspecified",
                framework,
                family,
                "dominance" if family == "access_control" else "taint",
                "unreviewed",
                current["semantics"],
            )
            declarations.append(
                CapabilityAdmission(
                    key,
                    "unqualified-population-v1",
                    str(args.evidence / "scorecard.json"),
                    "experimental",
                    "Unreviewed consequence for {operation} in {context}.",
                    "Unreviewed repair for {operation} in {context}.",
                )
            )
    decision = create_decision(
        profile, validation, run, current=current, runtime=json.loads(args.runtime.read_bytes()), declarations=declarations
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x") as stream:
        json.dump(decision, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(
        json.dumps(
            {
                "verdict": decision["verdict"],
                "enabled": sum(e["declaration"]["enabled"] for e in decision["entries"]),
                "artifact_sha256": decision["artifact_sha256"],
            }
        )
    )
    return 0 if decision["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
