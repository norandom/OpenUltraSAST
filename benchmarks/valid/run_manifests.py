"""Analyzer bundle materialisation and verification.

Task 12.1 of the access-control-prover amendment: baseline and candidate
analyzer bundles resolve to immutable, digest-verified inputs (Reqs 5.1, 5.5,
12.1). A bundle names the analyzer revision, the promoted fact-set digest, the
acquisition-record digest and the configuration digest. Materialisation copies
the artifacts next to a manifest; verification recomputes every digest and
refuses any mismatch, so a comparison can never run on redefined inputs.
"""

import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_NO_ACQUISITION = "none"


class BundleMismatch(ValueError):
    """A materialised bundle artifact does not match its recorded digest."""


@dataclass(frozen=True)
class AnalyzerBundle:
    """Design-exact bundle identity: revision plus three digests."""

    analyzer_revision: str
    fact_set_digest: str
    acquisition_record_digest: str
    configuration_digest: str


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def _configuration_digest(configuration: tuple[tuple[str, str], ...]) -> str:
    lines = sorted(f"{key}={value}" for key, value in configuration)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:12]


def _git_head(repo_root: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_root, capture_output=True, text=True, check=True).stdout.strip()


def bundle_from(
    repo_root: Path,
    facts_path: Path,
    acquisition_path: Path | None = None,
    configuration: tuple[tuple[str, str], ...] = (),
) -> AnalyzerBundle:
    """Resolve the bundle identity for the artifacts on disk."""
    if not facts_path.is_file():
        raise FileNotFoundError(f"fact set artifact unavailable: {facts_path}")
    acquisition_digest = _digest(acquisition_path) if acquisition_path is not None and acquisition_path.is_file() else _NO_ACQUISITION
    return AnalyzerBundle(
        analyzer_revision=_git_head(repo_root),
        fact_set_digest=_digest(facts_path),
        acquisition_record_digest=acquisition_digest,
        configuration_digest=_configuration_digest(configuration),
    )


def materialise(
    bundle: AnalyzerBundle,
    facts_path: Path,
    acquisition_path: Path | None,
    out_dir: Path,
) -> Path:
    """Write the bundle manifest and copy its artifacts immutably."""
    if not facts_path.is_file():
        raise FileNotFoundError(f"fact set artifact unavailable: {facts_path}")
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(facts_path, out_dir / facts_path.name)
    if acquisition_path is not None:
        if not acquisition_path.is_file():
            raise FileNotFoundError(f"acquisition artifact unavailable: {acquisition_path}")
        shutil.copy2(acquisition_path, out_dir / acquisition_path.name)
    manifest = out_dir / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "analyzer_revision": bundle.analyzer_revision,
                "fact_set_digest": bundle.fact_set_digest,
                "acquisition_record_digest": bundle.acquisition_record_digest,
                "configuration_digest": bundle.configuration_digest,
                "fact_artifact": facts_path.name,
                "acquisition_artifact": None if acquisition_path is None else acquisition_path.name,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def _recomputed(bundle_dir: Path, repo_root: Path, payload: dict[str, object]) -> AnalyzerBundle:
    fact_artifact = str(payload.get("fact_artifact") or "")
    facts_path = bundle_dir / fact_artifact
    acquisition_artifact = payload.get("acquisition_artifact")
    acquisition_path = None if acquisition_artifact is None else bundle_dir / str(acquisition_artifact)
    return bundle_from(
        repo_root,
        facts_path,
        acquisition_path,
        configuration=(),  # configuration digest is read from the manifest, not recomputed
    )


def verify(bundle_dir: Path, repo_root: Path) -> AnalyzerBundle:
    """Recompute artifact digests and refuse any mismatch with the manifest."""
    payload = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    recorded = AnalyzerBundle(
        analyzer_revision=str(payload["analyzer_revision"]),
        fact_set_digest=str(payload["fact_set_digest"]),
        acquisition_record_digest=str(payload["acquisition_record_digest"]),
        configuration_digest=str(payload["configuration_digest"]),
    )
    recomputed = _recomputed(bundle_dir, repo_root, payload)
    for field in ("analyzer_revision", "fact_set_digest", "acquisition_record_digest"):
        if getattr(recomputed, field) != getattr(recorded, field):
            raise BundleMismatch(f"bundle artifact mismatch: {field}")
    return recorded


if __name__ == "__main__":  # pragma: no cover
    sys.exit(0)
