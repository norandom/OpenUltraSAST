#!/usr/bin/env python3
"""Stage an installer checkout with lean kind manifests; never modify the source checkout.

Usage: python ops/ax/prepare-substrate.py SOURCE EMPTY_DESTINATION
The destination lives only for an install/render. Source/build inputs are symlinked;
manifests are copied because the installer uses fixed paths (including the OTEL ConfigMap).
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import yaml


def prepare(source: Path, destination: Path) -> None:
    source = source.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError(f"staging directory must be empty: {destination}")
    for entry in source.iterdir():
        if entry.name != "manifests":
            (destination / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
    shutil.copytree(source / "manifests", destination / "manifests")
    install = destination / "manifests/ate-install"
    shutil.copytree(install / "kind", install / "kind-upstream")
    overlay = Path(__file__).resolve().parent / "substrate-kind-lean"
    shutil.copytree(overlay, install / "kind", dirs_exist_ok=True)
    # The installer applies this file directly before it renders the bundle.
    # Keep the strategic-merge directive only in the overlay's patch file.
    config = yaml.safe_load((overlay / "ate-otel-config.yaml").read_text())
    config["data"].pop("$patch")
    (install / "kind/disabled-otel-config.yaml").write_text(yaml.safe_dump(config))
    (install / "kind/ate-otel-config.yaml").rename(install / "kind/otel-config-patch.yaml")
    (install / "kind/disabled-otel-config.yaml").rename(install / "kind/ate-otel-config.yaml")
    kustomization = install / "kind/kustomization.yaml"
    kustomization.write_text(kustomization.read_text().replace("path: ate-otel-config.yaml", "path: otel-config-patch.yaml"))


if __name__ == "__main__":
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
