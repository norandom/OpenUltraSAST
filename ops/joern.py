"""pyinfra deploy for the Joern CPG engine (model-grounded-detection, Req 4).

Replaces the ad-hoc `curl | unzip` this engine was first installed with. Joern is the model layer's arbiter
substrate and the only thing standing between a `suspicion` and a `model_entailed`, so how it reaches a
machine should be reproducible and stated rather than remembered.

Deliberately narrow:

* **It installs an engine, it does not become one.** No sandbox, no container, no service.
  ``openultrasast.cpg.backend`` reaches Joern by subprocess and nothing here changes that.
* **The checksum is verified, in a shell step rather than by ``files.download``.** Upstream publishes a
  ``.sha512`` beside the archive and pyinfra's download operation offers sha384/sha256/sha1/md5 but not
  sha512, so the verification is done with ``sha512sum -c`` against the published file. An unverified 1.8 GB
  download that then parses your source tree is not something to wave through.
* **Idempotent.** A version stamp short-circuits the download and extraction, so a re-run costs a file read.
* **Nothing the tool needs at runtime.** The core install stays ``dependencies = []``; without Joern the model
  layer degrades to ``suspicion`` with a recorded reason, which is a supported state rather than a broken one.

Usage:

    uv pip install pyinfra            # tooling only, never a project dependency
    pyinfra @local ops/joern.py       # this machine
    pyinfra inventory.py ops/joern.py # anywhere else
"""

from __future__ import annotations

from pyinfra import host
from pyinfra.operations import files, server

# Pinned. An engine that silently changes version changes every verdict it produces, and the ceiling
# artifacts under benchmarks/measurements are only comparable against a fixed one.
JOERN_VERSION = host.data.get("joern_version", "v4.0.623")
PREFIX = host.data.get("joern_prefix", "/opt/joern")
ARCHIVE = "joern-cli-linux-x86_64.zip"
BASE = f"https://github.com/joernio/joern/releases/download/{JOERN_VERSION}"
STAMP = f"{PREFIX}/.joern-version"

# Joern ships Scala but not a JVM. `php2cpg` additionally shells out to a real PHP interpreter (it drives
# PHP-Parser), so without `php` on PATH a PHP tree fails to build with an opaque "Process exited with code 1"
# -- measured on this machine before the package was added. `php_frontend` is opt-in because most targets do
# not need it and it pulls a second runtime.
PACKAGES = ["openjdk-21-jre-headless", "unzip"]
if host.data.get("php_frontend", False):
    PACKAGES.append("php-cli")

server.packages(
    name="Install a JVM, unzip, and (optionally) the PHP frontend's interpreter",
    packages=PACKAGES,
    present=True,
    _sudo=True,
)

files.directory(
    name=f"Create {PREFIX}",
    path=PREFIX,
    present=True,
    _sudo=True,
)

server.shell(
    name=f"Install Joern {JOERN_VERSION} (skipped when the stamp already matches)",
    commands=[
        # One guarded block: a matching stamp skips the download, the checksum and the extraction alike.
        f"""
        if [ -f {STAMP} ] && grep -qx {JOERN_VERSION} {STAMP}; then
            echo "joern {JOERN_VERSION} already installed"
        else
            set -e
            cd /tmp
            curl -fsSL -o {ARCHIVE} {BASE}/{ARCHIVE}
            curl -fsSL -o {ARCHIVE}.sha512 {BASE}/{ARCHIVE}.sha512
            # Verify before unpacking, never after: the archive is what we are choosing to trust.
            sha512sum -c {ARCHIVE}.sha512
            rm -rf {PREFIX}/joern-cli
            unzip -q -o {ARCHIVE} -d {PREFIX}
            echo {JOERN_VERSION} > {STAMP}
            # 1.8 GB in /tmp is how a disk fills up.
            rm -f {ARCHIVE} {ARCHIVE}.sha512
        fi
        """
    ],
    _sudo=True,
)

server.shell(
    name="Verify joern-parse runs",
    commands=[f"{PREFIX}/joern-cli/joern-parse --help > /dev/null"],
)
