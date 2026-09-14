"""Build the approved test-retention adaptation from checksum-pinned upstream sources.

Usage: python3 install.py /opt/joern-cli. Requires curl, unzip, Java 21 and Python3.
Only the two upstream input filters change. OUSAST_INCLUDE_TESTS=1 opts in;
unset/0 keeps upstream behavior. Sources, lockfile and build identity are retained.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

PINS = {
    "astgen.tar.gz": (
        "https://codeload.github.com/joernio/astgen-monorepo/tar.gz/refs/tags/javascript-astgen/v3.50.1",
        "8d9728dca8eab694a0f07bcd7a1c9a88368cb7bd354fc19c2ee8ca8611ff869a",
    ),
    "AstGenRunner.scala": (
        "https://raw.githubusercontent.com/joernio/joern/v4.0.625/joern-cli/frontends/jssrc2cpg/src/main/scala/io/joern/jssrc2cpg/utils/AstGenRunner.scala",
        "9963f949360d7e17baed1bd8875b717b2855745cf7260eef8a87d17533a54268",
    ),
    "bun.zip": (
        "https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-linux-x64.zip",
        "36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913",
    ),
}
JAR_SHA256 = "49fe488a79cc52b4e1d2e056143ec414f59e0007ed25f054c5fa7ae4aa34dff3"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(path: Path, before: str, after: str) -> None:
    source = path.read_text()
    if source.count(before) != 1:
        raise ValueError(f"Unexpected source shape: {path.name}")
    path.write_text(source.replace(before, after))


def build(root: Path) -> None:
    jar = root / "frontends/jssrc2cpg/lib/io.joern.jssrc2cpg-4.0.625.jar"
    installed = root / "ousast-frontend-retention-v1/manifest.json"
    if installed.is_file():
        previous = json.loads(installed.read_text())
        if (
            previous.get("builder_sha256") == digest(Path(__file__))
            and previous.get("adapted_jar_sha256") == digest(jar)
            and previous.get("astgen_sha256") == digest(root / "frontends/jssrc2cpg/bin/astgen/astgen-linux")
        ):
            print("Verified installed frontend-retention adaptation")
            return
    if digest(jar) != JAR_SHA256:
        raise ValueError("Expected pristine Joern 4.0.625 jssrc2cpg jar")
    with tempfile.TemporaryDirectory(prefix="ousast-frontend-build-") as temporary:
        work = Path(temporary)
        for name, (url, expected) in PINS.items():
            with urllib.request.urlopen(url) as response:
                (work / name).write_bytes(response.read())
            if digest(work / name) != expected:
                raise ValueError(f"Checksum mismatch: {name}")
        with tarfile.open(work / "astgen.tar.gz") as archive:
            archive.extractall(work, filter="data")
        with zipfile.ZipFile(work / "bun.zip") as archive:
            archive.extractall(work)
        bun = work / "bun-linux-x64/bun"
        bun.chmod(0o755)
        astgen = work / "astgen-monorepo-javascript-astgen-v3.50.1/javascript-astgen"
        file_utils = astgen / "src/FileUtils.ts"
        replace_once(
            file_utils,
            "const IGNORE_DIRS_SET = new Set(Defaults.IGNORE_DIRS.map((d) => d.toLowerCase()))",
            """const INCLUDE_TESTS = process.env.OUSAST_INCLUDE_TESTS === "1"
const TEST_DIRS = new Set(["test", "tests", "e2e", "e2e-beta", "cypress", "__tests__", "__mocks__"])
const IGNORE_DIRS_SET = new Set(Defaults.IGNORE_DIRS.filter(d => !INCLUDE_TESTS || !TEST_DIRS.has(d)).map(d => d.toLowerCase()))
const IGNORE_FILE_PATTERN = INCLUDE_TESTS
    ? new RegExp("(chunk-vendors|app~|conf|[.-]min|\\\\.d)\\\\.(js|jsx|cjs|mjs|xsjs|xsjslib|ts|tsx)$", "i")
    : Defaults.IGNORE_FILE_PATTERN""",
        )
        replace_once(
            file_utils,
            'dirName.startsWith("__") ||',
            '(dirName.startsWith("__") && !(INCLUDE_TESTS && TEST_DIRS.has(dirName.toLowerCase()))) ||',
        )
        replace_once(file_utils, "Defaults.IGNORE_FILE_PATTERN.test(fileName)", "IGNORE_FILE_PATTERN.test(fileName)")
        scala = work / "AstGenRunner.scala"
        replace_once(
            scala,
            "lazy val isIgnoredTest = IgnoredTestsRegex.exists(_.matches(filePath))",
            'lazy val isIgnoredTest = !sys.env.get("OUSAST_INCLUDE_TESTS").contains("1") && IgnoredTestsRegex.exists(_.matches(filePath))',
        )
        # Keep the original Gruntfile path and bytes. Other default filters remain intact.
        replace_once(
            scala,
            "lazy val isIgnored     = IgnoredFilesRegex.exists(_.matches(filePath))",
            "lazy val isIgnored = IgnoredFilesRegex.exists(_.matches(filePath)) && "
            '!(sys.env.get("OUSAST_INCLUDE_BUILD_CONFIGS").contains("1") && '
            'Paths.get(filePath).getFileName.toString == "Gruntfile.js")',
        )
        # Upstream stages embedded TS standard-library assets; retain that build recipe,
        # selecting just the supported Linux x64 target instead of all release platforms.
        script = astgen / "scripts/build-binaries.ts"
        source = script.read_text()
        start = source.index("const targets = [")
        end = source.index("] as const", start) + len("] as const")
        script.write_text(
            source[:start] + 'const targets = [{target: "bun-linux-x64", outfile: "./astgen-linux-x64"}] as const' + source[end:]
        )
        subprocess.run([str(bun), "install", "--frozen-lockfile"], cwd=astgen, check=True)
        subprocess.run([str(bun), "scripts/sync-version.ts"], cwd=astgen, check=True)
        subprocess.run([str(bun), "scripts/build-binaries.ts"], cwd=astgen, check=True)
        classes = work / "classes"
        classes.mkdir()
        jars = sorted(set(root.glob("lib/*.jar")) | set(root.glob("frontends/jssrc2cpg/lib/*.jar")))
        classpath = ":".join(map(str, jars))
        subprocess.run(
            ["java", "-cp", classpath, "dotty.tools.dotc.Main", "-classpath", classpath, "-d", str(classes), str(scala)], check=True
        )
        outputs = sorted(classes.rglob("*"))
        compiled = {path.relative_to(classes).as_posix(): path for path in outputs if path.is_file()}
        if not compiled or any(not name.startswith("io/joern/jssrc2cpg/utils/AstGenRunner") for name in compiled):
            raise ValueError("Compiler produced unexpected classes")
        adapted = work / "adapted.jar"
        with zipfile.ZipFile(jar) as original, zipfile.ZipFile(adapted, "w", zipfile.ZIP_DEFLATED) as destination:
            for entry in original.infolist():
                if entry.filename not in compiled:
                    destination.writestr(entry, original.read(entry.filename))
            for name, path in compiled.items():
                destination.write(path, name)
        provenance = root / "ousast-frontend-retention-v1"
        provenance.mkdir(exist_ok=True)
        for source_path in (file_utils, scala, script, astgen / "bun.lock"):
            shutil.copy2(source_path, provenance / source_path.name)
        binary = astgen / "astgen-linux-x64"
        manifest = {
            "revision": "ousast-frontend-retention-v1",
            "builder_sha256": digest(Path(__file__)),
            "policy": "OUSAST_INCLUDE_TESTS=1; OUSAST_INCLUDE_BUILD_CONFIGS=1 retains Gruntfile.js",
            "sources": PINS,
            "original_jar_sha256": JAR_SHA256,
            "adapted_jar_sha256": digest(adapted),
            "astgen_sha256": digest(binary),
            "compiled_entries": sorted(compiled),
        }
        shutil.copy2(binary, root / "frontends/jssrc2cpg/bin/astgen/astgen-linux")
        shutil.copy2(adapted, jar)
        (provenance / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    build(Path(sys.argv[1]).resolve())
