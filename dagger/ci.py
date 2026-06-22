from __future__ import annotations

import sys

import anyio

import dagger

# Substrings that mark a transient registry / image-pull failure (e.g. a Docker
# Hub 5xx on the python:3.11-bookworm pull, or a registry.dagger.io timeout) that
# is worth retrying rather than failing the whole pipeline.
_TRANSIENT_MARKERS = (
    "pull image",
    "failed to authorize",
    "failed to fetch oauth",
    "TransportQueryError",
    "i/o timeout",
    "connection reset",
    "context deadline exceeded",
    " 502",
    " 503",
    " 520",
    " 429",
)


async def _run_checks() -> None:
    config = dagger.Config(log_output=sys.stderr)
    async with dagger.Connection(config) as client:
        source = client.host().directory(
            ".",
            exclude=[
                ".git",
                ".mypy_cache",
                ".pytest_cache",
                ".ruff_cache",
                ".venv",
                "**/.openultrasast",
                "dist",
            ],
        )
        checks = (
            client.container()
            .from_("python:3.11-bookworm")
            .with_directory("/src", source)
            .with_workdir("/src")
            .with_exec(["python", "-m", "pip", "install", "uv"])
            .with_exec(["uv", "sync", "--group", "dev"])
            .with_exec(["uv", "run", "ruff", "format", "--check", "."])
            .with_exec(["uv", "run", "ruff", "check", "."])
            .with_exec(["uv", "run", "mypy", "src/openultrasast"])
            .with_exec(["uv", "run", "pytest"])
            .with_exec(["uv", "run", "python", "-m", "openultrasast.gate"])
            .with_exec(["uv", "run", "python", "-m", "compileall", "src", "tests"])
            .with_exec(["uv", "build"])
        )
        await checks.sync()


async def main() -> None:
    attempts = 3
    for attempt in range(1, attempts + 1):
        try:
            await _run_checks()
            return
        except Exception as exc:  # noqa: BLE001 — retry only transient registry/pull failures
            message = str(exc)
            transient = any(marker in message for marker in _TRANSIENT_MARKERS)
            if attempt < attempts and transient:
                print(f"dagger: transient registry/pull failure on attempt {attempt}; retrying in 20s", file=sys.stderr)
                await anyio.sleep(20)
                continue
            raise


if __name__ == "__main__":
    anyio.run(main)
