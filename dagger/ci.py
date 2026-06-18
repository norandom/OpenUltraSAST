from __future__ import annotations

import sys

import anyio

import dagger


async def main() -> None:
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
            .with_exec(["uv", "run", "python", "-m", "compileall", "src", "tests"])
            .with_exec(["uv", "build"])
        )
        await checks.sync()


if __name__ == "__main__":
    anyio.run(main)
