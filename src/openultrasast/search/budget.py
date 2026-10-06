"""Search ceilings carried to every executor; no model or transport dependencies."""

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class SearchBudget:
    # Recalibrated 2026-10-05 on the first three measured searches: settled cost was ~$0.003 per model call,
    # but worst-case reservations (~$0.027 per call) exhausted the old $0.05 task allowance after 2-4 calls.
    spend_usd: float = 2.00
    # Both ceilings bound each task: $0.40 and 40 model steps.
    max_call_usd: float = 0.40
    max_steps: int = 40
    http_start_seconds: int = 90
    cli_start_seconds: int = 30
    reason_rounds: int = 4
    intents_per_round: int = 3
    demonstrations: int = 3
    tasks: int = 32
    retries: int = 1
    memory_bytes: int = 5 * 1024**3
    disk_bytes: int = 2 * 1024**3
    task_wall_seconds: float = 900
    wall_seconds: float = 4 * 3600
    cleanup_seconds: float = 30

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError(f"invalid {name}")
            if value < 0 or (value == 0 and name not in ("retries", "spend_usd")):
                raise ValueError(f"invalid {name}")
            if name in (
                "max_steps",
                "http_start_seconds",
                "cli_start_seconds",
                "reason_rounds",
                "intents_per_round",
                "demonstrations",
                "tasks",
                "retries",
                "memory_bytes",
                "disk_bytes",
            ) and not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")


def verification_timeout(schema: dict, limits: dict | None = None) -> int:
    """Resolve the mode's start/command allowance from the search task budget."""
    key = "http_start_seconds" if schema["start"]["mode"] == "http" else "cli_start_seconds"
    value = (limits or {}).get(key, getattr(SearchBudget(), key))
    if type(value) is not int or not 1 <= value <= 300:
        raise ValueError("invalid verification timeout")
    return value


def verification_run_seconds(schema: dict, timeout: int) -> int:
    # One readiness operation, all declared steps, and driver shutdown/handshake.
    return timeout * (1 + len(schema["steps"])) + 5
