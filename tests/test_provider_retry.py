"""Provider retry/backoff policy (Phase 15)."""

import urllib.error

import pytest

from openultrasast.provider.openrouter import OpenRouterError, call_with_retry


class _Counter:
    def __init__(self, fail_times: int, exc: Exception) -> None:
        self.calls = 0
        self._fail_times = fail_times
        self._exc = exc

    def __call__(self) -> str:
        self.calls += 1
        if self.calls <= self._fail_times:
            raise self._exc
        return "ok"


def _no_sleep(_seconds: float) -> None:
    return None


def test_retries_transient_then_succeeds() -> None:
    op = _Counter(2, TimeoutError("slow"))
    assert call_with_retry(op, attempts=3, base_delay=0, sleep=_no_sleep) == "ok"
    assert op.calls == 3


def test_retries_transient_http_5xx() -> None:
    op = _Counter(1, urllib.error.HTTPError("u", 503, "busy", {}, None))  # type: ignore[arg-type]
    assert call_with_retry(op, attempts=3, base_delay=0, sleep=_no_sleep) == "ok"
    assert op.calls == 2


def test_does_not_retry_non_transient_http_4xx() -> None:
    op = _Counter(5, urllib.error.HTTPError("u", 400, "bad", {}, None))  # type: ignore[arg-type]
    with pytest.raises(urllib.error.HTTPError):
        call_with_retry(op, attempts=3, base_delay=0, sleep=_no_sleep)
    assert op.calls == 1  # tried once, not retried


def test_raises_after_exhausting_attempts() -> None:
    op = _Counter(10, TimeoutError("slow"))
    with pytest.raises(TimeoutError):
        call_with_retry(op, attempts=3, base_delay=0, sleep=_no_sleep)
    assert op.calls == 3


def test_backoff_is_exponential() -> None:
    delays: list[float] = []
    op = _Counter(2, urllib.error.URLError("reset"))
    call_with_retry(op, attempts=3, base_delay=0.5, sleep=delays.append)
    assert delays == [0.5, 1.0]  # 0.5 * 2**0, 0.5 * 2**1


def test_non_retryable_value_error_propagates_immediately() -> None:
    def op() -> str:
        raise OpenRouterError("not network")

    with pytest.raises(OpenRouterError):
        call_with_retry(op, attempts=3, base_delay=0, sleep=_no_sleep)
