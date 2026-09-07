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


def test_a_body_that_stops_mid_read_is_transient() -> None:
    """Measured: an evolve round died on `http.client.IncompleteRead(0 bytes read)`.

    The retry classified only connection-level failures, so a response whose *body* stopped arriving escaped both
    the retry and the error wrapper, and the exception walked out of the round. The network is allowed to be
    unreliable; losing a paid round to it is our defect, not the provider's."""
    import http.client

    from openultrasast.provider.openrouter import OpenRouterError, _is_transient, call_with_retry

    assert _is_transient(http.client.IncompleteRead(b"")) is True
    assert _is_transient(http.client.RemoteDisconnected("closed")) is True
    assert _is_transient(ValueError("a bug in our own code")) is False

    attempts = []

    def flaky() -> str:
        attempts.append(1)
        if len(attempts) < 3:
            raise http.client.IncompleteRead(b"")
        return "ok"

    assert call_with_retry(flaky, attempts=3, base_delay=0.0, sleep=lambda _s: None) == "ok"
    assert len(attempts) == 3
    assert issubclass(OpenRouterError, Exception)


def test_a_read_failure_is_reported_as_a_provider_error_not_a_raw_http_exception() -> None:
    import http.client
    import urllib.error

    from openultrasast.provider.openrouter import OpenRouterChatClient, OpenRouterError

    client = OpenRouterChatClient(api_key="k", base_url="https://example.invalid", max_attempts=1)

    def boom(*_args: object, **_kwargs: object) -> object:
        raise http.client.IncompleteRead(b"")

    import openultrasast.provider.openrouter as module

    original = module.urllib.request.urlopen
    module.urllib.request.urlopen = boom  # type: ignore[assignment]
    try:
        with pytest.raises(OpenRouterError, match="IncompleteRead"):
            client.complete_chat_raw(model="m", messages=[{"role": "user", "content": "x"}])
    finally:
        module.urllib.request.urlopen = original  # type: ignore[assignment]
    assert urllib.error.URLError is not None
