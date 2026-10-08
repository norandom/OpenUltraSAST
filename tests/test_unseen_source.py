"""Sanitized REST-shaped advisory fixtures; every external client is a fake."""

import copy
import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
s = importlib.import_module("benchmarks.unseen.source")


def advisory():
    path = Path(__file__).resolve().parents[1] / "benchmarks/unseen/fixtures/advisory.json"
    return json.loads(path.read_bytes())


class API:
    def __init__(self):
        self.parents = ["b" * 40]
        self.spdx = "MIT"
        self.license_text = "SPDX-License-Identifier: MIT"
        self.calls = []
        self.repo = {"full_name": "fixture/project", "private": False, "size": 100, "clone_url": "https://github.com/fixture/project.git"}

    def get_repo(self, name):
        return copy.deepcopy(self.repo)

    def get_commit(self, name, sha):
        return {"sha": sha, "parents": [{"sha": p} for p in self.parents]}

    def get_license(self, name, ref):
        self.calls.append((name, ref))
        return {"text": self.license_text, "spdx_id": self.spdx, "path": "LICENSE"}


class OSV:
    def get(self, identifier):
        return {
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "fixture"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.2"}, {"fixed": "1.3"}]}],
                }
            ]
        }


def test_candidate_cwe_cutoff_bracket_and_pinned_license():
    api = API()
    candidate = s.candidate(advisory(), api, OSV())
    assert candidate.family == "injection" and candidate.post_cutoff
    assert candidate.first_affected == "1.2"
    assert candidate.license_class == "permissive"
    assert api.calls == [("fixture/project", "b" * 40)]
    raw = advisory()
    raw["published_at"] = "2026-06-01T12:00:00Z"
    assert not s.candidate(raw, api, OSV()).post_cutoff
    raw["published_at"] = "2018-12-31T00:00:00Z"
    with pytest.raises(s.Rejected, match="date"):
        s.candidate(raw, api, OSV())


@pytest.mark.parametrize("spdx", ["GPL-3.0", "AGPL-3.0-only", "LGPL-2.1", "NOASSERTION", "", "BUSL-1.1", "MIT OR GPL-3.0"])
def test_private_licenses(spdx):
    api = API()
    api.spdx = spdx
    api.license_text = ""
    assert s.candidate(advisory(), api, OSV()).license_class == "private"


def test_license_file_overrides_api_and_missing_file_is_private():
    api = API()
    api.license_text = "SPDX-License-Identifier: GPL-3.0-only"
    assert s.candidate(advisory(), api, OSV()).license_class == "private"
    api.license_text = ""
    api.spdx = "Apache-2.0"
    assert s.candidate(advisory(), api, OSV()).license_spdx == "Apache-2.0"


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (lambda a, api: api.parents.append("c" * 40), "parents"),
        (lambda a, api: a["references"].append("https://github.com/fixture/other/commit/" + "d" * 40), "fix_links"),
        (lambda a, api: a.update(cwes=[{"cwe_id": "CWE-99999"}]), "family"),
        (lambda a, api: api.repo.update(size=512001), "repository"),
        (lambda a, api: api.repo.update(private=True), "repository"),
        (lambda a, api: api.repo.update(clone_url="ssh://fixture/project"), "repository"),
    ],
)
def test_rejections(mutation, reason):
    api, raw = API(), advisory()
    mutation(raw, api)
    with pytest.raises(s.Rejected, match=reason):
        s.candidate(raw, api, OSV())


def test_post_cutoff_first_within_ecosystem_is_seeded():
    rows = [advisory() for _ in range(12)]
    for i, row in enumerate(rows):
        row["ghsa_id"] += str(i)
        if i % 2:
            row["published_at"] = "2025-01-01T00:00:00Z"
    ordered = s.ordered_advisories(rows, 17)
    assert ordered == s.ordered_advisories(list(reversed(rows)), 17)
    assert all(s.post_cutoff(row) for row in ordered[:6])


def test_http_adapters_with_fake_transport():
    import base64
    from urllib.parse import parse_qs, urlsplit

    class Transport:
        response_headers = {}

        def __init__(self):
            self.calls = []

        def get(self, url, headers):
            self.calls.append((url, headers))
            parsed = urlsplit(url)
            if parsed.path == "/advisories":
                after = parse_qs(parsed.query).get("after")
                self.response_headers = {} if after else {"Link": f'<{url}&after=cursor>; rel="next"'}
                return [
                    {**advisory(), "ghsa_id": f"GHSA-test-test-{i:04d}"} for i in range(0 if not after else 100, 100 if not after else 101)
                ]
            if "/license" in parsed.path:
                assert parse_qs(parsed.query)["ref"] == ["b" * 40]
                return {
                    "license": {"spdx_id": "MIT"},
                    "path": "LICENSE",
                    "content": base64.b64encode(b"SPDX-License-Identifier: MIT").decode(),
                }
            if "/commits/" in parsed.path:
                return {"sha": "a" * 40, "parents": [{"sha": "b" * 40}]}
            if parsed.hostname == "api.osv.dev":
                return OSV().get("ignored")
            return API().repo

    transport = Transport()
    api = s.GitHub("fake-token", transport)
    assert len(list(api.advisories())) == 101
    assert s.candidate(advisory(), api, s.OSV(transport)).first_affected == "1.2"
    assert all(headers["Authorization"] == "Bearer fake-token" for url, headers in transport.calls if "api.github.com" in url)
    count = api.calls
    api.get_repo("fixture/project")
    assert api.calls == count


def test_http_failures_are_not_empty_results():
    class Transport:
        response_headers = {}

        def get(self, url, headers):
            raise ValueError("http_failure")

    with pytest.raises(ValueError, match="http_failure"):
        list(s.GitHub("fake", Transport()).advisories())
    with pytest.raises(ValueError, match="http_failure"):
        s.OSV(Transport()).get("GHSA-test-test-test")


def test_transport_rate_limit_retry_and_sanitized_failure():
    import io
    from urllib.error import HTTPError

    waits, attempts = [], []

    def opener(request, timeout):
        attempts.append(request)
        if len(attempts) == 1:
            raise HTTPError(request.full_url, 403, "private message", {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "120"}, None)
        return io.BytesIO(b'{"ok": true}')

    transport = s.JSONTransport(opener=opener, sleeper=waits.append, clock=lambda: 100)
    assert transport.get("https://example.invalid", {}) == {"ok": True}
    assert waits == [60] and transport.attempts == 2

    def down(request, timeout):
        raise HTTPError(request.full_url, 503, "private name", {}, None)

    transport = s.JSONTransport(opener=down, sleeper=waits.append)
    with pytest.raises(ValueError, match="^http_failure$"):
        transport.get("https://example.invalid", {})
    assert transport.attempts == 5


@pytest.mark.parametrize("failures", [1, 3, 4, 5, 7])
@pytest.mark.parametrize("kind", ["url", "timeout", "connection", "reset", "incomplete", "json"])
def test_transport_connection_and_body_transients(kind, failures):
    import io
    from http.client import IncompleteRead
    from urllib.error import URLError

    errors = {
        "url": URLError("private endpoint"),
        "timeout": TimeoutError("private endpoint"),
        "connection": ConnectionError("private endpoint"),
        "reset": ConnectionResetError("private endpoint"),
        "incomplete": IncompleteRead(b"private partial body", 100),
    }
    waits, calls = [], []

    class BrokenBody(io.BytesIO):
        def read(self, *args):
            raise errors[kind]

    def opener(request, timeout):
        calls.append(request)
        if len(calls) <= failures:
            if kind == "json":
                return io.BytesIO(b'{"private":')  # exercise json.load, not just the opener
            if kind == "incomplete":
                return BrokenBody()
            raise errors[kind]
        return io.BytesIO(b'{"ok": true}')

    transport = s.JSONTransport(opener=opener, sleeper=waits.append)
    if failures >= 5:
        with pytest.raises(ValueError, match="^http_failure$"):
            transport.get("https://example.invalid", {})
    else:
        assert transport.get("https://example.invalid", {}) == {"ok": True}
    assert transport.attempts == len(calls) == min(failures + 1, 5)
    assert waits == [2**i for i in range(min(failures, 4))]


@pytest.mark.parametrize("code", [400, 401, 403, 404, 422])
def test_transport_nonretryable_http_status(code):
    from urllib.error import HTTPError

    waits = []

    def opener(request, timeout):
        raise HTTPError(request.full_url, code, "private endpoint", {}, None)

    transport = s.JSONTransport(opener=opener, sleeper=waits.append)
    error, message = (s.RepositoryNotFound, "not_found") if code == 404 else (ValueError, "http_failure")
    with pytest.raises(error, match=f"^{message}$"):
        transport.get("https://example.invalid", {})
    assert transport.attempts == 1 and waits == []


@pytest.mark.parametrize("code", [403, 429, 500, 502, 503, 504])
@pytest.mark.parametrize("retry_after", ["7", "invalid", "3606"])
def test_transport_http_retry_after_and_window_guard(code, retry_after):
    import io
    from urllib.error import HTTPError

    waits, calls = [], []

    def opener(request, timeout):
        calls.append(request)
        if len(calls) == 1:
            raise HTTPError(request.full_url, code, "private endpoint", {"Retry-After": retry_after}, None)
        return io.BytesIO(b"{}")

    transport = s.JSONTransport(opener=opener, sleeper=waits.append)
    if retry_after == "7":
        assert transport.get("https://example.invalid", {}) == {}
        assert waits == [7] and transport.attempts == 2
    else:
        with pytest.raises(ValueError, match="^http_retry_failed$"):
            transport.get("https://example.invalid", {})
        assert waits == [] and transport.attempts == 1


def test_transport_decode_retry_respects_response_retry_after():
    import io

    waits = []
    responses = [io.BytesIO(b'{"truncated":'), io.BytesIO(b"{}")]
    responses[0].headers = {"Retry-After": "9"}
    transport = s.JSONTransport(opener=lambda *a, **kw: responses.pop(0), sleeper=waits.append)
    assert transport.get("https://example.invalid", {}) == {}
    assert waits == [9]


@pytest.mark.parametrize("ecosystem", s.ECOSYSTEMS)
def test_advisory_page_filters_match_candidate_population(ecosystem):
    from urllib.parse import parse_qs, urlsplit

    taxonomy = s.load_families()
    expected = {c for f in taxonomy.families if f.id in s.FAMILIES for c in f.cwes}

    class Transport:
        response_headers = {}

        def get(self, url, headers):
            query = parse_qs(urlsplit(url).query)
            assert query == {
                "type": ["reviewed"],
                "per_page": ["100"],
                "sort": ["published"],
                "direction": ["asc"],
                "ecosystem": [ecosystem],
                "published": [">=2019-01-01"],
                "cwes": [",".join(sorted((c.removeprefix("CWE-") for c in expected), key=int))],
            }
            return []

    assert s.GitHub("fake", Transport()).advisory_page(ecosystem=ecosystem) == {"rows": [], "next_url": None}
    # Every enumerated CWE is selectable at the inclusive date boundary.
    for cwe in expected:
        row = advisory()
        row.update(published_at="2019-01-01T00:00:00Z", cwes=[{"cwe_id": cwe}])
        row["vulnerabilities"][0]["package"]["ecosystem"] = ecosystem
        assert s.candidate(row, API(), OSV()).family == taxonomy.family_of_cwe(cwe).id


@pytest.mark.parametrize("token", ["CWE-89*", "CWE-", "89", "CWE-79..CWE-89"])
def test_advisory_page_omits_entire_cwe_filter_for_non_exact_taxonomy(monkeypatch, token):
    from dataclasses import replace
    from urllib.parse import parse_qs, urlsplit

    taxonomy = s.load_families()
    family = taxonomy.by_id("injection")
    taxonomy = replace(taxonomy, families=tuple(replace(f, cwes=f.cwes | {token}) if f == family else f for f in taxonomy.families))
    monkeypatch.setattr(s, "load_families", lambda: taxonomy)

    class Transport:
        response_headers = {}

        def get(self, url, headers):
            query = parse_qs(urlsplit(url).query)
            assert "cwes" not in query
            assert query["published"] == [">=2019-01-01"]
            assert query["ecosystem"] == ["pip"]
            return []

    s.GitHub("fake", Transport()).advisory_page(ecosystem="pip")


@pytest.mark.parametrize("journaled", [False, True])
def test_cursor_walk_ignores_page_numbers_and_stops_without_next(tmp_path, journaled):
    import io
    from email.message import Message
    from urllib.parse import parse_qs, urlencode, urlsplit

    calls = []

    def opener(request, timeout):
        query = parse_qs(urlsplit(request.full_url).query)
        eco = query["ecosystem"][0]
        after = query.get("after", [None])[0]
        calls.append((eco, after))
        assert len(calls) <= 12  # Fail loudly if a page-number loop repeats forever.
        # Like /advisories, ignore any page parameter. Only the opaque cursor advances.
        offset = 100 if after == "opaque+/=" else 0
        rows = [{**advisory(), "ghsa_id": f"GHSA-test-test-{i:04d}"} for i in range(offset, offset + 100)]
        response = io.BytesIO(json.dumps(rows).encode())
        response.headers = Message()
        if after is None:
            following = "https://api.github.com/advisories?" + urlencode({**query, "after": ["opaque+/="]}, doseq=True)
            response.headers["link"] = f'<https://api.github.com/advisories?before=other>; rel="prev", <{following}>; rel="next"'
        else:
            # A full last page with a Link header, but no next relation, is exhausted.
            response.headers["link"] = '<https://api.github.com/advisories?before=other>; rel="prev"'
        return response

    transport = s.JSONTransport(opener=opener)
    first = "https://api.github.com/advisories?ecosystem=pip"
    assert transport.get(first + "&page=1", {}) == transport.get(first + "&page=100", {})
    calls.clear()
    api = s.GitHub("fake", transport)
    if journaled:
        draft = importlib.import_module("benchmarks.unseen.draft")
        with draft.Journal(tmp_path / "journal").open({"journal_version": 4}) as journal:
            rows = draft.enumerate_advisories(api, journal)
    else:
        rows = list(api.advisories())
    assert [row["ghsa_id"] for row in rows] == [f"GHSA-test-test-{i:04d}" for i in range(200)]
    assert calls == [(eco, cursor) for eco in s.ECOSYSTEMS for cursor in (None, "opaque+/=")]


def test_transport_replaces_last_successful_response_headers():
    import io

    responses = [io.BytesIO(b"{}"), io.BytesIO(b'{"broken":'), io.BytesIO(b"[]")]
    responses[0].headers = {"Link": '<https://api.github.com/advisories?after=cursor>; rel="next"'}
    responses[1].headers = {"Link": "failed response"}
    waits = []
    transport = s.JSONTransport(opener=lambda *a, **kw: responses.pop(0), sleeper=waits.append)
    assert transport.get("https://example.invalid", {}) == {}
    assert "cursor" in transport.response_headers["Link"]
    assert transport.get("https://example.invalid", {}) == []
    assert transport.response_headers == {}
    assert waits == [1]
