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
        def __init__(self):
            self.calls = []

        def get(self, url, headers):
            self.calls.append((url, headers))
            parsed = urlsplit(url)
            if parsed.path == "/advisories":
                page = int(parse_qs(parsed.query)["page"][0])
                return [advisory()] * (100 if page == 1 else 1)
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
