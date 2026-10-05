import html
import shutil
import subprocess

import pytest

from openultrasast.search.oracles import BrowserExecutor


def test_browser_launch_failure_is_not_negative(monkeypatch):
    def fail(*args, **kwargs):
        return subprocess.CompletedProcess(args, 1, "", "failed")

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(OSError):
        BrowserExecutor(binary="/fake/chromium")('<script>alert("ousast-xss")</script>', "nonce")


@pytest.mark.skipif(not (shutil.which("chromium") or shutil.which("chromium-browser")), reason="chromium not installed")
def test_real_browser_executes_not_reflects():
    browser = BrowserExecutor()
    payload = '<script>alert("ousast-xss")</script>'
    try:
        observed = browser(payload, "nonce")
    except OSError as exc:
        # A present binary is insufficient on restricted hosts. Only known
        # host permission denials skip; ordinary browser failures remain failures.
        if "Operation not permitted" in str(exc) or "Permission denied" in str(exc):
            pytest.skip("host denies browser isolation/socket setup: " + str(exc))
        raise
    assert observed
    assert not browser(html.escape(payload), "nonce")
    assert not browser("<p>nonce</p>", "nonce")


@pytest.mark.parametrize("executed", [False, True])
def test_marker_is_dom_attribute_not_source_text(monkeypatch, executed):
    import re
    from urllib.parse import unquote

    def run(command, **kwargs):
        assert "--headless" in command and "--dump-dom" in command
        assert "--unshare-all" in command and "--no-sandbox" not in command
        document = unquote(command[-1].split(",", 1)[1])
        attr, value = re.search(r'setAttribute\("([^"]+)","([^"]+)"\)', document).groups()
        root = f'<html {attr}="{value}">' if executed else "<html>"
        return subprocess.CompletedProcess(command, 0, root + document + "</html>", "")

    monkeypatch.setattr(subprocess, "run", run)
    assert BrowserExecutor(binary="/usr/bin/chromium")("<p>reflected nonce</p>", "nonce") is executed
