"""Offline packaged CLI/registry and disposable Git hook validation, not detector qualification."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

from openultrasast.model.scan import ScanBudget
from openultrasast.push.eligibility import _DEFAULT, load_registry
from openultrasast.push.runner import _provenance

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--ops", type=Path, required=True)
args = parser.parse_args()
out = args.out
out.mkdir(exist_ok=False)


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, timeout=20, **kwargs)


help_result = run(["ousast", "pre-push", "--help"])
assert help_result.returncode == 0, help_result.stderr
(out / "help.txt").write_bytes(help_result.stdout)
current = _provenance(out, ScanBudget(max_model_calls=0, max_regions=500, order_by_evidence=True))
registry = load_registry(current=current)
assert _DEFAULT.is_file() and _DEFAULT.stat().st_size > 0
assert registry.status == "NO-GO" and not registry.capabilities, registry
results = []
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    for prior_exit in (0, 7):
        root = tmp / str(prior_exit)
        root.mkdir()

        def git(*args, root=root):
            result = run(["git", "-C", str(root), *args])
            assert result.returncode == 0, result.stderr
            return result.stdout.decode().strip()

        git("init")
        git("config", "user.name", "Packaged smoke")
        git("config", "user.email", "smoke@example.invalid")
        (root / "api.js").write_text("function endpoint(req) { return eval(req.body.value); }\n")
        assert len((root / "api.js").read_bytes()) > 0
        git("add", "api.js")
        git("commit", "-m", "Authored interface smoke, not a security control")
        head = git("rev-parse", "HEAD")
        remote = root / "remote.git"
        git("init", "--bare", str(remote))
        git("remote", "add", "origin", str(remote))
        git("config", "core.hooksPath", ".custom-hooks")
        installer = run([str(args.ops / "install-pre-push"), str(root)])
        assert installer.returncode == 0, installer.stderr
        hook = root / ".custom-hooks/pre-push"
        before_hook = hook.read_bytes()
        refused = run([str(args.ops / "install-pre-push"), str(root)])
        assert refused.returncode != 0 and hook.read_bytes() == before_hook
        prior = hook.with_name("pre-push.before-ousast")
        prior.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > prior-args\ncat > prior-stdin\nexit ' + str(prior_exit) + "\n")
        prior.chmod(0o755)
        before = ((root / ".git/index").read_bytes(), (root / "api.js").read_bytes(), head)
        artifacts = out / str(prior_exit)
        env = {**os.environ, "OUSAST_ARTIFACT_DIR": str(artifacts), "OUSAST_PUSH_DEADLINE": "0.1"}
        result = run(["git", "-C", str(root), "push", "origin", "HEAD:refs/heads/smoke"], env=env)
        assert (result.returncode == 0) == (prior_exit == 0), result.stderr
        assert (root / "prior-stdin").read_text() == f"HEAD {head} refs/heads/smoke {'0' * 40}\n"
        assert (root / "prior-args").read_text().splitlines() == ["origin", str(remote)]
        assert before == ((root / ".git/index").read_bytes(), (root / "api.js").read_bytes(), git("rev-parse", "HEAD"))
        assert git("config", "core.hooksPath") == ".custom-hooks"
        saved = list(artifacts.glob("*.json"))
        assert len(saved) == 1
        artifact = json.loads(saved[0].read_bytes())
        assert not artifact["admission"]["defects"]
        assert artifact["result"]["coverage_status"] != "complete_within_scope"
        original = prior.read_bytes()
        hook.unlink()
        prior.rename(hook)
        assert hook.read_bytes() == original
        after = run(["git", "-C", str(root), "push", "origin", "HEAD:refs/heads/restored"], env=env)
        assert (after.returncode == 0) == (prior_exit == 0)
        results.append(
            dict(
                prior_exit=prior_exit,
                push_exit=result.returncode,
                removal_push_exit=after.returncode,
                exact_stdin=True,
                exact_remote_args=True,
                live_state_preserved=True,
                overwrite_refused=True,
                coverage=artifact["result"]["coverage_status"],
                source_bytes=len(before[1]),
                terminal=(result.stdout + result.stderr).decode(),
            )
        )
receipt = dict(
    uid=os.getuid(),
    provenance=current,
    registry_status=registry.status,
    enabled=0,
    no_model_configuration=True,
    network="disabled by docker invocation",
    cases=results,
)
(out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt))
