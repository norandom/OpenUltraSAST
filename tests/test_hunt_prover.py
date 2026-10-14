"""Prover integration on instrumented local Git fixtures."""

import subprocess

import pytest

from openultrasast.hunt.producers import Context
from openultrasast.hunt.prover import prove_change


def repository(tmp_path, text, extra=None, lines=None):
    def git(*args):
        return subprocess.run(
            ["git", "-C", str(tmp_path), "-c", "core.hooksPath=/dev/null", *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.invalid")
    (tmp_path / "Fixture.java").write_text("class Plain {}\n")
    git("add", "Fixture.java")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    (tmp_path / "Fixture.java").write_text(text)
    for path, value in (extra or {}).items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(value)
        git("add", path)
    git("add", "Fixture.java")
    git("commit", "-qm", "head")
    change = dict(
        id="fixture",
        repo="fixture/app",
        kind="ordinary",
        base=base,
        head=git("rev-parse", "HEAD"),
        files=[{"path": "Fixture.java", "head_lines": lines or [[1, len(text.splitlines())]]}],
    )
    return tmp_path, change


@pytest.mark.parametrize("guard,findings", [("", 1), ("Jenkins.get().checkPermission(Jenkins.ADMINISTER);", 0)])
def test_stapler_verdict(tmp_path, guard, findings):
    root, change = repository(
        tmp_path,
        f"""class X extends Descriptor<Thing> {{
 public Object doTestConnection() {{
  {guard}
  return CredentialsProvider.lookupCredentials(Thing.class);
 }}
}}""",
    )
    ctx = Context(root, change)
    result = prove_change(root, change, ctx)
    assert len(result.findings) == findings
    assert result.coverage.operations_checked == 1
    assert result.coverage.operations_discharged == 1 - findings
    assert result.coverage.reached == 1
    assert len(ctx.read("Fixture.java").encode()) > 0
    if findings:
        (finding,) = result.findings
        assert finding["family"] == "access_control" and finding["function"] == "doTestConnection"
        assert finding["id"] == "obligation:protected_read:Fixture.java:4:path_guard"
        assert finding["entry"]["kind"] == "route" and finding["hops"] == [["Fixture.java::doTestConnection", None]]
        assert finding["operation"]["calls"] == ["lookupCredentials"] and finding["missing"] == "path_guard"
        assert finding["evidence"]


def test_unrecognised_is_coverage_only(tmp_path):
    root, change = repository(tmp_path, "class Plain { public Object run() { return lookupCredentials(); } }")
    result = prove_change(root, change)
    assert not result.findings and result.coverage.frameworks_recognised == {}
    assert result.coverage.unchecked_by_reason["framework_unrecognised"] == 1


@pytest.mark.parametrize("guard_position,expected", [("before", 0), ("after", 1), ("none", 1)])
def test_callee_and_caller_guard_order(tmp_path, guard_position, expected):
    guard = "Jenkins.get().checkPermission(Jenkins.ADMINISTER);"
    root, change = repository(
        tmp_path,
        f"""class X extends Descriptor<Thing> {{
 public Object doTestConnection() {{
  {guard if guard_position == "before" else ""}
  Object result = Helper.readSecret();
  {guard if guard_position == "after" else ""}
  return result;
 }}
}}""",
        {"Helper.java": "class Helper { public static Object readSecret() { return lookupCredentials(); } }"},
        [[2, 7]],
    )
    result = prove_change(root, change)
    assert len(result.findings) == expected and result.coverage.operations_checked == 1
    if expected:
        assert result.findings[0]["path"] == "Helper.java"
        assert len(result.findings[0]["hops"]) == 2


def test_touched_helper_walks_to_entry(tmp_path):
    root, change = repository(
        tmp_path,
        """class X extends Descriptor<Thing> {
 public Object doTestConnection() { return readSecret(); }
 public Object readSecret() { return lookupCredentials(); }
}""",
        lines=[[3, 3]],
    )
    result = prove_change(root, change)
    assert len(result.findings) == 1 and len(result.findings[0]["hops"]) == 2


def test_all_paths_are_checked(tmp_path):
    root, change = repository(
        tmp_path,
        """class X extends Descriptor<Thing> {
 public Object doFirst() {
  Jenkins.get().checkPermission(Jenkins.ADMINISTER);
  return readSecret();
 }
 public Object doSecond() { return readSecret(); }
 public Object readSecret() { return lookupCredentials(); }
}""",
        lines=[[7, 7]],
    )
    result = prove_change(root, change)
    assert len(result.findings) == 1 and result.coverage.operations_discharged == 0


def test_generated_output_and_parse_failure_counted(tmp_path):
    root, change = repository(
        tmp_path,
        "class X { public Object broken( { return lookupCredentials(); }",
        {"dist/bundle.java": "class X { public void doTest() {} }"},
    )
    change["files"].append({"path": "dist/bundle.java", "head_lines": [[1, 1]]})
    result = prove_change(root, change)
    assert not result.findings and result.coverage.unchecked_by_reason["parse_failed"] >= 1
    assert result.coverage.unchecked_by_reason["excluded_dir"] == 1


@pytest.mark.parametrize("exits,expected", [(True, 0), (False, 1)])
def test_caller_permission_predicate_requires_exit(tmp_path, exits, expected):
    root, change = repository(
        tmp_path,
        f"""class X extends Descriptor<Thing> {{
 public Object doTestConnection() {{
  boolean allowed = Jenkins.get().hasPermission(Jenkins.ADMINISTER);
  {"if (!allowed) {" if exits else ""}
  {"return null;" if exits else ""}
  {"}" if exits else ""}
  return Helper.readSecret();
 }}
}}""",
        {"Helper.java": "class Helper { public static Object readSecret() { return lookupCredentials(); } }"},
    )
    result = prove_change(root, change)
    assert len(result.findings) == expected and result.coverage.reached == 1
    assert result.coverage.operations_discharged == 1 - expected


def test_declared_public_route_suppresses_premise(tmp_path):
    root, change = repository(
        tmp_path,
        """class X extends Descriptor<Thing> {
 public Object doTestConnection() { return lookupCredentials(); }
}""",
        {".openultrasast/obligations.toml": 'version = 1\n[[route]]\npath = "doTestConnection"\naccess = "public"\n'},
    )
    result = prove_change(root, change)
    assert not result.findings and result.coverage.operations_checked == 1
    assert result.coverage.operations_discharged == 0


def test_nonpublic_unreached_function_in_partly_covered_repo(tmp_path):
    root, change = repository(
        tmp_path,
        "class Plain { public Object run() { return lookupCredentials(); } }",
        {"Exposed.java": "class X extends Descriptor<Thing> { public void doTest() {} }"},
    )
    result = prove_change(root, change)
    assert result.coverage.frameworks_recognised == {"stapler": 1}
    assert result.coverage.unchecked_by_reason["framework_unrecognised"] == 1
    assert not result.findings
