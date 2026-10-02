from pathlib import Path

SKILLS_ROOT = Path(".agents/skills")  # the plural directory OpenCode searches by default


def test_project_agent_skills_have_required_frontmatter() -> None:
    # Scope to the project's own skills; third-party tooling (e.g. kiro-*) lives
    # alongside them and uses a different frontmatter convention.
    skill_files = sorted(SKILLS_ROOT.glob("openultrasast-*/SKILL.md"))

    assert {path.parent.name for path in skill_files} == {
        "openultrasast-scan",
        "openultrasast-triage",
    }

    for skill_file in skill_files:
        text = skill_file.read_text()
        header = text.split("---", 2)[1]
        assert f"name: {skill_file.parent.name}" in header
        assert "description: " in header
        assert "Use when" in header


def test_scan_skill_states_the_evidence_ladder_as_the_code_defines_it() -> None:
    # The skill must not drift from verification.py again: every level, in the code's order, and the
    # retired threshold language gone.
    text = (SKILLS_ROOT / "openultrasast-scan" / "SKILL.md").read_text()
    levels = [
        "suspicion",
        "static_corroboration",
        "crash_reproduced",
        "root_cause_explained",
        "exploit_demonstrated",
        "patch_validated",
    ]
    ladder = text[text.index("## Evidence ladder") : text.index("## Run artifacts")]
    positions = [ladder.index(f"`{level}`") for level in levels]
    assert positions == sorted(positions)
    assert "configured report threshold" not in text
    current_cli = (
        "--mode quick|standard|deep",
        "--fail-on",
        "cpg_unavailable",
        "sandbox_unavailable",
        "report.sarif",
        "harness.json",
        "ousast mcp",
    )
    for flag in current_cli:
        assert flag in text, flag


def test_triage_skill_lists_the_false_positive_reasons_exactly() -> None:
    from openultrasast.calibration import FalsePositiveReason

    text = (SKILLS_ROOT / "openultrasast-triage" / "SKILL.md").read_text()
    listed = {line.strip()[3:-1] for line in text.splitlines() if line.startswith("- `") and line.strip().endswith("`")}
    assert listed == {reason.value for reason in FalsePositiveReason}
    assert "patch_validated" in text and "Nothing in the tool records `patch_validated`" in text
