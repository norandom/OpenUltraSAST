# Brief: remove HarnessX after the plane proves value

Status: brief only, gated. Not started until `ai-service-plane` Requirement 6 records a met gate.

## Inventory (read-only, 2026-09-29)

- Code: `src/openultrasast/harness_ext.py` (97 lines) and `hunter_harness.py` (197) exist only for HarnessX;
  guarded branches in `cli.py` (372-512), `fusion.py` (LLM panels, ~100 lines), `verify_judge.py` (judge path,
  ~90), `stage_processors.py` (`host_under_harnessx`, ~40), `config.py` (`HarnessxConfig`). About 575 of
  30,243 lines (1.9%). Every path falls back deterministically when the extra is absent and records a
  degradation (`harnessx_extra_unavailable`; fallbacks `run_hunter_pool`, `structural_verifier`,
  `deterministic_panels`). `evolve`, `regress`, `benchmark`, `gate` and quick mode do not depend on it.
- Packaging: `pyproject.toml` extra `harnessx` pinned to a git commit; mypy override; `uv.lock` entry.
- Tests: 14 files touch it; dedicated `test_harness_ext.py`, `test_hunter_harness.py`, `test_cli_hx_dispatch.py`,
  `test_verify_judge.py`; `tests/conftest.py` fixture `assert_cold_of_harnessx`.
- Docs: README sections "Configuring the HarnessX agentic plane" and "The HarnessX self-improving cycle";
  `docs/examples.md` section 6; `docs/threat-model.md` egress and spend caps.
- Specs: `harnessx-self-improving-rulesets` (approved, 43/43 done, Requirement 1 is direct adoption);
  `learning-harness` (30/33); `three-stage-scan` framed as its follow-up; `openrouter-sast-harness` (no
  spec.json); mentions in four more; steering `overview.md:175`.

## Shape of the removal

1. Replace the three guarded paths with plane tasks (hunter pool -> `verify`; judge -> `judge`; panels ->
   `judge`/`agree`) so their fallbacks become the only path, then delete the two modules, the config block,
   the extra, the override and the fixture.
2. Retire the four specs' HarnessX requirements with a dated note, not a rewrite; update README and docs.
3. Gate: the plane increment met (recall and cost), and the replaced features measured no worse on the
   development pins before deletion.
