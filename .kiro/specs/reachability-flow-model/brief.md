# Brief: reachability-flow-model

## Problem

The tool's stated principle is to steer effort where risk is actually reduced. Today it cannot, because it has no model of how data or control reaches a sink:

- "Reachable" means the finding's line sits inside a route or CLI handler (`mapping.analyze_entry_points`). There is no call graph. On real code, sinks live in helpers several calls below the handler, so nearly everything is `unknown`, and `worth_fixing` (triggerable plus reachable) rarely fires.
- The overlay's taint is intra-file and one hop. A flow from a request parameter to a memcpy three functions away is invisible, and `unadjudicated` carries no partial path.
- Every stage handoff discards information. LLM hunter findings are capped at suspicion and cannot become sandbox candidates (`cli.py:404`, `prove_filter.py`); prove sees only regex-proposed, overlay-promoted ids.
- The hunter reads whole files and returns JSON. That is the most expensive and least verifiable use of a model.
- The improve loop's only levers are rule status and policy constants. It cannot add a sink, a sanitizer, a nullable callee, or a transformer, which are the only data that move recall.

Codebase shape confirms it: detection logic is about 16 percent of the source; harness plumbing, governance, and ranking are the rest, built around an engine that cannot express a guard or a call edge.

## Desired Outcome

A path model: entry point, hops, sink, guards seen, summaries used. Reachability becomes graph distance with a concrete path. The hunter works on paths and asks one checkable question per hole the static engine cannot fill. Answers become facts, gated on the pair corpus, reused at zero token cost. The report's first section is fix points: the few places whose fix collapses the most reachable risk.

True concolic execution is out of scope. The sandbox is the concrete half; the hunter proposing an input for a path and the sandbox running it is the loop this spec designs for, without a solver.

## Approach

Build a name-resolved call graph from the `FunctionIR` records tree-sitter already produces. Compute per-function taint summaries with the existing intra-file engine and compose them along the graph to a bounded depth. Attach graph reachability to findings, rank, map, and worth-fixing. Give the hunter a `path_context` tool and let a hunter finding with a locatable sink become a sandbox candidate after the safety check. Add a fact oracle: closed question kinds the static engine asks a model about a callee, cached as candidate facts with provenance, promoted only through the improve loop's new `facts` lever under the per-profile holdout gate from `pair-corpus-honesty`. Compute fix points as dominators on the path graph and report risk removed per fix.

## Scope

- **In**: call graph, summaries, path records, reachability attachment, rank and map integration, hunter on paths, hunter-to-candidate path, fact oracle with cache, `facts` lever with validator, fix-point ranking and report section, measurement on split-sink, vibe-py, vfc slices, offline tests.
- **Out**: guard dominance semantics (`guard-dominance-regime` consumes path records), CST walker fixes (`overlay-ir-completeness`), a whole-program points-to or symbolic engine, concolic execution, executing target code outside the sandbox, new dispositions, LLM as parser, any merge gate change.

## Boundary Candidates

- Call graph and summaries (semantic) vs entry points (mapping) vs rank and map consumers
- Fact oracle (asks and caches) vs facts lever (accepts) vs fact loader (consumes)
- Hunter path context vs regression candidate selection

## Out of Boundary

- Overlay dispositions and evidence rungs (`propose-adjudicate-prove`)
- CWE policy, project score, rule status lever (`harnessx-self-improving-rulesets`)
- Sandbox flags, recipes, verdict vocabulary (`three-stage-scan`)
- Pair scorer and label schema (`pair-corpus-honesty`)

## Upstream / Downstream

- **Upstream**: `FileIR`/`FunctionIR`, `analyze_entry_points`, `analyze_ir`, `load_facts`, `Hotspot`, `run_tool_hunter`, `select_candidates`, `run_improvement`, pair holdout metrics per profile.
- **Downstream**: `guard-dominance-regime` attaches guards to path records; later web-authorization detection is a path whose hops include no auth guard; reports and MCP read fix points.

## Existing Spec Touchpoints

- **Extends**: `three-stage-scan` (hunter tools, candidate selection, worth-fixing input), `propose-adjudicate-prove` (facts consumed unchanged; one new fact source), `harnessx-self-improving-rulesets` (one new lever under the same gate).
- **Depends**: `pair-corpus-honesty` for per-profile holdout metrics and the hunter scorer.
- **Adjacent**: `overlay-ir-completeness` improves the records this spec walks; neither blocks the other.

## Constraints

Core `dependencies = []`. Graph depth and fan-out bounded by config. Missing edges yield `unknown`, never `safe`. Model answers never bypass the gate; hand-written facts always win over candidate facts. No target code runs outside the sandbox. Youden on non-local slices stays off the merge gate.
