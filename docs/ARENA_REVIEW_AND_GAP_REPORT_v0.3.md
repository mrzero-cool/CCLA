# CLCA v0.3 — Arena Review, Gap Report and What Changed

**Date:** 29 October 2026
**Method:** four adversarial reviewer agents (security, architecture, benchmark/statistics, product) reviewed architecture v0.2 and the v0.2 scaffold in parallel; their findings were merged, prioritized, and the critical path was implemented as v0.3.

> Note: no "arena" skill is installed in this environment. The arena was built from four parallel general-purpose reviewer agents with adversarial briefs and non-overlapping scopes.

---

## 1. Arena verdict summary

| Reviewer | Headline finding |
|---|---|
| Security | **Critical:** trust was concentrated in the untrusted artifact. The `EvidenceBundle` supplied check statuses, requirements, policy identity and digests, while the trusted sources (policy file, check catalog, artifact contents) were never consulted. A forged bundle could yield `PASS`. |
| Architecture | **Critical:** the v0.2 scaffold implemented only `decide` + `plan`. Intake, adapters, impact resolution, runner, bundle builder, benchmark runner and reporting were all spec-only. Also: no digest algorithm was specified anywhere, so "reproducible from a bundle" was unverifiable. |
| Benchmark | **The v0.2 benchmark could not support the differentiation claim.** It is a scenario catalog, not a benchmark: no runnable patches, no oracle execution, no results; the oracle is defined in CLCA's own vocabulary (circular), label leakage is documented but unenforced, and abstention (`INCOMPLETE` everywhere) is not penalized. |
| Product | **5.5/10.** Thoughtful but not differentiated: GitHub required status checks + CODEOWNERS already gate merges. The one genuinely novel idea is the `INCOMPLETE` state — "we cannot prove safety, so we refuse to render PASS." Over-scoped to three heterogeneous asset families for a hackathon. |

The product reviewer's sharpest recommendation — *make the tool-grant escalation the demo moment: "your CI says green, this says block"* — is now an executable end-to-end test (`tests/test_e2e.py::test_write_tool_escalation_blocks_even_when_unit_tests_pass`).

---

## 2. Gap register: fixed in v0.3

| # | Gap (source) | Severity | v0.3 fix |
|---|---|---|---|
| 1 | Forged bundle → `PASS`: bundle digest never verified, policy digest attacker-chosen (Security #1) | Critical | `policy.decide()` recomputes the canonical bundle digest, and compares `policy_digest` against the SHA-256 of the loaded policy file; mismatch → `INCOMPLETE` |
| 2 | Check requirements came from the untrusted bundle (Security #2) | Critical | Requirements and `required_check_ids` are derived from `config/check_catalog.json`; a bundle-declared downgrade or unknown `check_id` → `INCOMPLETE` |
| 3 | `config/policy.json` rules were decorative (Security #6) | High | `rules.py` evaluates the agent policy booleans against the tool-manifest diff: new allowed write tool / outbound tool / policy-flag escalation → deterministic `BLOCK` findings |
| 4 | Evidence freshness and revision binding never enforced (Security #4) | High | `stale` evidence or evidence observed at another revision → `INCOMPLETE`; `unknown` freshness → `WARN` |
| 5 | No runner existed; `command_ref` resolved to nothing (Security #5, Architecture #4) | High | `runner/allowlist.py` + `subprocess_runner.py`: allow-listed executables and static argv patterns, no shell, CWD containment, timeouts, redacted/truncated output, per-check artifacts with digests |
| 6 | `passed` without proof was satisfiable with invented strings (Security #1) | Critical | A mandatory `passed` check now requires verifiable on-disk artifacts whose SHA-256 matches the recorded digest; missing/mismatched artifacts → `INCOMPLETE` |
| 7 | No digest algorithm specified (Architecture B.1) | High | `digest.py` + section A.1 below: SHA-256 over canonical JSON; Merkle tree digest for check inputs |
| 8 | Change intake missing; no diff digest, no revision binding (Architecture #1) | Critical | `intake/git_diff.py`: base/head resolution, name-only diff, deterministic diff digest, `read_at_revision` for baseline comparison; content-digest fallback with an explicit `unversioned_source` gap when no VCS exists |
| 9 | No adapters (Architecture #2) | Critical | `python_ast.py` (functions/classes/API endpoints, resolved calls/imports, dynamic-dispatch gaps), `dbt_manifest.py` (models/columns/sources/edges, undeclared-SQL gaps), `agent_config.py` (tools/model binding/policy flags/prompts + head-vs-base privilege diff) |
| 10 | No impact resolver or gap registry (Architecture #3) | Critical | `graph/traverse.py`: policy-scoped traversal (per relation type and direction, max 4 hops), impact paths, `unknown_critical_impact` derived from unresolved edges and evidence-free critical assets |
| 11 | CLI lacked `analyze`/`verify`/`report` (Architecture #6) | Critical | Full `analyze → verify → decide → report` chain plus `run`; `--output` writes are contained to repo/artifact roots (Security #11) |
| 12 | No secret redaction on output paths (Security #8) | Medium | `redact.py` applied to stdout, JSON files, artifacts, and check log excerpts |
| 13 | Bundle never bound the check catalog (Architecture B.2) | Medium | `check_catalog_digest` in the bundle; a changed catalog after planning → `INCOMPLETE` |
| 14 | Report injection unmitigated (Security #9) | Medium | `reporting/markdown.py` escapes control characters, `<`/`>`, pipes, and truncates every untrusted cell |
| 15 | Sample app incomplete: no dbt manifest, no agent module, no contract/agent checks (Architecture A.10) | High | Added `data/dbt/manifest.json`, `agents/replenishment/agent.py`, `tests/contract/`, `tests/agent/`, `config/commands.json`, `conftest.py`; sample app is now a committed Git baseline |
| 16 | Planner emitted malformed gaps (blocking as string, no `gap_id`) (Security #3) | Medium | Planner gaps now carry `gap_id`, `why_it_matters`, boolean blocking, and a budget-exhausted gap is emitted whenever optional checks are skipped |

**Test evidence:** 37 tests pass (`pytest -q`), including hardening tests for forged digests, requirement downgrades, stale/cross-revision evidence, missing artifacts, allow-list refusals, and four end-to-end scenarios (safe change → `PASS/WARN`, write-tool escalation → `BLOCK`, column rename → contract `BLOCK`, unavailable mandatory check → `INCOMPLETE`).

---

## 3. Gap register: deferred (documented, not silently dropped)

| # | Gap | Why deferred | Recommended next step |
|---|---|---|---|
| D1 | Catalog is modifiable by the PR under review (Security #3) | Requires CI-side pinning | Pin `check_catalog_digest` in a trusted location (release config or CI variable) and refuse when the PR changes it; CODEOWNERS on `config/` |
| D2 | Working tree vs. committed revision divergence | MVP reads the head working tree while intake binds to commits | Analyze a `git worktree` checked out at `head_revision` so every layer reads the same bytes |
| D3 | Runner isolation (containers, network egress deny, rlimits) (Security #10) | Needs CI plumbing | Ephemeral runner, no secrets for fork PRs, network namespace deny; add `.github/workflows/clca.yml` with `permissions: contents: read` on `pull_request` (not `pull_request_target`) |
| D4 | Benchmark is still a catalog, not a runnable harness (Benchmark P0s) | Large build; honesty requires redesign first | Give each scenario a real patch + seeded fault + hand-frozen oracle suite; split labels into an evaluator-only file; add an abstention/coverage metric; pre-register configuration C's pilot; Wilson intervals with raw numerator/denominator |
| D5 | Mitigation/auto-fix (architecture §8) | Product review: cut it | Revisit only if the core gate lands cleanly |
| D6 | External adapters (DataHub/OpenLineage/OWASP harness) | Explicitly out of hackathon scope | One adapter after a licensing and pilot review |
| D7 | Live-LLM agent evals and repeated-trial statistics | Deterministic mock only in MVP | Keep deterministic assertions; add pinned-model repeated trials as a separate, clearly-labeled result stream |
| D8 | `schemas/evidence-bundle.schema.json` is stale vs. models | Pydantic models are the working source of truth | Regenerate the JSON Schema from the v0.3 models |

---

## 4. Architecture addendum (normative)

### A.1 Digest specification

- **Algorithm:** SHA-256, rendered as `sha256:<64 lowercase hex>`.
- **Canonical JSON:** UTF-8, sorted keys, separators `(",", ":")`, non-ASCII preserved.
- **Tree digest** (check `input_digest`): sorted `relative/path\tsha256:<hash>` lines for every file under the repository root, excluding `.git`, `.venv`, `node_modules`, `__pycache__`, `artifacts`, `.pytest_cache`.
- **`policy_digest`** = SHA-256 of canonical JSON of the loaded `policy.json`.
- **`check_catalog_digest`** = SHA-256 of canonical JSON of the loaded catalog.
- **`bundle_digest`** = SHA-256 of the bundle with `bundle_digest` and `created_at` removed; recomputed after any mutation and verified on `decide`.

### A.2 Trust model

Trusted inputs (version-controlled, loaded by the orchestrator): `policy.json`, `check_catalog.json`, `commands.json`.
Untrusted inputs (may derive from pull-request content): repository files, agent manifests, prompts, and the evidence bundle as an artifact. `decide()` therefore re-derives requirements from the catalog, verifies the policy digest, verifies the bundle digest, and verifies artifact hashes on disk. Bundle-declared fields never widen permission.

### A.3 Known limitations of v0.3

1. Intake binds to committed revisions; adapters read the working tree. Keep them in sync or expect the mismatch to show up as revision-bound evidence against a stale diff (D2).
2. Python call resolution is intra-repository by bare name; cross-module dynamic calls are recorded as gaps, not guessed.
3. The metadata-probe simulator (architecture §6) is not implemented; no live probe occurs.
4. The runner executes in-process via `subprocess` with a reduced environment; it is not yet container-isolated (D3).
