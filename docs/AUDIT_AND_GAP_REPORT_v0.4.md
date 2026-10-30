# CLCA MVP v0.4 — Repository Audit and Gap Report

**Audit scope:** uploaded `clca_mvp.zip`, reviewed against `docs/MVP_ARCHITECTURE_v0.2.md`, `docs/ARENA_REVIEW_AND_GAP_REPORT_v0.3.md`, the benchmark manifest, the runner/policy/CLI/service code, UI, and GitHub Actions workflow.

**Result:** concrete correctness and trust-boundary changes were made. The result is still a hackathon-grade reference implementation, not a production security gate or sandbox. All claims below distinguish implemented code from planned work.

## 1. What the repository already contained

The uploaded project was materially beyond a UI mock-up. It already contained:

- Git diff intake with revision/diff digests;
- native Python AST, dbt-manifest, and agent-configuration adapters;
- typed assets, relationships, evidence records, coverage gaps and a cross-layer impact resolver;
- a rule-based policy engine and budget-based check planner;
- an allow-listed subprocess runner, output redaction and on-disk artifacts;
- a CLI pipeline (`analyze → verify → decide → report`);
- a demo HTTP service, graph API, DOT output and browser console;
- an evidence bundle and policy/catalog digest checks;
- a benchmark *catalog* with 48 proposed scenarios;
- CI/container/deployment documentation and a considerable existing test suite.

This was the correct foundation. The major issues were not lack of modules; they were inconsistencies between claims and enforcement, weak trust boundaries, a couple of misleading demo paths, and scale/benchmark gaps.

## 2. Fixes applied in this audit

### A. Evidence and policy integrity

1. **Artifact-root escape prevented.** The CLI no longer lets an untrusted evidence bundle nominate an arbitrary host artifact path. A path outside the repository requires an explicit operator-provided `--artifacts-root` override.
2. **Artifact proof must include a digest.** Artifact verification now rejects absent or malformed SHA-256 digests instead of treating file existence as proof.
3. **Artifact path sanitization and containment.** Run IDs and artifact names are normalized and the resolved target is checked against the store root before writing. This reduces traversal and symlink escape risk; it is not a formal defense against every possible local filesystem race.
4. **Catalog binding is mandatory.** A missing or mismatched check-catalog digest makes the decision `INCOMPLETE`.
5. **Planner output is independently re-derived.** The policy engine regenerates the expected selection from the loaded catalog and recorded plan inputs, then checks for omitted/unexpected checks and mismatched `required_check_ids`.
6. **Every `PASSED` claim needs proof.** This includes optional checks: successful exit code, duration, well-formed input/environment digests, artifact references, matching digest keys, and successful on-disk artifact verification.
7. **Executable path spoofing blocked.** The allow-list now accepts only bare executable names; `/some/path/python` and `./python` cannot pass just because their basename is allow-listed.
8. **Python runner pinned to active interpreter.** `python` and `pytest` command entries run through `sys.executable`; pytest plugin autoload is disabled for checked subprocesses to reduce hidden plug-in side effects.
9. **Subprocess timeout cleanup improved.** On POSIX, a timed-out check terminates its process group, not just the immediate child. Windows currently kills the direct child as a best-effort fallback; Windows Job Object containment is still needed for equivalent descendant control.
10. **Untrusted report text redacted.** Markdown output is redacted before printing and writing, not only when stored in a JSON artifact.

### B. Revision consistency

11. **Dirty/mismatched checkout rejected.** Git-backed analysis checks that the checked-out `HEAD` equals the requested analysis head and refuses a dirty source tree (excluding generated paths). This addresses the mismatch where the diff was computed from commits but adapters/tests read different bytes from the working tree.
12. **Portable sample repository setup.** Added `scripts/prepare_sample_app.py` to create a local-only Git baseline if the sample ZIP has no `.git` directory. It detects when `sample_app/` is merely inheriting the outer repository's Git root and creates a nested sample repository; it never adds a remote or creates a new baseline over an existing sample `HEAD`.
13. **Generated sample files ignored.** Added `sample_app/.gitignore` for Python caches, pytest cache, artifacts and environment files.

### C. Demo and GitHub trust boundaries

14. **Synthetic demo results cannot certify a real PR.** The webhook demo no longer posts a result from a built-in synthetic scenario to the PR's GitHub Checks API, even when `GITHUB_TOKEN` is set. Responses identify themselves as `demo_only`.
15. **Unknown and mixed path sets are not green.** An empty path list, unrecognized path, or PR spanning more than one demo scenario returns `unknown_change` instead of being mapped to a benign scenario.
16. **Fixture oracle hidden before running.** The scenario picker no longer exposes `expected_decision` in the pre-run listing. The expected fixture result can still appear after execution for demo self-consistency.
17. **Workflow downgraded to safe self-validation.** `.github/workflows/clca.yml` now has `contents: read`, disables persisted checkout credentials, runs unit tests/manifest validation/sample checks/CLI smoke, and does not publish a GitHub Check Run. It explicitly is **not** a PR release gate. This avoids allowing the same PR-controlled source/policy/workflow to certify itself with a write-capable token.

### D. Scenario realism and graph performance

18. **Data regression edits the SQL and manifest.** The column-rename scenario now changes both the SQL model and dbt manifest while leaving the consumer contract unchanged, rather than only editing metadata.
19. **Prompt regression added.** `prompt_behavior_regression` removes a required `evidence_refs` contract from the prompt and verifies that the deterministic behavior suite catches it. This is a deterministic contract regression fixture, not a live-LLM statistical benchmark.
20. **Cycle metric is bounded.** Removed unbounded enumeration of every simple cycle. The graph now reports whether a cycle exists and one representative cycle. For cyclic graphs, `cycle_count` is a lower bound (`>=1`), not a fabricated exact count. Betweenness centrality is exact up to 500 nodes and uses a deterministic fixed-size sample above that; the method is reported.
21. **Schema refreshed.** `schemas/evidence-bundle.schema.json` was regenerated from the current Pydantic models.
22. **Version/docs updated.** Package metadata and runtime provenance were bumped to `0.4.0`, and README/workflow guidance was clarified.

## 3. Validation performed

The following validations were run in the editing environment:

- Python bytecode compilation for `src`, `tests`, and `scripts` — passed.
- Focused hardening suite — passed during development, including policy, allow-list, artifact, GitHub mapping, sample-repo setup, graph metrics and CLI security tests.
- All **124 collected tests passed** (1 POSIX-specific runner-cleanup test skipped on Windows; expected to pass on Linux), executed in three groups to stay within the local command runtime limit: core suite **102 passed**, CLI end-to-end suite **5 passed**, HTTP service suite **17 passed**. These groups together cover the complete test collection; the tests were not run in one single pytest process.
- Benchmark manifest validation — **48 scenarios**, 12 per family.
- Planner-to-manifest diagnostic — **40/48 selections aligned, 8 mismatches reported**. The exact mismatch list is persisted at `benchmark/results/planner_alignment_v0.4.json`; this is a concrete remaining planner/benchmark consistency gap, not a regression-detection benchmark.
- End-to-end CLI smoke: a portable sample repository without `.git` was initialized; a clean run produced `PASS`; after adding and committing an allowed write-tool grant, the decision was `BLOCK`.
- All six synthetic demo scenarios returned their hand-authored expected outcomes. This is only a self-consistency check against the same fixtures/rules, not independent validation.
- Prompt-behavior regression scenario — passed its test (the change was blocked by the required agent behavior suite).

The final code was compiled after the last intake changes; targeted intake tests passed. The complete test collection has been covered by the three successful groups above.

## 4. Findings that remain open

The following are not implemented by v0.4 and must not be represented as finished features.

### P0 — Required before a real security/release gate

- **No OS/container sandbox for untrusted test code.** The runner uses subprocess limits and a reduced environment; it does not provide a hardened filesystem/network/credential boundary. Use ephemeral isolated runners or containers with network egress denied where possible. Windows needs Job Objects or stronger isolation.
- **The GitHub workflow is self-validation only.** It does not gate the PR's own merge. A production gate should use a separately trusted/pinned workflow or reusable workflow, protected policy/catalog/command definitions, no secrets in the untrusted execution job, and a narrowly privileged reporting job that validates the exact evidence artifact before publishing a Check Run. Do not solve this by checking out and executing untrusted PR code inside `pull_request_target`.
- **A bundle self-digest is not an authenticity signature.** An actor able to rewrite the bundle can recompute an unkeyed hash. Production evidence needs trusted-runner provenance, a signed/attested artifact or an equivalent protected channel, and decision-to-commit binding. Current hashes detect inconsistency/tampering only when the expected digest is independently trusted.
- **Policy/catalog still need a trusted source.** Current CLI checks local files against digests embedded in the generated bundle; it does not by itself protect a production PR gate from the PR changing its own source, policy, catalog or command definitions.

### P1 — Needed to substantiate the core product differentiation

- **Eight scenario check-selection contracts do not match the current planner.** The v0.4 diagnostic identifies `S016`, `S022`, `S032`, `S033`, `S038`, `S042`, `S044`, and `S048`. This is why the target manifest is retained as a contract and not auto-corrected to current behavior. Resolve each case by deciding whether the planner/catalog is missing a safety check or the benchmark's expected selection is wrong.
- **Benchmark is still a catalog, not a runnable comparative harness.** `benchmark/scenarios/scenarios.json` defines cases, but there is no orchestrator that runs all scenarios against baseline CI/native selector/competitor/static CLCA/integrated CLCA and emits `raw_scenario_results.jsonl` plus summary metrics.
- **External-tool adapters are not integrated.** No production adapters exist yet for AxiomCode, Enola, Farol, Code System Graph, DataHub, OpenMetadata or OpenLineage. Current adapters are native local parsers/manifest readers.
- **No live dynamic lineage probe.** The MVP consumes checked-in dbt-like metadata and code/config parsing. It does not query a live database/catalog to discover missing lineage. Any future probe must be metadata-only, read-only, target-allowlisted and credential-isolated.
- **No generated mitigation PR workflow.** The current product does not produce a proposed fix. Add only as a proposal in a temporary worktree, require human approval, and rerun mandatory checks before offering a patch; never auto-push or auto-merge by default.
- **No semantic prompt diff or statistical model-behavior comparison.** The new scenario is a deterministic text-contract regression. For real agent/model changes, use a fixed evaluation corpus plus repeated trials, explicit assertions/thresholds and an inconclusive state when sample evidence is insufficient. Embedding similarity must not be allowed to skip mandatory checks.
- **Planner is priority/estimate driven, not a calibrated risk optimizer.** It honors mandatory checks and can skip optional checks under budget, but check priority and duration estimates are declared catalog values. No measured risk model justifies numeric “zero regression risk” claims.

### P2 — Reliability and product maturity

- Add multi-repository asset identity and versioned relationship contracts.
- Add richer provenance for the compiler/parser/catalog producer itself, including tool binary/config digests.
- Ensure file-content collection is strictly from an immutable checkout/worktree derived from the requested head (the new dirty/head guard improves this but does not create a separate immutable worktree).
- Add schema migrations, history persistence, retention and resource quotas if the service becomes multi-user. Current HTTP run history is in-memory.
- Add rate limiting/authentication for any reachable service deployment. It should not be exposed publicly as-is.
- Add a real action/plugin architecture for language/data/agent check adapters and validate each adapter's coverage separately.
- Keep browser-facing asset strings escaped; add a browser security test suite and a CSP if the service is deployed beyond local demo use.

## 5. Important benchmark rules

Never claim “X% time saved with 0% regression risk” from the current fixture set. That is not mathematically supportable from a finite seeded suite. Report raw counts and coverage along with:

- failure-revealing test recall against a declared full-suite oracle;
- seeded regression detection rate;
- false-block rate on safe changes;
- evidence completeness and decision soundness;
- wall time/test runtime and cost per change;
- unsupported scenario count for every baseline tool;
- all cases where the full suite cannot establish ground truth.

Keep baseline CI, native selection, relevant existing tool, static-only CLCA and integrated CLCA on the same repository snapshots and scenario labels. Do not compare numbers from different datasets as if directly comparable.

## 6. Next work in priority order

1. Build a runnable benchmark harness around the 48 scenario manifest and publish raw outputs.
2. Move the CI trust boundary out of the PR-controlled workflow and add an isolated runner; keep reporting permissions separate from test execution.
3. Implement the normalized evidence adapter contract and at least one real cross-layer source per layer (code, data and agent config).
4. Add repeat-run AI evaluation with statistical reporting and an explicit inconclusive state.
5. Add human-approved mitigation patches in disposable worktrees, followed by mandatory revalidation.
6. Only then add more graph visualization, LLM summarization or broader language support.

## 7. Product verdict

CLCA has a sound direction: **change-aware, evidence-backed verification across code, data and agent configuration**. The meaningful value is not the graph itself; it is a reproducible, policy-governed decision and proof record. v0.4 hardens several real implementation flaws and improves demo credibility, but it is not yet safe to market as a production security gate or claim comparative productivity gains. The benchmark runner and trusted execution architecture are the two highest-value remaining deliverables.
