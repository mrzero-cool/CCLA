# CLCA Production Readiness Gap Analysis

Source: CLCA v0.4 source tree + CLCA_Production_Readiness_Roadmap_v1.0.md
Status: Prototype — not yet safe as an authoritative production merge gate

## Executive Summary

CLCA v0.4 is a validated prototype (124 tests passing, 48 benchmark scenarios,
8 planner mismatches documented). The remaining gap to production is not more AI
or better visualization — it is **trustworthy execution boundaries, authenticated
evidence, durable state, and a separate trusted control plane**.

The roadmap defines five stages. v0.4 sits between Stage 0 (contract definition)
and Stage 1 (correctness/reproducibility). Everything from Stage 2 onward is
missing.

---

## P0 — Release Blockers (must close before any authoritative production gate)

### 2.1 Isolate Untrusted Execution

| Requirement | v0.4 State | Gap | Production Implementation |
|---|---|---|---|
| Fresh sandbox per run | Local `tempfile.mkdtemp` copy of sample_app | No isolation; host OS is the boundary | Ephemeral VM/microVM (gVisor/Kata) or hardened container per run |
| No host Docker socket / mounts / secrets | N/A (not implemented) | Full gap | Sandbox with no socket mounts, no SSH agent, no cloud creds |
| Default-deny outbound network | N/A | Full gap | Egress-deny firewall; controlled package proxy for deps |
| Read-only base FS, unprivileged UID, dropped caps | N/A | Full gap | Read-only root, explicit writable work dir, seccomp/AppArmor |
| CPU/memory/disk/PID/wall-clock quotas | `budget_seconds` hint only (not enforced) | Partial | Hard cgroup/ulimit quotas enforced by sandbox runtime |
| Process-tree termination on crash/cancel | Worker `finally` releases slot only | Partial | Kill process group; reap orphans; cleanup on disconnect |
| Image pinned by digest | N/A | Full gap | Digest-pinned runner image; no `latest` |
| Sandbox escape / timeout tests | None | Full gap | Seeded attack tests run in CI |

**Acceptance criteria (missing):** seeded test suite must not read control-plane
secrets, access host socket, reach non-approved network, persist files between
runs, exceed limits without termination, or leave processes after cancellation.

### 2.2 Separate PR Code from Trusted Control Logic

| Requirement | v0.4 State | Gap | Production Implementation |
|---|---|---|---|
| Policy/catalog in trusted protected source | Reads `--policy/--catalog` from PR checkout | PR can neuter its own gate | Org-owned service/reusable workflow pinned to immutable SHA |
| PR source treated as untrusted input | Partial (webhook maps to built-in scenarios only) | CI mode reads PR config | Banner step exists; full base-pinning is future work |
| No `pull_request_target` with write perms | N/A | Full gap | Separate reporter identity; sandbox gets no GitHub write token |
| Webhook HMAC + delivery dedup | Implemented (body-digest keyed) | Verified | Keep; add per-installation quotas |
| Third-party Actions pinned by SHA | Not pinned | Full gap | Pin all actions to full SHAs; org-level allowed-actions lock |
| Branch protection requires expected App identity | N/A | Full gap | Enforce check from expected GitHub App identity |

### 2.3 Make Evidence Authentic, Immutable, Commit-Bound

| Requirement | v0.4 State | Gap | Production Implementation |
|---|---|---|---|
| SHA-256 bundle digest | Implemented (sealed digest) | Digest only proves bytes match | Add trusted signing/attestation |
| Tenant, repo, PR, delivery ID in evidence | Partial (context captured) | Incomplete | Full evidence envelope per roadmap §2.3 |
| Base/head commit, tree hash, source digest | Partial (head only) | Missing base binding | Exact base+head+tree hash in every bundle |
| Policy/catalog/command/adapter/runner digests | Partial (policy+catalog digests) | Missing adapter/runner digests | Bind all versions into evidence |
| Artifact URI + SHA-256 | Partial | Incomplete | Every artifact referenced with digest |
| Sign/attest with trusted workload identity | **None** | Full gap | in-toto/SLSA-compatible provenance; credential unavailable to test process |

**Acceptance criteria (missing):** altering any critical evidence field, swapping
commit SHA, changing policy version, replacing artifact, changing runner identity,
or replaying after new commit must invalidate verification.

### 2.4 Bind Analysis to Immutable Repository State

| Requirement | v0.4 State | Gap | Production Implementation |
|---|---|---|---|
| Controlled checkout of exact base/head | Git diff between commits | Adapters may read working tree | Immutable detached worktree per run |
| Content hashes for inspected files | Partial | Incomplete | Hash every file actually inspected |
| Diff-base validation for merges/rebases | None | Full gap | Validate merge/rebase commit identity |
| Submodule/LFS policy | None | Full gap | Explicit support-or-incomplete policy |
| Symlink/path normalization | None | Full gap | No path traversal; no reading outside workspace |
| Recheck identity before/after validation | None | Full gap | Verify HEAD matches requested; INCOMPLETE/BLOCK on mismatch |

### 2.5 Fix Benchmark/Planner Contracts

| Requirement | v0.4 State | Gap | Production Implementation |
|---|---|---|---|
| Resolve 8 planner mismatches (S016, S022, S032, S033, S038, S042, S044, S048) | Documented, not resolved | Full gap | Review each; add regression test per resolution |
| Runnable benchmark harness | Catalog only (`benchmark/scenarios/scenarios.json`) | No orchestrator | Harness runs all scenarios, emits JSONL + summary metrics |
| Ground-truth oracle | Hand-authored fixture expectations | Not independent | Independent oracle; versioned; separate from planner |

### 2.6 Secure the API Before Network Exposure

| Requirement | v0.4 State | Gap | Production Implementation |
|---|---|---|---|
| SSO/OIDC (Microsoft Entra ID) | **No auth** (explicit demo choice) | Full gap | Entra ID / enterprise IdP |
| RBAC (viewer, developer, repo admin, policy admin, auditor) | None | Full gap | Role-based access on every endpoint |
| Tenant-scoped authorization | None | Full gap | Tenant binding on runs/reports/artifacts |
| Rate limits, concurrency quotas, body/graph-depth limits | Admission cap (3 runs) only | Partial | Full rate limiting + pagination |
| TLS, CORS, CSP, CSRF, output encoding | Basic headers only | Partial | Harden for public exposure |
| Webhook signature + replay + dedup | Implemented | Verified | Keep; add per-installation quotas |
| No secrets/prompts/customer data in logs | Redaction implemented | Verified | Keep; extend to all telemetry |

---

## P1 — Build a Real Product

### 3.1 Durable Workflow (replace in-memory state)

| Component | v0.4 State | Production Target |
|---|---|---|
| API | stdlib `ThreadingHTTPServer` | FastAPI/ASGI with auth middleware |
| Database | In-memory `_RUNS` dict (MAX_HISTORY=100) | PostgreSQL: users, tenants, runs, policy versions, assets, edges, findings, audit |
| Queue | None (inline threads) | Azure Service Bus / Redis / DB-backed queue |
| Workers | Single daemon thread per run | Separate planner workers + isolated execution workers |
| Object storage | Local `artifacts/` dir | Azure Blob / S3-compatible |
| Migrations | None | Alembic; tested on anonymized prod schema copy |
| Idempotency | Delivery dedup only | Run key = repo + head SHA + policy + catalog + workflow config |
| Lifecycle state | running/completed/failed | QUEUED, RUNNING, SUCCEEDED, FAILED, CANCELLED, TIMED_OUT |

### 3.2 Change Evidence Model (typed graph)

Current v0.4 graph: generic source/target strings only.

Production asset classes:
- **Code:** repository, package, module, function, class, API route, test
- **Data:** source, catalog, schema, table, column, dbt model, metric, dashboard
- **AI:** agent, prompt version, model binding, tool manifest, tool permission, eval corpus, policy
- **Runtime:** job, deployment, service, owner, environment

Relationships: CALLS, IMPORTS, READS_TABLE, READS_COLUMN, WRITES_TABLE, DERIVES_FROM,
EXPOSES_API, CONSUMES_API, REFERENCES_PROMPT, GRANTS_TOOL, EVALUATED_BY, DEPLOYED_AS

Every edge: source/provenance, parser version, commit/catalog snapshot, observed time,
freshness rule, confidence, inferred vs observed flag. Preserve conflicting edges.

### 3.3 Adapter Contracts

| Contract Method | v0.4 State | Production |
|---|---|---|
| `discover_assets(snapshot)` | Native Python AST + dbt manifest | Stable contract with provenance |
| `discover_relationships(snapshot)` | Basic traversal | Typed relationships + confidence |
| `changed_assets(diff)` | Git diff | Immutable snapshot diff |
| `coverage_report()` | Coverage gaps present | Explicit gaps for unsupported languages |

First production pilot: one real adapter per layer (code, data, AI), not ten shallow ones.

### 3.4 Planner: Measurable and Explainable

- Mandatory checks unconditional; budget ranks/defers optional only
- If required checks can't complete → INCOMPLETE, never skip
- Duration estimates calibrated from actual observations + uncertainty
- Transparent rules first; no opaque risk model until labeled history exists

### 3.5 Safe Dynamic Lineage Probing

- Query approved metadata API or dbt/catalog snapshot first
- Read-only identity against allow-listed host/db/schema only
- No arbitrary SQL from PR; no data-value retrieval by default
- Query timeouts, quotas, audit logging, deny-by-default network

### 3.6 AI/Agent Regression Evaluation

- Corpus version + provenance; baseline model/provider/version
- Exact schema + policy assertions before semantic judge scores
- Repeated trials + confidence intervals + explicit inconclusive
- Cost/latency budget per eval; cache keys include all behavior-affecting digests
- Prompt injection, data disclosure, excessive agency, supply chain, unbounded consumption tests
- Model outage/rate-limit → INCOMPLETE, not pass

### 3.7 Human-Approved Mitigation (later feature)

Proposal-only patch generation; human approval; isolated worktree; full mandatory
revalidation; no auto-push/merge by default.

---

## P1 — Runnable Benchmark and Evidence of Value

### 4.1 Turn 48 Scenarios into a Harness

- Materialize each scenario as immutable snapshot/patch with expected outputs
- Run: baseline full CI, native test selection, existing tool, CLCA static-only, CLCA integrated
- Capture JSONL: tool/version, commit digest, selected checks, mandatory checks, run time, CPU/RAM, cost, failures, precision/recall, skipped checks, decision
- Redact secrets; cap output size
- Retry/flaky classification without cherry-picking
- HTML/Markdown summary + raw machine-readable results
- Record unsupported cases per competitor; don't count unsupported as failure
- Pin environment images + dependencies; one-command reproducer

### 4.2 Metrics

- Failure-revealing test recall vs full-suite oracle
- Seeded regression detection rate
- False-block rate on known-safe changes
- Impact path precision/recall vs manual ground truth
- Mandatory-check omission rate (must be zero)
- Evidence completeness + incorrect-PASS rate (must be zero for enforced invariants)
- p50/p95 planner latency; total wall time
- Check minutes, compute cost, model cost per change
- Timeout/failure/flaky rate; unsupported/unknown percentage

### 4.3 Pilot Acceptance Gates

- Zero cases where missing mandatory evidence/commit mismatch/unauthenticated result → PASS
- Zero critical permission/policy escalations missed in seeded security corpus
- Zero unexplained planner-manifest mismatches
- No cross-tenant data access in security test suite
- ≥95% failure-revealing test recall, ≤5% false-block rate (raw x/y reported)
- Time/cost improvement vs full suite (no generalization claims)
- Signed, commit-bound evidence bundle for every enforced decision

---

## P2+ — Remaining Items

P2: Durable data model (tenant, user, run, asset, relationship, policy, check, evidence, audit),
versioned REST/OpenAPI API, idempotency keys, pagination, SSE/websocket progress,
signed URL artifact access, admin endpoints.

P2 Observability: OpenTelemetry traces/metrics/logs; correlated spans per run; SLOs
(99.9% API availability, p95 ≤10s intake+planning, no silent stuck jobs).

P2 Reliability: DB backups + PITR + restore drills; queue DLQ + poison-job handling;
per-tenant quotas; rolling deploys; runbooks.

P2 Supply Chain: pinned deps with hashes; digest-pinned images; SBOM; dependency/secret/IaC
scan; build provenance; fuzz input parsers; threat model; NIST SSDF mapping.

---

## Azure Production Reference Architecture

Control plane: Container Apps/App Service API + Entra ID + PostgreSQL + Service Bus +
Blob Storage + Key Vault + managed identities + ACR image scanning + Monitor/Application Insights.

Execution plane: Separate subscription/RG; ephemeral isolated runner VMs/microVMs;
controlled egress gateway/package mirror; scoped result-upload (no GitHub write, no cross-tenant reads).

Trusted reporting plane: Separate identity with minimal GitHub App permissions; reads signed
evidence only; never executes PR code.

---

## Go-Live Checklist (from roadmap §14)

1. Supported language/framework scope explicit
2. Exact base/head commit + file-tree hashes verified
3. Mandatory checks from trusted catalog/policy, not PR-controlled
4. Eight planner mismatches resolved with tests
5. Benchmark runner produces raw results + reproducible metrics
6. Execution isolated, ephemeral, resource-limited, default-deny network
7. Runner has no GitHub write token or production credentials
8. Evidence signed/attested by trusted identity + independently verified
9. Commit/policy/catalog/tool/runner versions bound into evidence
10. GitHub reporter has minimal write perms, never executes PR code
11. SSO/RBAC/tenant boundaries + API abuse tests pass
12. Durable DB/queue/artifact store + retention + backups + restore tests
13. Structured logs/traces/metrics/alerting/redaction implemented
14. Deps/container/GitHub Actions pinned/scanned; SBOM/provenance
15. Incident response/runbooks/ownership/emergency bypass documented
16. Pilot in shadow/advisory mode before blocking enabled
17. No "zero regression risk" claim; published claims include dataset + numerator/denominator + limitations