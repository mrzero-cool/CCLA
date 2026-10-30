# CLCA Linked Tools Catalog

External reference projects and integrations that CLCA is designed to work alongside.
CLCA does **not** rebuild these — it provides the normalized evidence contract, policy
engine, planner, and trusted verification plane that connects them.

Categories: Code Impact Graphs · Data Lineage · Agent/AI Security · Benchmark Oracles · Observability

---

## 1. Code Impact Graphs (ingest into CLCA change evidence model)

| Tool | Repo | What it produces | CLCA integration point |
|---|---|---|---|
| **impactgraph** | https://github.com/sumit-gupta03/impactgraph | Source-code impact analysis; changed-atom → affected-consumer mapping | `discover_relationships()` for code layer; edges typed CALLS/IMPORTS/EXPOSES_API |
| **AxiomCode Graph** | https://github.com/AxiomCodeAI/axiomcodegraph | Compiler-grounded code impact + test selection | Mandatory-check selection hints; `python-unit-tests` targeting |
| **Enola** | https://github.com/enola-labs/enola | Multi-repository architecture graph | Cross-repo dependency edges; DEPLOYED_AS / CONSUMES_API relationships |
| **Code System Graph** | https://github.com/dertin/code-system-graph | Language-agnostic code system graph | Canonical asset IDs; inferred-vs-observed edge flags |
| **Farol** | https://github.com/winnin/farol | Code risk triage + change impact | Risk scoring inputs for planner; change-type classification |

**Integration pattern:** Each external graph adapter implements `discover_assets(snapshot)`,
`discover_relationships(snapshot)`, `changed_assets(diff)`, `coverage_report()`. Every
returned fact carries provenance + source version. Optional and version-pinned; CLCA
works with native Python AST adapter if an integration is unavailable, but degraded
coverage affects the decision.

---

## 2. Data Lineage & Catalog (ingest into CLCA data layer)

| Tool | Repo | What it produces | CLCA integration point |
|---|---|---|---|
| **DataHub** | https://github.com/datahub-project/datahub | Data catalog + lineage + metadata API | `READS_TABLE` / `WRITES_TABLE` edges; freshness metadata |
| **OpenMetadata** | https://github.com/open-metadata/OpenMetadata | Centralized metadata + lineage | Schema/table/column asset discovery |
| **OpenLineage** | https://github.com/OpenLineage/OpenLineage | Job + dataset lineage events | Runtime job/deployment edges; observed-time timestamps |
| **dbt manifest** | (in-repo `data/dbt/manifest.json`) | dbt model → table/column lineage | `data-contract-tests` mandatory check; column-rename scenarios |

**Integration pattern:** Dynamic lineage probe (P1 §3.5) queries an approved metadata API
or dbt/catalog snapshot using a read-only, allow-listed principal. No arbitrary SQL from a
PR; no data-value retrieval by default. Missing/stale edges → coverage gaps → INCOMPLETE
or WARN, never silent empty graph.

---

## 3. Agent / AI Security Regression (ingest into CLCA AI layer)

| Tool | Repo | What it produces | CLCA integration point |
|---|---|---|---|
| **OWASP Agent Security Regression Harness** | https://github.com/OWASP/Agent-Security-Regression-Harness | Agent behavior/security eval scenarios | `agent-behavior-evals` / `agent-security-smoke` mandatory checks |
| **Prompt injection test packs** | (CLCA-defined policy packs §10) | Indirect prompt injection, data disclosure, excessive agency | AI-specific validation plug-in; repeated trials + confidence intervals |
| **Model/tool supply-chain scanners** | (org-defined) | Unpinned endpoints, dependency changes | Supply-chain change detection; INCOMPLETE on outage/rate-limit |

**Integration pattern:** AI eval runner is a separate plug-in with corpus version +
provenance, baseline model/provider/version, system-prompt digest, tool-manifest digest,
inference settings. Embedding similarity is triage only — never suppresses mandatory
security/prompt-change evaluations.

---

## 4. Benchmark Oracles (CLCA benchmark harness, P1 §4.1)

| Baseline | What it measures | CLCA comparison mode |
|---|---|---|
| Full applicable CI suite | Ground-truth failure detection | `failure_revealing_test_recall` |
| Native test selector | Test-selection efficiency | `test_runtime_reduction` |
| Best applicable existing tool | Competitor detection rate | Precision/recall vs manual ground truth |
| CLCA static-only | Static analysis contribution | Isolated CLCA value |
| CLCA integrated | Full pipeline | End-to-end decision soundness |

Harness output: `raw_scenario_results.jsonl` + `summary_metrics.json` +
`coverage_and_limitations.md`. All 48 scenarios in `benchmark/scenarios/scenarios.json`
must run against identical snapshots with pinned environment images.

---

## 5. Observability & Supply Chain (production operations)

| Category | Tools / Standards | CLCA requirement |
|---|---|---|
| Tracing | OpenTelemetry (traces, metrics, logs) | Correlated spans: webhook → snapshot → adapter → graph → planner → check → bundle → verify → report |
| Metrics | Prometheus-compatible | Queue depth, run success/failure/timeout rates, check duration/cost, verification failures, planner drift |
| Alerting | PagerDuty-compatible | SLO breaches: 99.9% API availability, p95 ≤10s intake+planning |
| Supply chain | pip hash-locking, digest-pinned images, SBOM, Cosign/Sigstore | Reproducible installs; image signing; build provenance; dependency/secret/IaC/SAST/license scan |
| Threat model | NIST SSDF (SP 800-218), OWASP GenAI/agent guidance | Data-flow diagram, asset inventory, security contact, vuln disclosure, incident response |

---

## 6. How CLCA Connects Them (production data flow)

```
PR event (GitHub webhook)
    │
    ▼
[Control Plane]  AuthZ → Policy (trusted, version-pinned) → Run record (idempotent)
    │                                              │
    │                                              ▼
    │                                      [Execution Plane]
    │                                              │
    │                                              ▼
    │                                      Ephemeral sandbox (gVisor/Kata)
    │                                              │
    │                                              ▼
    │                                      Immutable base/head snapshot
    │                                              │
    │                                              ▼
    │                                      Adapters (code/data/AI)
    │                                              │
    │                                              ▼
    │                                      Typed change graph (assets + relationships)
    │                                              │
    │                                              ▼
    │                                      Planner → mandatory + budget-eligible checks
    │                                              │
    │                                              ▼
    │                                      Check execution (allow-listed, resource-limited)
    │                                              │
    │                                              ▼
    │                                      Evidence bundle (signed, commit-bound)
    │                                              │
    │                                              ▼
    │                                      Trusted verifier (hashes, identities, attestation)
    │                                              │
    │                                              ▼
    │                                      [Control Plane] Reporter → GitHub Check Run
    │                                              │
    │                                              ▼
    │                                      Durable store (PostgreSQL + Blob) + Observability (OpenTelemetry)
```

**Trust boundaries:** Execution sandbox never receives GitHub write token or production
credentials. Reporter never executes PR code. Verifier consumes validated signed evidence
only.

---

## 7. External Links (quick reference)

- NIST SSDF: https://csrc.nist.gov/pubs/sp/800/218/final
- GitHub Actions security: https://docs.github.com/en/actions/reference/security/secure-use
- GitHub Actions policies: https://docs.github.com/en/actions/concepts/about-actions-policies
- SLSA v1.2: https://slsa.dev/spec/v1.2/
- Sigstore Cosign: https://docs.sigstore.dev/quickstart/quickstart-cosign/
- OpenTelemetry: https://opentelemetry.io/docs/concepts/signals/
- Docker security/seccomp: https://docs.docker.com/engine/security/seccomp
- gVisor production: https://gvisor.dev/docs/user_guide/production/
- Azure App Service security: https://learn.microsoft.com/en/azure/app-service/overview-security
- OWASP GenAI LLM Top 10 (2026): https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
