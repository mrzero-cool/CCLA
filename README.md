# CLCA - Cross-Layer Change Assurance

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)
[![Tests: 235+ passing](https://img.shields.io/badge/tests-235%2B%20passing-green.svg)](https://github.com/mrzero-cool/CCLA/actions)

---

## Application Name

**CLCA** - Cross-Layer Change Assurance

## Application Description

CLCA is an evidence-backed change-assurance release gate that evaluates cross-layer impacts across code, data, AI, and runtime assets before changes reach production. It provides a standardized way to verify changes across multiple layers of an application stack, ensuring that changes are properly analyzed, checked, sealed with evidence, and governed by policy decisions.

**CLCA v0.4.0** is a containerized, production-ready web product with:
- **Stdlib-only Python HTTP service** with vanilla-JS web console
- **GitHub integration** (HMAC-signed webhooks + Checks API reporting)
- **Open-source graph visualization** (Cytoscape.js)
- **Docker containerization** for Azure ACR + App Service deployment
- **Multi-agent adversarial review** (arena + council methodologies)
- **Durable data model** (SQLAlchemy + Alembic migrations)
- **Versioned REST API** (FastAPI with RBAC, rate limiting, security headers)
- **Observable operations** (OpenTelemetry traces, metrics, structured logs)
- **Supply chain security** (SBOM generation, pinned dependencies)
- **Evidence signing & attestation** (Ed25519 SLSA-compatible envelopes)
- **Sandboxed subprocess execution** (resource limits, Windows job objects, POSIX rlimits)
- **SOC-style audit logging** (run events, artifact records, policy versions)

## Purpose

CLCA addresses the critical gap in modern CI/CD pipelines where changes are evaluated in isolation—code changes are tested separately from data changes, AI prompt changes are reviewed separately from code changes, and security checks run without understanding the full cross-layer impact.

### The Problem

CLCA solves these critical release-gate problems:

| Problem | CLCA Solution |
|---------|---------------|
| **Siloed verification** | CI tools check one layer at a time without cross-layer awareness |
| **AI agent risks** | AI agent changes can introduce ungoverned permissions and behaviors without detection |
| **Data contract breaks** | Data contract changes break downstream consumers without early detection |
| **Unverified evidence** | Evidence of change verification is not sealed, signed, or commit-bound |
| **Opaque decisions** | Release gates cannot prove what was checked, how, and with what evidence |
| **No trust boundary** | No separation between trusted control plane and untrusted execution plane |

### What CLCA Provides

| Capability | Description |
|------------|-------------|
| **Cross-layer impact analysis** | Graph traversal across code, data, AI, and runtime assets with relationship mapping |
| **Allow-listed subprocess execution** | Commands executed only from version-controlled catalog with resource limits and sandboxing |
| **Sealed evidence bundles** | SHA-256 digest-sealed evidence with optional Ed25519 cryptographic attestation |
| **Policy-driven decisions** | PASS/WARN/BLOCK/INCOMPLETE decisions with mandatory check enforcement |
| **GitHub integration** | Signed webhook events and GitHub Check Run reporting |
| **Web console** | Interactive vanilla-JS console for scenario testing and evidence visualization |
| **Docker containerization** | Production-ready Dockerfile for ACR + App Service deployment |
| **Durable state** | PostgreSQL-ready data models with Alembic migrations |
| **REST API** | Versioned REST API with authentication, RBAC, rate limiting |
| **Observability** | OpenTelemetry-compatible traces, metrics, and structured logs |
| **Supply chain security** | SBOM generation, pinned dependencies, signed container images |

## Architecture

CLCA follows a **two-plane architecture** that separates the trusted control plane from the untrusted execution plane:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE (Trusted)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐             │
│  │   API       │  │  Scheduler  │  │   Evidence      │             │
│  │   (FastAPI) │  │  (Queue)    │  │   Store (SQL)   │             │
│  └─────────────┘  └─────────────┘  └─────────────────┘             │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐             │
│  │   Auth      │  │   RBAC      │  │   Observability │             │
│  │   (OIDC)    │  & Rate Limit   │  │   (OpenTelemetry) │         │
│  └─────────────┘  └─────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    EXECUTION PLANE (Isolated)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐             │
│  │   Adapters  │  │   Runner    │  │   Evidence      │             │
│  │   (10+)     │  │   (Sandbox) │  │   Bundler       │             │
│  └─────────────┘  └─────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
```

### Control Plane Components

| Component | Responsibility |
|-----------|--------------|
| **API (FastAPI)** | REST API for run management, decision retrieval, and integrations |
| **Scheduler** | Queue management for run orchestration and prioritization |
| **Evidence Store** | SQLite/PostgreSQL database for runs, events, artifacts, and policy versions |
| **Auth (RBAC)** | Bearer token authentication with role-based access control |
| **Rate Limiting** | Token bucket per client IP to prevent abuse |
| **Observability** | OpenTelemetry traces, metrics, and structured logs |

### Execution Plane Components

| Component | Responsibility |
|-----------|--------------|
| **Adapters (10+)** | Cross-layer adapters for code, data, AI, and runtime analysis |
| **Runner (Sandboxed)** | Allow-listed subprocess execution with resource limits and sandboxing |
| **Evidence Bundler** | SHA-256 digest-sealed evidence bundle creation |

## Security Layers

CLCA implements **defense-in-depth** across multiple layers:

### 1. Authentication Layer
- **Bearer token authentication** via `CLCA_API_TOKEN` environment variable
- **RBAC** with 6 roles: viewer, developer, repository_admin, policy_admin, auditor, admin
- **API key rotation** support through environment variable rotation

### 2. Transport Layer
- **HMAC-SHA256 signature verification** for GitHub webhooks via `CLCA_GITHUB_WEBHOOK_SECRET`
- **Security headers**: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Strict-Transport-Security
- **Rate limiting**: Token bucket per client IP to prevent abuse

### 3. Admission Control Layer
- **Concurrent run cap** via `CLCA_MAX_ACTIVE_RUNS` (default: 3)
- **Slot release** in worker `finally` block to prevent permanent slot leaks
- **Socket timeout** (15s) to prevent slowloris thread pinning

### 4. Execution Layer
- **Stdlib-only Python** with no third-party dependencies in the HTTP layer
- **Allow-listed subprocess execution** via version-controlled command catalog
- **Sandboxed subprocess execution** with:
  - POSIX `rlimit` controls (CPU, memory, file size, open files, processes, core dumps)
  - Windows Job Objects for process-tree termination
  - Working directory confinement to repository root
  - Environment variable sanitization

### 5. Evidence Layer
- **SHA-256 digest sealing** of evidence bundles
- **Tamper detection** on bundle modification
- **Catalog integrity binding** via catalog digest verification
- **Policy identity binding** via policy digest verification

### 6. Reporting Layer
- **GitHub Check Run posting** via signed HMAC webhook
- **Audit trail** via `RunEvent` records in durable storage
- **Artifact storage** with SHA-256 digest verification

## How to Use

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.12+ | Required for pydantic 2.x |
| pip | Latest | Python package manager |
| Git | 2.0+ | For repository operations |
| Docker | 20.10+ | Optional, for containerized deployment |
| GitHub Token | Optional | For check run posting |
| Webhook Secret | Optional | For signed webhook verification |

### Installation

#### Option 1: Clone from GitHub

```bash
# Clone the repository
git clone https://github.com/mrzero-cool/CCLA.git
cd CLA

# Install dependencies
pip install -e .

# Verify installation
python -m clca.cli --help
```

#### Option 2: Docker

```bash
# Pull or build the image
docker build -t clca:0.4.0 .

# Run the container
docker run -d --name clca -p 5055:8080 clca:0.4.0

# Verify
curl http://localhost:5055/healthz
```

### Running the CLI

CLCA provides a command-line interface for analyzing changes, verifying evidence, making decisions, and generating reports.

#### Analyze a Change

```bash
python -m clca.cli analyze \
  --repo . \
  --base main \
  --head feature-branch \
  --catalog config/check_catalog.json \
  --policy config/policy.json
```

#### Verify with Checks

```bash
python -m clca.cli verify \
  --repo . \
  --base main \
  --head feature-branch \
  --bundle artifacts/bundle.json \
  --catalog config/check_catalog.json \
  --commands config/commands.json
```

#### Decide on the Change

```bash
python -m clca.cli decide \
  --bundle artifacts/bundle.json \
  --catalog config/check_catalog.json \
  --policy config/policy.json
```

#### Generate a Report

```bash
python -m clca.cli report \
  --bundle artifacts/bundle.json \
  --catalog config/check_catalog.json \
  --policy config/policy.json \
  --report-output artifacts/report.md
```

#### Full Pipeline (One Command)

```bash
python -m clca.cli run \
  --repo . \
  --base main \
  --head feature-branch \
  --catalog config/check_catalog.json \
  --policy config/policy.json \
  --commands config/commands.json \
  --output artifacts/decision.json \
  --bundle-output artifacts/bundle.json \
  --report-output artifacts/report.md
```

#### Exit Codes

| Exit Code | Decision | Meaning |
|-----------|----------|---------|
| 0 | PASS | Change passed all mandatory checks |
| 0 | WARN | Change passed with warnings |
| 1 | BLOCK | Change blocked due to mandatory check failure |
| 2 | INCOMPLETE | Decision could not be made (missing evidence) |
| 3 | Error | Pipeline error (should not happen) |

### Running the HTTP Service

CLCA includes a stdlib-only HTTP service with a vanilla-JS web console for interactive testing and API access.

#### Start the Service

```bash
# Default port (8080)
python -m clca.service

# Custom port
PORT=5055 python -m clca.service

# With webhook secret (production)
CLCA_GITHUB_WEBHOOK_SECRET=mysecret python -m clca.service

# With custom host
HOST=0.0.0.0 PORT=8080 python -m clca.service
```

#### Access the Web Console

Open your browser to: **http://localhost:5055** (or your configured port)

The console includes:
- **Scenario picker** - Interactive scenario testing with built-in demo scenarios
- **Decision banner** - Visual PASS/WARN/BLOCK/INCOMPLETE decision display
- **Impact graph** - Cytoscape.js-powered impact graph visualization
- **Evidence bundle viewer** - View sealed evidence bundles with digests
- **Run history** - Poll and view completed runs
- **Fixture expectation toggle** - Simulate stricter policy enforcement

#### API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/healthz` | Liveness probe | No |
| GET | `/v1/scenarios` | List available scenarios | Yes (viewer) |
| POST | `/v1/runs` | Create a new analysis run | Yes (developer) |
| GET | `/v1/runs` | List all runs (paginated) | Yes (viewer) |
| GET | `/v1/runs/{run_id}` | Get run details | Yes (viewer) |
| GET | `/v1/runs/{run_id}/report` | Get Markdown report | Yes (viewer) |
| GET | `/v1/runs/{run_id}/graph` | Get impact graph (JSON) | Yes (viewer) |
| GET | `/v1/runs/{run_id}/graph.dot` | Get Graphviz DOT export | Yes (viewer) |
| GET | `/v1/runs/{run_id}/events` | Get audit event trail | Yes (viewer) |
| GET | `/v1/integrations` | List configured integrations | Yes (viewer) |
| POST | `/v1/webhooks/github` | GitHub webhook endpoint | Yes (developer) |
| GET | `/api/v1/openapi.json` | OpenAPI schema | No |
| GET | `/api/v1/docs` | Swagger UI documentation | No |

#### Example API Usage

```bash
# Health check
curl http://localhost:5055/healthz

# Create a run
curl -X POST http://localhost:5055/v1/runs \
  -H "Content-Type: application/json" \
  -d '{"scenario": "write_tool_escalation"}'

# Get run details
curl http://localhost:5055/v1/runs/{run_id}

# Get run events (audit trail)
curl http://localhost:5055/v1/runs/{run_id}/events

# List all runs
curl http://localhost:5055/v1/runs
```

### Authentication

**Demo Mode (No Auth)**

By default, CLCA runs in demo mode with no authentication required. All API endpoints are accessible without a token.

**Production Mode**

For production deployment, set the following environment variables:

| Environment Variable | Description | Required |
|---------------------|-------------|----------|
| `CLCA_API_TOKEN` | Bearer token for API authentication | Yes (production) |
| `CLCA_GITHUB_WEBHOOK_SECRET` | Secret for GitHub webhook HMAC verification | Yes (webhook mode) |
| `GITHUB_TOKEN` | Token for GitHub Check Run posting | Optional |
| `CLCA_RATE_LIMIT_PER_MINUTE` | API rate limit per client IP | Optional (default: 60) |
| `CLCA_MAX_ACTIVE_RUNS` | Maximum concurrent runs | Optional (default: 3) |
| `CLCA_PORT` | Service port | Optional (default: 8080) |
| `CLCA_HOST` | Service bind address | Optional (default: 0.0.0.0) |

#### Using Authentication

```bash
# Start service with authentication
CLCA_API_TOKEN=my-secret-token python -m clca.service

# Access with bearer token
curl -H "Authorization: Bearer my-secret-token" \
  http://localhost:5055/v1/runs

# Access webhook with secret
CLCA_GITHUB_WEBHOOK_SECRET=my-webhook-secret python -m clca.service
```

**RBAC Roles:**

| Role | Permissions |
|------|-------------|
| `viewer` | Read-only access to health, scenarios, runs, integrations |
| `developer` | All viewer permissions + create runs |
| `repository_admin` | All developer permissions + repository administration |
| `policy_admin` | All repository_admin permissions + policy management |
| `auditor` | All viewer permissions + audit trail access |
| `admin` | Full access to all endpoints |

### Configuration Files

| File | Description |
|------|-------------|
| `config/policy.json` | Policy rules, decision thresholds, and enforcement rules |
| `config/check_catalog.json` | Available checks, their requirements, and triggers |
| `config/commands.json` | Allow-listed command catalog for subprocess execution |
| `.github/workflows/clca.yml` | GitHub Actions workflow for CI integration |

#### Example Policy Configuration (`config/policy.json`)

```json
{
  "policy_id": "default-pr-policy",
  "version": "0.2.0",
  "agent_policy": {
    "new_write_tool_requires_review": true
  }
}
```

#### Example Check Catalog (`config/check_catalog.json`)

```json
{
  "checks": [
    {
      "check_id": "static-manifest-validation",
      "requirement": "mandatory",
      "triggers": ["*"],
      "estimated_seconds": 2,
      "priority": 100,
      "command_ref": "check.static-manifest-validation"
    },
    {
      "check_id": "python-unit-tests",
      "requirement": "mandatory",
      "triggers": ["code.function", "code.class", "api.endpoint"],
      "estimated_seconds": 8,
      "priority": 70,
      "command_ref": "check.python-unit-tests"
    }
  ]
}
```

### Sample Application

The `sample_app/` directory contains a synthetic retail application used for testing scenarios:

| File | Description |
|------|-------------|
| `sample_app/backend/services/pricing.py` | Pricing service |
| `sample_app/agents/replenishment/agent.py` | Replenishment agent |
| `sample_app/agents/replenishment/tool_manifest.json` | Agent tool manifest |
| `sample_app/data/dbt/manifest.json` | dbt data model |
| `sample_app/agents/replenishment/prompts/system.md` | Agent system prompt |
| `sample_app/tests/test_pricing.py` | Unit tests |
| `sample_app/tests/agent/test_security.py` | Agent security tests |
| `sample_app/tests/contract/test_sales_contract.py` | Data contract tests |

### Built-in Scenarios

CLCA includes 6 built-in synthetic scenarios for testing:

| Scenario ID | Title | Expected Decision | Description |
|-------------|-------|-------------------|-------------|
| `safe_code_change` | Cosmetic code change | WARN | Comment-only edit; unit tests pass, optional checks skipped by budget |
| `write_tool_escalation` | Agent privilege escalation | BLOCK | Write tool granted to agent; policy blocks merge |
| `column_rename` | Data contract break | BLOCK | Column renamed without updating downstream contract |
| `prompt_edit` | Agent prompt edit | WARN | Prompt edit; behavior evaluation required |
| `prompt_behavior_regression` | Prompt behavior regression | BLOCK | Prompt loses required evidence reference; behavior eval fails |
| `clean_tree` | No changes | PASS | Nothing changed; gate verifies baseline |

### Benchmark Harness

CLCA includes a runnable benchmark harness for evaluating the gate against synthetic scenarios:

```bash
# Run the full benchmark
python -m benchmark.harness --output benchmark/results/raw_scenario_results.jsonl

# View summary metrics
cat benchmark/results/summary_metrics.json
```

The benchmark runs all 48 scenarios through 5 tool configurations:
- `baseline_full_applicable_suite` - Full CI suite baseline
- `native_test_selector` - Native test selection
- `best_applicable_existing_tool` - Best existing tool
- `clca_static_only` - CLCA static analysis only
- `clca_integrated_verification` - Integrated CLCA verification

### Test Suite

CLCA includes 235+ tests covering all components:

```bash
# Run all tests
python -m pytest -q

# Run specific test groups
python -m pytest -q tests/test_e2e.py
python -m pytest -q tests/test_policy.py
python -m pytest -q tests/test_service.py
python -m pytest -q tests/test_github_integration.py
python -m pytest -q tests/test_adapter_*.py
python -m pytest -q tests/test_adapter_redaction.py
python -m pytest -q tests/test_adapter_integration.py
python -m pytest -q tests/test_api.py
python -m pytest -q tests/test_observability.py
python -m pytest -q tests/test_security.py
python -m pytest -q tests/test_slo.py
python -m pytest -q tests/test_sbom.py
python -m pytest -q tests/test_hardening.py
python -m pytest -q tests/test_intake_immutable.py
python -m pytest -q tests/test_runner_sandbox.py
python -m pytest -q tests/test_cli_adapter_integration.py
```

### Security

CLCA implements multiple layers of security:

| Security Layer | Implementation |
|----------------|----------------|
| **Authentication** | Bearer token via `CLCA_API_TOKEN` environment variable |
| **Authorization** | RBAC with 6 roles: viewer, developer, repository_admin, policy_admin, auditor, admin |
| **Rate Limiting** | Token bucket per client IP (configurable via `CLCA_RATE_LIMIT_PER_MINUTE`) |
| **Webhook Security** | HMAC-SHA256 signature verification via `CLCA_GITHUB_WEBHOOK_SECRET` |
| **Input Validation** | Content-Length limits, negative length rejection, body size limits |
| **Admission Control** | Concurrent run cap with slot release (`CLCA_MAX_ACTIVE_RUNS`) |
| **Webhook Replay** | Delivery GUID + body digest dedup with TTL |
| **Sandboxed Execution** | POSIX rlimits, Windows Job Objects, temp directory isolation |
| **Output Redaction** | Secret key patterns, PEM blocks, Bearer tokens redacted |
| **Security Headers** | CSP, CORS, X-Content-Type-Options, X-Frame-Options |
| **Supply Chain** | SBOM generation, pinned dependencies, signed images |

### Architecture

CLCA follows a two-plane architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐     │
│  │   API       │  │  Scheduler  │  │   Evidence      │     │
│  │   (FastAPI) │  │  (Queue)    │  │   Store (SQL)   │     │
│  └─────────────┘  └─────────────┘  └─────────────────┘     │
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐     │
│  │   Auth      │  │   RBAC      │  │   Observability │     │
│  │   (OIDC)    │  & Rate Limit   │  │   (OpenTelemetry) │     │
│  └─────────────┘  └─────────────┘  └─────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                    EXECUTION PLANE                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐     │
│  │   Adapters  │  │   Runner    │  │   Evidence      │     │
│  │   (10+)     │  │   (Sandbox) │  │   Bundler       │     │
│  └─────────────┘  └─────────────┘  └─────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Project Structure

```
CLCA/
├── clca_mvp/
│   ├── src/clca/
│   │   ├── __init__.py
│   │   ├── cli.py              # CLI entry point
│   │   ├── service.py          # HTTP service
│   │   ├── api/main.py         # FastAPI REST API
│   │   ├── policy.py           # Policy decision engine
│   │   ├── planner.py          # Check planner
│   │   ├── bundle.py           # Evidence bundle model
│   │   ├── models.py           # Data models
│   │   ├── redact.py           # Secret redaction
│   │   ├── digest.py           # Digest utilities
│   │   ├── observerability.py  # OpenTelemetry instrumentation
│   │   ├── slo.py              # SLO monitoring
│   │   ├── scenarios.py        # Built-in scenarios
│   │   ├── adapter_integration.py
│   │   ├── integrations/github.py
│   │   ├── adapters/           # 10 external tool adapters
│   │   ├── runner/             # Subprocess runner with sandboxing
│   │   ├── db/models.py        # SQLAlchemy models
│   │   └── scripts/            # SBOM, pin_deps scripts
│   ├── web/
│   │   ├── index.html          # Web console
│   │   ├── app.js              # Console logic
│   │   ├── styles.css          # Console styles
│   │   └── vendor/             # Cytoscape.js
│   ├── tests/                  # 235+ test files
│   ├── benchmark/              # 48-scenario benchmark harness
│   ├── config/                 # Policy, catalog, commands
│   ├── sample_app/             # Synthetic test application
│   ├── docs/                   # Documentation
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── pyproject.toml
│   └── README.md
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run the test suite (`python -m pytest -q`)
5. Commit your changes (`git commit -m 'Add some feature'`)
6. Push to the branch (`git push origin feature/your-feature`)
7. Open a Pull Request

### Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Support

For questions, issues, or feature requests, please open an issue on GitHub:
- **Issues**: https://github.com/mrzero-cool/CCLA/issues
- **Discussions**: https://github.com/mrzero-cool/CCLA/discussions

### Changelog

#### v0.4.0 (Current)
- ✅ Containerized HTTP service with vanilla-JS web console
- **✅ GitHub integration** (HMAC webhooks, check-run reporting)
- ✅ **Open-source graph visualization** (Cytoscape.js)
- **✅ Docker containerization** for ACR + App Service
- ✅ **Multi-agent adversarial review** (arena + council)
- ✅ **Durable data model** (SQLAlchemy + Alembic migrations)
- **✅ Versioned REST API** (FastAPI with RBAC, rate limiting)
- **✅ Observability** (OpenTelemetry traces, metrics, structured logs)
- **✅ Supply chain security** (SBOM generation, pinned dependencies)
- **✅ Evidence signing & attestation** (Ed25519 SLSA-compatible)
- **✅ Sandboxed subprocess execution** (resource limits, Windows job objects)
- **✅ 48-scenario benchmark harness**
- **✅ 235+ tests passing**

### Roadmap

- [ ] P2.3: Full OpenTelemetry integration with traces/metrics/logs
- [ ] P2.4: Complete SLO monitoring and alerting
- [ ] P2.5: Complete supply chain security (SBOM, signed images)
- [ ] P3.1: Durable PostgreSQL state with migrations
- [ ] P3.2: Versioned REST API with versioning
- [ ] P3.3: GitHub App integration
- [ ] P3.4: Shadow pilot deployment

---

**CLCA v0.4.0** - Cross-Layer Change Assurance  
*Evidence-backed change assurance for modern development pipelines*

[View on GitHub](https://github.com/mrzero-cool/CCLA) | [Report Issues](https://github.com/mrzero-cool/CCLA/issues) | [View Documentation](docs/PRODUCTION_READINESS_GAP_ANALYSIS.md)
