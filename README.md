# CLCA - Cross-Layer Change Assurance

## Application Description

CLCA (Cross-Layer Change Assurance) is an evidence-backed change-assurance release gate that evaluates cross-layer impacts across code, data, AI, and runtime assets. It provides a standardized way to verify changes across multiple layers of an application stack before they reach production, ensuring that changes are properly analyzed, checked, and documented.

CLCA v0.4.0 is a containerized, production-ready web product integrated with GitHub, featuring open-source graph visualization, multi-agent adversarial review validation, and comprehensive security hardening.

## Purpose

CLCA addresses the problem of siloed change verification where:
- CI tools check one layer at a time without cross-layer awareness
- AI agent changes can introduce ungoverned permissions and behaviors
- Data contract changes break downstream consumers without detection
- Evidence of change verification is not sealed, signed, or commit-bound
- Release gates cannot prove what was checked, how, and with what evidence

CLCA provides:
- **Cross-layer impact analysis** via graph traversal across code, data, AI, and runtime assets
- **Allow-listed subprocess execution** with resource limits and sandboxing
- **Sealed evidence bundles** with SHA-256 digests and optional cryptographic attestation
- **Policy-driven decisions** (PASS/WARN/BLOCK/INCOMPLETE) with mandatory check enforcement
- **GitHub integration** via signed webhooks and check run reporting
- **Web console** for interactive scenario testing and evidence visualization
- **Docker containerization** for ACR + App Service deployment

## How to Use

### Prerequisites

- Python 3.12+
- Git
- Docker (optional, for containerized deployment)

### Installation

```bash
# Clone the repository
git clone https://github.com/mrzero-cool/CCLA.git
cd CLA

# Install dependencies
pip install -e .

# Verify installation
python -m clca.cli --help
```

### Running the CLI

```bash
# Analyze a change
python -m clca.cli analyze --repo . --base base-sha --head head-sha

# Verify changes with checks
python -m clca.cli verify --repo . --base base-sha --head head-sha --bundle artifacts/bundle.json

# Decide on the change
python -m clca.cli decide --bundle artifacts/bundle.json --catalog config/check_catalog.json --policy config/policy.json

# Generate a report
python -m clca.cli report --bundle artifacts/bundle.json --catalog config/check_catalog.json --policy config/policy.json

# Full pipeline in one command
python -m clca.cli run --repo . --base base-sha --head head-sha --catalog config/check_catalog.json --policy config/policy.json --commands config/commands.json --output artifacts/decision.json
```

### Running the HTTP Service

```bash
# Start the service (default port 8080)
python -m clca.service

# Custom port
PORT=5055 python -m clca.service

# With webhook secret
CLCA_GITHUB_WEBHOOK_SECRET=mysecret python -m clca.service
```

**Endpoints:**
- `GET /healthz` - Health check
- `GET /v1/scenarios` - List available scenarios
- `POST /v1/runs` - Start a new analysis run
- `GET /v1/runs/{run_id}` - Get run details
- `GET /v1/runs/{run_id}/report` - Get markdown report
- `GET /v1/runs/{run_id}/graph` - Get impact graph (JSON)
- `GET /v1/runs/{run_id}/graph.dot` - Get Graphviz DOT export
- `GET /v1/integrations` - List configured integrations
- `POST /v1/webhooks/github` - GitHub webhook endpoint (requires HMAC signature)

### Web Console

The service includes a vanilla-JS web console at `http://localhost:5055/` with:
- Scenario picker for interactive testing
- Decision banner (PASS/WARN/BLOCK/INCOMPLETE)
- Impact graph visualization
- Evidence bundle viewer
- Run history and polling

### Docker Deployment

```bash
# Build the image
docker build -t clca:0.4.0 .

# Run the container
docker run -d --name clca -p 5055:8080 clca:0.4.0

# Verify
curl http://localhost:5055/healthz
```

### GitHub Actions Integration

Add `.github/workflows/clca.yml`:

```yaml
name: clca-gate
on:
  pull_request:
    types: [opened, synchronize, reopened]
jobs:
  clca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - run: python -m clca.cli run --repo . --base ${{ github.event.pull_request.base.sha }} --head ${{ github.sha }} --output artifacts/decision.json
      - uses: actions/upload-artifact@v4
        with: { name: clca-evidence, path: artifacts/ }
```

### Authentication

**No authentication is implemented** for the demo version. The service runs in demo mode where all requests are allowed.

For production deployment:
- Set `CLCA_API_TOKEN` environment variable for bearer token authentication
- Set `CLCA_GITHUB_WEBHOOK_SECRET` for GitHub webhook verification
- Set `GITHUB_TOKEN` for GitHub Check Run posting
- Configure RBAC roles: viewer, developer, repository_admin, policy_admin, auditor

### Configuration Files

- `config/policy.json` - Policy rules and decision thresholds
- `config/check_catalog.json` - Available checks and their requirements
- `config/commands.json` - Allow-listed command catalog
- `.github/workflows/clca.yml` - GitHub Actions workflow

### Sample App

The `sample_app/` directory contains a synthetic retail application used for testing scenarios:
- `backend/services/pricing.py` - Pricing service
- `agents/replenishment/agent.py` - Replenishment agent
- `agents/replenishment/tool_manifest.json` - Agent tool manifest
- `data/dbt/manifest.json` - dbt data model
- `agents/replenishment/prompts/system.md` - Agent system prompt

### Test Suite

```bash
# Run all tests
python -m pytest -q

# Run specific test groups
python -m pytest -q tests/test_e2e.py
python -m pytest -q tests/test_policy.py
python -m pytest -q tests/test_service.py
python -m pytest -q tests/test_github_integration.py
python -m pytest -q tests/test_adapter_*.py
```

### License

MIT License

---

*Built for the Cross-Layer Change Assurance project. For production deployment, see docs/PRODUCTION_READINESS_GAP_ANALYSIS.md and docs/LINKED_TOOLS_CATALOG.md.*
