# Deploying CLCA to Azure Container Registry + App Service

The container runs the **demo API** (`python -m clca.service`): it serves `/healthz`, lists the built-in synthetic scenarios, and runs the full evidence pipeline (analyze → verify → decide → report) for a selected scenario. It never accepts repository URLs, credentials, or arbitrary commands.

## What the image contains

| Item | Value |
|---|---|
| Base image | `python:3.12-slim` (+ `git`, `tini`) |
| Process | `python -m clca.service` under tini (reaps check subprocesses) |
| Port | `8080` (override with `PORT`) |
| User | non-root `clca` (uid 10001) |
| Health probe | `GET /healthz` → `200 {"status":"ok",...}` |
| Writes | only under `TMPDIR` (scenario temp worktrees) |

## 1. Build and push to ACR

```bash
# Variables — set these for your subscription
export ACR_NAME=<your-acr-name>          # e.g. tredenceclcademo
export IMAGE_TAG=0.4.0
export RESOURCE_GROUP=<your-rg>
export LOCATION=eastus
export APP_NAME=<globally-unique-app-name>

# One-time: create the registry (skip if you already have one)
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic --admin-enabled true

# Build ON the cloud (no local Docker daemon needed) and push
az acr build --registry $ACR_NAME --image clca:$IMAGE_TAG .

# Equivalent local build + push, if you prefer:
# docker build -t $ACR_NAME.azurecr.io/clca:$IMAGE_TAG .
# az acr login --name $ACR_NAME
# docker push $ACR_NAME.azurecr.io/clca:$IMAGE_TAG
```

## 2. Run it once in ACI (optional smoke test before App Service)

```bash
az container create \
  --resource-group $RESOURCE_GROUP \
  --name clca-smoke \
  --image $ACR_NAME.azurecr.io/clca:$IMAGE_TAG \
  --registry-login-server $ACR_NAME.azurecr.io \
  --dns-name-label $APP_NAME-dns \
  --ports 8080 \
  --environment-variables PORT=8080

curl "https://$APP_NAME-dns.$LOCATION.azurecontainer.io:8080/healthz"
```

## 3. Deploy to App Service (Linux, custom container)

```bash
# App Service plan (Linux). Use PremiumV3+ for production; Basic works for a demo.
az appservice plan create \
  --resource-group $RESOURCE_GROUP \
  --name clca-plan \
  --sku B1 \
  --is-linux

# Web app from the ACR image
az webapp create \
  --resource-group $RESOURCE_GROUP \
  --plan clca-plan \
  --name $APP_NAME \
  --deployment-container-image-name $ACR_NAME.azurecr.io/clca:$IMAGE_TAG

# Let App Service pull from the private registry
az webapp config container set \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --docker-custom-image-name $ACR_NAME.azurecr.io/clca:$IMAGE_TAG \
  --docker-registry-server-url https://$ACR_NAME.azurecr.io \
  --docker-registry-server-user $(az acr credential show --name $ACR_NAME --query username -o tsv) \
  --docker-registry-server-password $(az acr credential show --name $ACR_NAME --query passwords[0].value -o tsv)

# The container listens on 8080 inside; tell App Service where to route
az webapp config appsettings set \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --settings PORT=8080 WEBSITES_PORT=8080 WEBSITES_ENABLE_APP_SERVICE_STORAGE=false

# Health check: App Service recycles the container if /healthz stops answering
az webapp config set \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --health-check-path /healthz \
  --generic-configurations '{"http20Enabled": true}'
```

> **ACR auth note:** `az acr credential show` works on Basic/Standard with `admin-enabled true`. For production, prefer an **Azure AD identity pull** (`az webapp identity assign` + `AcrPull` role) instead of admin credentials, and rotate the admin password off.

## 4. Smoke test the deployed app

```bash
BASE="https://$APP_NAME.azurewebsites.net"

curl -s "$BASE/healthz"
curl -s "$BASE/v1/scenarios"

# Async run: POST returns 202 + run_id, then poll
RUN=$(curl -s -X POST "$BASE/v1/runs" -H "Content-Type: application/json" -d '{"scenario":"write_tool_escalation"}')
ID=$(echo "$RUN" | python -c "import sys,json;print(json.load(sys.stdin)['run_id'])")
curl -s "$BASE/v1/runs/$ID"     # poll until status=completed → decision=BLOCK
curl -s "$BASE/v1/runs/$ID/report"
```

Expected: the escalation scenario completes with `"decision": "BLOCK"` and `AGENT_NEW_WRITE_TOOL`, even though the Python unit suite passes. The web console is at `$BASE/` — open it in a browser and run scenarios interactively.

## 5. Redeploy after a code change

```bash
az acr build --registry $ACR_NAME --image clca:$IMAGE_TAG .
az webapp restart --resource-group $RESOURCE_GROUP --name $APP_NAME
```

## Cost / sizing notes

- `B1` Linux plan is enough for a demo (~₹1,400/month in most regions); stop it when idle: `az appservice stop --resource-group $RESOURCE_GROUP --name $APP_NAME`.
- Each scenario run copies `sample_app` to `TMPDIR`, executes allow-listed checks via subprocess, and deletes the copy; disk use is transient. Runs are stored in process memory only — an App Service instance restart loses run history (by design for the demo).

## Security posture (demo scope)

- No authentication on the API. Add App Service Easy Auth (`az webapp auth config`) or put it behind a private endpoint before sharing the URL.
- The container runs as non-root, has no cloud credentials, and the runner refuses any executable or argument pattern outside `config/commands.json`.
- Scenario runs are synthetic and self-contained; no external repositories or data sources are contacted.
