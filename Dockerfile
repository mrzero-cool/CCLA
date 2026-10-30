# syntax=docker/dockerfile:1
# Cross-Layer Change Assurance — demo API container
# Runs the evidence-backed release gate against built-in synthetic scenarios.

FROM python:3.12-slim AS base

# git is required by the change-intake layer (revision binding + baseline diffs).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency layer first so source edits don't bust the pip cache.
COPY pyproject.toml ./
COPY src ./src
RUN python -m pip install --no-cache-dir --upgrade pip \
 && python -m pip install --no-cache-dir '.[test]'

# Runtime data: the check catalog, policy, command allow-list, sample app and web console.
COPY config ./config
COPY sample_app ./sample_app
COPY web ./web

ENV CLCA_ROOT=/app \
    CLCA_WEB_ROOT=/app/web \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    HOST=0.0.0.0

# App Service / containers best practice: run as non-root.
RUN useradd --system --create-home --uid 10001 clca \
 && mkdir -p /tmp/clca-runs \
 && chown -R clca:clca /app /tmp/clca-runs
USER clca
ENV TMPDIR=/tmp/clca-runs

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','8080'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/healthz', timeout=4).status==200 else 1)"

# tini reaps the check subprocesses so the container exits cleanly.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "python -m clca.service"]
