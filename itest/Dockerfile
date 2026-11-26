# Pre-baked CI image for Hyphae (`hyp`) Black-Box Integration Testing (`ghcr.io/hyphae-to/hyp-itest:latest`).
#
# Rebuilt automatically on `main` when `itest/Dockerfile` or `itest/versions.lock.json` changes so
# Tier 1 PR jobs and Tier 2 nightly jobs boot real coding harnesses in ~15s without repeating npm installs.

FROM node:24-bookworm-slim AS base

ARG TARGETARCH=amd64
ARG ALERTMANAGER_VERSION=0.28.1

ENV DEBIAN_FRONTEND=noninteractive \
    HYPHAE_ITEST_CACHE_DIR=/opt/hyphae-itest \
    HYPHAE_NO_SERVICE=1 \
    HYPHAE_SECRET_BACKEND=file \
    HYPHAE_NO_OPEN=1 \
    HYPHAE_WIZARD_NO_ANIM=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    PATH="/opt/hyphae-itest/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Core runtime utilities + Python 3 (stdlib PTY driver) + SQLite + Mosquitto broker for Tier 2.
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      git \
      jq \
      mosquitto \
      mosquitto-clients \
      procps \
      python3 \
      sqlite3 \
      tar \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Prometheus Alertmanager static binary (`alertmanager` + `amtool`) for Tier 2 parity.
RUN set -eu; \
    ARCH="${TARGETARCH:-amd64}"; \
    case "${ARCH}" in \
      amd64|arm64) ;; \
      *) ARCH="amd64" ;; \
    esac; \
    mkdir -p /opt/hyphae-itest/bin /tmp/am; \
    curl -fsSL "https://github.com/prometheus/alertmanager/releases/download/v${ALERTMANAGER_VERSION}/alertmanager-${ALERTMANAGER_VERSION}.linux-${ARCH}.tar.gz" \
      | tar -xz --strip-components=1 -C /tmp/am; \
    install -m 0755 /tmp/am/alertmanager /opt/hyphae-itest/bin/alertmanager; \
    install -m 0755 /tmp/am/amtool /opt/hyphae-itest/bin/amtool; \
    rm -rf /tmp/am

# Copy lockfile & provisioner and pre-populate version-pinned isolated npm harness prefixes.
WORKDIR /opt/hyphae-itest/src
COPY itest/versions.lock.json /opt/hyphae-itest/src/versions.lock.json
COPY itest/scripts/provision.mjs /opt/hyphae-itest/src/scripts/provision.mjs

RUN node /opt/hyphae-itest/src/scripts/provision.mjs \
      --cache-dir /opt/hyphae-itest \
      --tools openclaw,claude,codex,gemini \
      --json > /opt/hyphae-itest/toolchain-manifest.json \
    && npm cache clean --force

# Dedicated non-root `itest` user (matches hermetic 0700/0600 file-permission checks).
RUN groupadd --gid 1001 itest \
    && useradd --uid 1001 --gid 1001 --create-home --shell /bin/bash itest \
    && mkdir -p /workspace \
    && chown -R itest:itest /opt/hyphae-itest /workspace

USER itest
WORKDIR /workspace

CMD ["node", "/opt/hyphae-itest/src/scripts/provision.mjs", "--check"]
