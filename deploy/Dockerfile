# syntax=docker/dockerfile:1
# Hyphae v2 multi-stage Rust build (non-root UID 10001)
# Build from repository root:
#   docker build -f deploy/Dockerfile -t hyphae-node:latest .

FROM rust:1.87-bookworm AS builder
WORKDIR /src

# Copy workspace manifests, Rust crates, and all compile-time assets read by
# crates/hyp-cli/build.rs and include_str!() macros (plugins/, skills/, scripts/).
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY plugins ./plugins
COPY skills ./skills
COPY scripts ./scripts

RUN cargo build --release --locked -p hyp-cli

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 hyphae \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/hyphae --shell /usr/sbin/nologin hyphae \
    && mkdir -p /var/lib/hyphae /etc/hyphae \
    && chown 10001:10001 /var/lib/hyphae /etc/hyphae \
    && chmod 0700 /var/lib/hyphae

COPY --from=builder /src/target/release/hyp /usr/local/bin/hyp

ENV HYPHAE_SECRET_BACKEND=file \
    HYPHAE_STATE_DIR=/var/lib/hyphae \
    HYPHAE_CONFIG=/etc/hyphae/node.json

USER 10001:10001
WORKDIR /var/lib/hyphae
EXPOSE 8790

# Built-in manifest + anti-recon check (zero external curl/wget needed);
# external load balancers/probes may also hit GET /v1/health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/hyp", "deploy", "check", "--url", "http://127.0.0.1:8790", "--json"]

ENTRYPOINT ["/usr/local/bin/hyp"]
CMD ["node", "start", "--config", "/etc/hyphae/node.json", "--bind", "0.0.0.0:8790", "--no-local-socket"]
