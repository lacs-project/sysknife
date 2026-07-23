# syntax=docker/dockerfile:1
#
# Glama starts this image to inspect the MCP server over stdio. The privileged
# sysknife-daemon remains external to the container: this image only publishes
# the CLI's MCP transport and never grants it host administration access.
FROM docker.io/library/rust:1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/sysknife-cli ./apps/sysknife-cli
# Cargo resolves every workspace member before selecting sysknife-cli.
COPY apps/sysknife-shell/src-tauri ./apps/sysknife-shell/src-tauri
RUN cargo build --locked --release --package sysknife-cli

FROM docker.io/library/debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin sysknife

COPY --from=builder /src/target/release/sysknife /usr/local/bin/sysknife

USER sysknife
ENTRYPOINT ["sysknife", "mcp-server"]
