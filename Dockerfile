# syntax=docker/dockerfile:1
#
# Glama starts this image to inspect the MCP server over stdio. The privileged
# sysknife-daemon remains external to the container: this image only publishes
# the CLI's MCP transport and never grants it host administration access.
# Base images are pinned by manifest-list digest (not just tag) so a moved or
# compromised tag cannot silently change the build. Dependabot's Docker
# ecosystem tracks these and bumps both the tag and the digest together.
FROM docker.io/library/rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/sysknife-cli ./apps/sysknife-cli
# Cargo resolves every workspace member before selecting sysknife-cli.
COPY apps/sysknife-shell/src-tauri ./apps/sysknife-shell/src-tauri
RUN cargo build --locked --release --package sysknife-cli

FROM docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin sysknife

COPY --from=builder /src/target/release/sysknife /usr/local/bin/sysknife

USER sysknife
ENTRYPOINT ["sysknife", "mcp-server"]
