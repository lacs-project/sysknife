# Build image for ClusterFuzzLite (see .github/workflows/cflite_pr.yml). It is
# built from the repository root, so `.dockerignore` decides which files reach
# the `COPY` below; it lists `fuzz/` and `.clusterfuzzlite/` for that reason.
#
# Pinned by digest like the root Dockerfile: the tag alone can move. The base
# image carries `cargo fuzz` and a nightly Rust toolchain.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f

# The base image's nightly (2025-09-05, rustc 1.91) is older than sqlx 0.9
# accepts (rustc 1.94). Install a dated nightly and select it. Raise the date when
# a dependency asks for a newer compiler.
RUN rustup toolchain install nightly-2026-10-26 --profile minimal --component rust-src
ENV RUSTUP_TOOLCHAIN=nightly-2026-10-26

COPY . $SRC/sysknife
WORKDIR $SRC/sysknife
COPY .clusterfuzzlite/build.sh $SRC/
