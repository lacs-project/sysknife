# Build image for ClusterFuzzLite (see .github/workflows/cflite_pr.yml). It is
# built from the repository root, so `.dockerignore` decides which files reach
# the `COPY` below; it lists `fuzz/` and `.clusterfuzzlite/` for that reason.
#
# Pinned by digest like the root Dockerfile: the tag alone can move. The base
# image carries `cargo fuzz` and a nightly Rust toolchain.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:2216f0ac0a289a0e8974917779c3f744c354067dd81e0c8f2fc53bc1a9a573db

# The base image's nightly (2025-09-05, rustc 1.91) is older than sqlx 0.9
# accepts (rustc 1.94). Install a dated nightly and select it. Raise the date when
# a dependency asks for a newer compiler.
RUN rustup toolchain install nightly-2026-10-26 --profile minimal --component rust-src
ENV RUSTUP_TOOLCHAIN=nightly-2026-10-26

COPY . $SRC/sysknife
WORKDIR $SRC/sysknife
COPY .clusterfuzzlite/build.sh $SRC/
