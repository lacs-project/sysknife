#!/bin/bash -eu
# Builds the cargo-fuzz targets under fuzz/ for ClusterFuzzLite. Runs inside the
# image from .clusterfuzzlite/Dockerfile, where the repository is $SRC/sysknife
# and $OUT is where ClusterFuzzLite collects fuzz targets, seed corpora and
# dictionaries.

cd "$SRC/sysknife"

# Fail on a stale fuzz/Cargo.lock instead of resolving dependencies afresh.
cargo fetch --locked --manifest-path fuzz/Cargo.toml

# -O builds in release mode. --debug-assertions also turns on overflow checks,
# so an arithmetic overflow fails the fuzzer instead of wrapping.
cargo fuzz build -O --debug-assertions

release=fuzz/target/x86_64-unknown-linux-gnu/release
for source in fuzz/fuzz_targets/*.rs; do
    target="$(basename "${source%.rs}")"
    cp "$release/$target" "$OUT/"
    # ClusterFuzzLite starts each run from <target>_seed_corpus.zip and
    # <target>.dict when they sit next to the binary.
    zip -qj "$OUT/${target}_seed_corpus.zip" "fuzz/corpus/$target"/*
    if [ -f "fuzz/dictionaries/$target.dict" ]; then
        cp "fuzz/dictionaries/$target.dict" "$OUT/"
    fi
done
