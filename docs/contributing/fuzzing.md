# Fuzzing the trust boundary

SysKnife's safety rests on code that takes a string from a model or a client and
decides what reaches `sudo`: the `validated_*` functions, the typed-parameter
decoding behind `build_action_spec`, and the daemon's request and frame
decoding. The fuzz targets in `fuzz/` feed that code arbitrary bytes and check
what comes back. They are [cargo-fuzz](https://rust-fuzz.github.io/book/)
targets, and ClusterFuzzLite runs them on pull requests.

## What each target covers

| Target | Entry point | Checked on every input |
|---|---|---|
| `validators` | every `validated_*` function in `crates/sysknife-daemon/src/actions/validate.rs` | Never panics. Whatever a validator accepts has no control character (so no NUL), no leading `-` where the value would be read as an option, the documented length bound, the documented character set, and the shape its doc comment promises. |
| `action_spec` | `build_action_spec(name, &params)` over arbitrary JSON | Never panics. A command spec names a program. |
| `daemon_request` | the request decode in the connection loop (`DaemonRequest`) | Never panics. |
| `frame_recv` | `FramedStream::recv`, the length-prefixed frame reader | The result matches an independent reading of the wire format: the exact body, `MessageTooLarge`, or an unexpected-EOF error. |

The first byte of a `validators` input picks the validator, the rest is the
string. The first two bytes of an `action_spec` input pick the action from
`KNOWN_ACTION_NAMES`, the rest is the JSON.

## Run a target on your machine

You need a nightly toolchain, a C compiler (the daemon bundles SQLite) and
`cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Run a target for a minute from the repository root:

```sh
export ASAN_OPTIONS=detect_odr_violation=0
mkdir -p /tmp/validators-corpus
cargo +nightly fuzz run -O --debug-assertions validators \
  /tmp/validators-corpus fuzz/corpus/validators \
  -- -dict=fuzz/dictionaries/validators.dict -max_total_time=60
```

- `fuzz/corpus/<target>/` holds the committed seeds. libFuzzer writes new inputs
  into the first corpus directory it is given, so pass a scratch directory first
  and the seeds second, and the seeds stay as they are.
- `--debug-assertions` turns on overflow checks, so an arithmetic overflow fails
  the run instead of wrapping.
- The `ASAN_OPTIONS` line is a local workaround. AddressSanitizer can report an
  `odr-violation` on `aiOff` in the bundled SQLite: two constants with the same
  name and contents that the linker merges into one. ClusterFuzzLite turns the
  check off by default.
- `fuzz/dictionaries/<target>.dict` lists the keywords and field names the
  target compares against. `frame_recv` has none.

At the end of a run, `stat::number_of_executed_units` shows how many inputs ran
and the last `cov:` figure shows how much code they reached.

## Reproduce a crash

libFuzzer writes the failing input to `fuzz/artifacts/<target>/crash-<hash>`.
Replay it, then shrink it:

```sh
cargo +nightly fuzz run -O --debug-assertions validators fuzz/artifacts/validators/crash-<hash>
cargo +nightly fuzz tmin -O --debug-assertions validators fuzz/artifacts/validators/crash-<hash>
```

A crash in a validator can be a security issue. Report it through
[SECURITY.md](https://github.com/lacs-project/sysknife/blob/main/SECURITY.md) and leave it out of public issues and pull
requests.

## How it is wired

`fuzz/` is its own Cargo workspace. The repository's `Cargo.toml` and
`Cargo.lock` do not list it, so `cargo build --workspace` never compiles
libFuzzer's C++ runtime and the main lockfile stays as it is. `fuzz/Cargo.lock`
pins the fuzz crate's own dependencies.

The validators live in a `pub(crate)` module and `DaemonRequest` is private, so
the daemon exposes them to the fuzz crate in a `pub mod fuzzing` that exists under
`#[cfg(fuzzing)]` and nowhere else (see `crates/sysknife-daemon/src/lib.rs`).
cargo-fuzz sets that cfg for its builds. A normal or release build of the daemon
does not contain the module, and its public API is unchanged.

ClusterFuzzLite builds with `.clusterfuzzlite/Dockerfile` and `build.sh`, which
build every file in `fuzz/fuzz_targets/` and zip its seeds next to the binary.
The Dockerfile installs a dated nightly toolchain, because the nightly in its
base image is older than the daemon's dependencies accept. Raise the date when a
dependency asks for a newer compiler.
`.github/workflows/cflite_pr.yml` runs the targets for five minutes on pull
requests that touch `crates/` or the fuzz setup. The Dockerfile copies the
whole build context, so `.dockerignore` lets `fuzz/` and `.clusterfuzzlite/`
through.

## Add a validator

1. Add a row at the **end** of `SPECS` in `fuzz/fuzz_targets/validators.rs`. The
   selector byte of every seed is the row index, so inserting in the middle
   points the old seeds at the wrong validator.
2. Fill in the row from the validator's doc comment: the longest value it may
   accept, the characters it may contain, whether it refuses a leading `-`, and
   an `extra` function for any shape rule (an allowlist, a denylist, a prefix).
   Restate these from the contract. A copy of the validator's own code always
   agrees with the validator.
3. Add seeds under `fuzz/corpus/validators/`: one file per case, first byte the
   row index, the rest the string. The existing seeds come from the string
   literals in the unit tests of `validate.rs`, and libFuzzer names a seed by its
   SHA-1 (`sha1sum`).

## Add a target

1. Create `fuzz/fuzz_targets/<name>.rs` with `fuzz_target!` and a `[[bin]]` entry
   in `fuzz/Cargo.toml`.
2. Put seeds in `fuzz/corpus/<name>/`, and a dictionary in
   `fuzz/dictionaries/<name>.dict` if the input has keywords.
3. If the code under test is private to the daemon, add an entry point to the
   `fuzzing` module in `crates/sysknife-daemon/src/lib.rs`, behind
   `#[cfg(fuzzing)]`. Do not widen the daemon's normal public API for a fuzzer.

`.clusterfuzzlite/build.sh` finds the new target on its own.
