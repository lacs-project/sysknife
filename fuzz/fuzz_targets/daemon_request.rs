#![no_main]
//! Fuzz `DaemonRequest` deserialisation from arbitrary bytes.
//!
//! `DaemonRequest` is private to the daemon's dispatcher, so the target goes
//! through `fuzz_decode_request`, which repeats the connection loop's two-step
//! decode (`serde_json::from_slice` into a `Value`, then `from_value` into the
//! enum). A frame from any peer must end in a request or in an error, never in
//! a panic: a panic here would let an unauthenticated byte string take down the
//! connection task.

use libfuzzer_sys::fuzz_target;
use sysknife_daemon::fuzzing::fuzz_decode_request;

fuzz_target!(|data: &[u8]| {
    std::hint::black_box(fuzz_decode_request(data));
});
