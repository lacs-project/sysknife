pub mod actions;
pub mod audit_chain;
pub mod audit_forward;
pub mod audit_watermark;
pub mod auth;
pub mod checkpoint_sink;
pub mod dispatcher;
pub mod executor;
pub mod jobs;
mod pg_tls;
pub mod policy;
pub mod preview;
pub mod state;
pub mod state_collector;
pub mod store;
pub mod transactions;
pub mod transport {
    pub mod framing;
    pub mod listen;
}

/// Entry points for the cargo-fuzz targets in `fuzz/`. cargo-fuzz builds with
/// `--cfg fuzzing`, so none of this exists in a normal or release build. The
/// validators live in a `pub(crate)` module; a glob re-export makes every
/// `pub fn` in it reachable here without widening the module itself.
#[cfg(fuzzing)]
pub mod fuzzing {
    pub use crate::actions::validate::*;
    pub use crate::dispatcher::fuzz_decode_request;
}
