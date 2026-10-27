#![no_main]
//! Fuzz action-parameter decoding through the public path the daemon uses,
//! `build_action_spec(action_name, &params)`, over arbitrary JSON.
//!
//! Input layout: two bytes (little endian) pick an action from
//! `KNOWN_ACTION_NAMES`, or an unknown name when the index lands one past the
//! end; the rest is parsed as JSON and handed over as `params`. Input that is
//! not JSON is skipped, since the daemon decodes the envelope before it ever
//! builds a spec.
//!
//! The call must return a spec or an error and never panic. A command spec must
//! also name a program.

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use sysknife_daemon::actions::ActionMechanism;
use sysknife_daemon::executor::build_action_spec;
use sysknife_types::KNOWN_ACTION_NAMES;

fuzz_target!(|data: &[u8]| {
    let Some((selector, json)) = data.split_first_chunk::<2>() else {
        return;
    };
    let index = usize::from(u16::from_le_bytes(*selector)) % (KNOWN_ACTION_NAMES.len() + 1);
    let name = KNOWN_ACTION_NAMES
        .get(index)
        .copied()
        .unwrap_or("NoSuchAction");
    let Ok(params) = serde_json::from_slice::<Value>(json) else {
        return;
    };

    let Ok(spec) = build_action_spec(name, &params) else {
        return;
    };

    if let ActionMechanism::Command { program, .. } = &spec.mechanism {
        assert!(!program.is_empty(), "{name}: empty program");
    }
});
