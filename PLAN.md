# OSS Contribution Plan: sysknife (Issues #230, #281)

## Scope
Fix two related correctness bugs in the SysKnife protocol framing and envelope encoding.

## Issue #230: Frame limit constant duplication
**Problem**: The 4 MiB frame limit is declared three times with different types (`usize`, `u32`) in three crates. Each side can move independently, causing drift.

**Files**:
- `crates/sysknife-daemon/src/transport/framing.rs` — declare shared constant
- `apps/sysknife-cli/src/client.rs` — use shared constant
- `apps/sysknife-shell/src-tauri/src/daemon_client.rs` — use shared constant
- Add test in `crates/sysknife-daemon/src/transport/framing.rs` asserting equality

**Test command**: `cargo nextest run --workspace --locked`

**Acceptance criteria**:
1. Constant declared once in `framing.rs` with `usize` type.
2. All three uses reference the same constant.
3. Test fails when constants differ, passes when equal.
4. All workspace tests pass.

**Risk**: Low. Only affects framing checks, not data flow.

---

## Issue #281: Hand-typed wire numbers
**Problem**: Outbound encoding uses hand-typed code tables (`caller_role_code`, `risk_level_code`, `job_state_code`). Inbound decoding uses generated enums from `.proto`. If `.proto` is renumbered, outbound keeps the old numbers, causing misinterpretation.

**Files**:
- `crates/sysknife-types/src/lib.rs` — replace 3 functions with enum conversions

**Test command**: `cargo nextest run --workspace --locked`

**Acceptance criteria**:
1. Replace each `*_code(value)` call with `i32::from(proto::X::from(value))`.
2. Delete the three hand-typed functions (lines ~589-616).
3. All existing tests pass.
4. Round-trip tests already use generated enum on decode; verify they still pass.

**Risk**: Low. Minimal scope (one file, ~30 lines changed). TDD: existing tests should pass without mutation.

---

## TDD Strategy
1. Write PLAN.md (this file).
2. **For #230**: Add test `assert_constant_equal()` that fails when constants differ, passes when equal.
3. **For #281**: Verify all tests pass with current code (they already use generated enum on decode).
4. Make minimal changes to satisfy tests.
5. Run full workspace test suite.
6. If any test fails, diagnose and fix iteratively (max 3 iterations).

## Pre-flight checklist
- [x] Research done (gh issue threads, contributing guide).
- [x] No claims/PRs exist for these issues.
- [x] Test command confirmed: `cargo nextest run --workspace --locked`
