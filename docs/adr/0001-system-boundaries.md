# ADR 0001: System Boundaries

## Status

Accepted.

## Context

SysKnife exists to let an agent perform real Linux administration without
granting it arbitrary shell access or root.

## Decision

SysKnife uses three separate roles:

- `sysknife-brain` plans
- `sysknife-shell` presents and collects approval
- `sysknife-daemon` executes

The daemon is the only privileged executor. The brain is never
allowed to mutate the system directly.

## Consequences

- The trust boundary is simple and auditable.
- The shell remains a client instead of a second privileged runtime.
- The daemon can enforce policy, preview, transaction logging, and
  rollback in one place.
- The project can grow without collapsing into an unsafe command runner.
