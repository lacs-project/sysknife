# Evidence for published numbers

Every figure SysKnife publishes — test counts, the action count, story pass rates
— is checked against a file in here by `scripts/check_evidence_claims.py`, which
runs as part of `scripts/check_public_claims.sh` in CI. A number that no artifact
produces fails the build.

This exists because the README claimed "65/65 stories" validated on a live VM in
eight places. No run ever produced that figure; no story set of that size had
existed, and the Ubuntu family then contained 50 stories (79 since every
Debian-only action got one). The test count had rotted the other way: three docs
said "1,561 Rust tests" and the claims checker *required* that exact string while
the suite had grown past 1,600.

Nothing here is filled in by hand, including by way of illustration — a number in
this directory is a claim, and the point of the directory is that claims come from
runs.

### Why every replay twin used to fail, and what fixed it

Each LTS carried a `.replay.json` whose `cassette_audit.verdict` was `failed`,
on a different story each time — 101 on 22.04, 119 on 24.04, 125 and 130 on
26.04. Three symptoms, one cause, and it was not the stories.

The provider sometimes rejects a tool call the model emitted under a name that
is not in `request.tools` (Groq words it `code: "tool_use_failed"`). The planner
handles that: it appends a correction and re-asks, because re-sending identical
bytes reproduces the identical malformed answer. The cassette, however, stored
only *successes* — so the only entry written for such a story was the **second**
call, the one carrying the correction. A replay starts from the first, finds no
entry, and then, because a `CassetteMiss` carries none of the markers that
trigger a correction, re-sends identical bytes and misses again.

The diagnostic said so once the harness started collecting the CLI's stderr:

> no recorded output for this intent. The prompt and tools match, so the
> cassette is current — this particular request was never recorded

Cassette v2 records the rejection too (`entries[].rejection`), for exactly the
failures the planner corrects and no others — the two sets are one predicate,
`ProviderError::is_invalid_tool_call`, so a recorder narrower than the retrier
cannot leave a retried run unreplayable and a wider one cannot serve a transient
failure back for ever. A replay now takes the same path the live run took: the
recorded rejection, the correction, the recorded answer.

Two things this cost, worth stating because both are easy to repeat:

- The first attempt matched `ProviderError::Http { status: 400, .. }`. **No
  adapter constructs that variant** — a 400 is classified `StatusClass::Other`
  and arrives as `Request`. Three new tests were green against a shape the
  system cannot produce, and the proof was a recording made with that build:
  cassette `v2`, zero rejections.
- `check_evidence_claims.py` let a release be tiered **Validated** on a replay
  twin that merely *existed*. A pass-rate figure was already refused on a
  `failed` verdict; the tier was not. It is now, so "Validated" means the twin
  reproduced the run.

## `workspace-tests.json`

Suite sizes, one field per suite, each written by the command that measured it:

```sh
UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh              # Rust workspace
UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh --frontend   # vitest
```

Without `UPDATE_TEST_BASELINE` those commands *verify* instead, and they are what
CI runs in place of the bare test commands — so a suite that grows without the
baseline moving fails in the job that knows the real number.

## `story-runs/*.json`

One file per live-VM story run, written by `tests/e2e/run-stories.sh` when
`SYSKNIFE_RESULTS_JSON` is set. Each records the release, the provider/model
surface, the cassette mode and hash, per-story verdicts, and the totals. See
`docs/contributing/ubuntu-vm-testing.md` for the full recording procedure.

Only a run of a complete story family (`ubuntu` or `atomic`) may back a published
figure. Subset runs record an empty `story_set`, so a four-story probe cannot be
quoted as a headline result.

Regenerating any of these is a deliberate act with a real run behind it. Editing
one by hand defeats the only thing it is for.
