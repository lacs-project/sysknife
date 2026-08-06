# Evidence for published numbers

Every figure SysKnife publishes — test counts, the action count, story pass rates
— is checked against a file in here by `scripts/check_evidence_claims.py`, which
runs as part of `scripts/check_public_claims.sh` in CI. A number that no artifact
produces fails the build.

This exists because the README claimed "65/65 stories" validated on a live VM in
eight places. No run ever produced that figure; no story set of that size has
existed, and the Ubuntu family contains 50 stories. The test count had rotted the
other way: three docs said "1,561 Rust tests" and the claims checker *required*
that exact string while the suite had grown past 1,600.

Nothing here is filled in by hand, including by way of illustration — a number in
this directory is a claim, and the point of the directory is that claims come from
runs.

### The committed 22.04 run

`story-runs/ubuntu-22.04-gpt-oss-120b.json` records 49/50 with
`openai/gpt-oss-120b`. The one failure is story 101, and it is not a planning
defect: the model produced exactly the plan the story accepts
(`ListContainers{username:root}`) but emitted it under the tool name
`commentary`, which the provider rejected with `tool_use_failed` (HTTP 400). It
reproduced on retry, so it is a model/provider interaction rather than a transient
one. See #178 for the retry gap it exposes.

The matching cassette covers 48 of the 50 stories. Two calls are not replayable,
for different reasons, and a full-family replay therefore reports 2 misses and
fails by design:

- **story 101** — no successful response was ever returned, so there was nothing
  to record.
- **story 91** — a multi-turn run whose later turns are not reproducible from the
  recorded first turn.

That is the miss guard behaving correctly: it refuses to call a run reproduced
when it was not. Closing the gap is part of the replay-gate work, not something to
paper over by trimming the story set.

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
