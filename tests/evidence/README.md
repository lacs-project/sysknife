# Evidence for published numbers

Every figure SysKnife publishes — test counts, the action count, story pass rates
— is checked against a file in here by `scripts/check_evidence_claims.py`, which
runs as part of `scripts/check_public_claims.sh` in CI. A number that no artifact
produces fails the build.

This exists because the README claimed "65/65 stories" validated on a live VM in
eight places. No run ever produced that figure; no story set of that size has
existed, and the Ubuntu family contains 50 stories. The first measurements
traceable to a run are 46/50 on 22.04 and 45/50 on 24.04 with
`openai/gpt-oss-120b`. The test count had rotted the other way: three docs said
"1,561 Rust tests" and the claims checker *required* that exact string while the
suite had grown past 1,600.

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
