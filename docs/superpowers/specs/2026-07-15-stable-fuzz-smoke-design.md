# Stable Fuzz Smoke Design

## Context

PR #2's `fuzz-smoke` job failed in Go 1.26.5 with a bare
`context deadline exceeded` exactly when `-fuzztime=10s` expired. The log did
not identify a failing corpus input or a `t.Fatalf` source line. Five local
repetitions of the same source-map fuzz target with Go 1.26.5 and four workers
passed. Inspection of Go's fuzz coordinator shows that duration-based fuzzing
uses a context deadline to stop all worker processes, so the failure is in the
time-based shutdown path rather than a parser assertion.

Every step in the current `fuzz-smoke` job uses duration-based fuzzing. Fixing
only the source-map step would leave the HTML, URL, and API fuzz steps exposed
to the same shutdown race.

## Approaches Considered

1. **Use a fixed execution count for all four fuzz targets (selected).** This
   avoids the overall wall-clock deadline while retaining Go's independent
   per-input timeout and gives CI a deterministic amount of fuzz work.
2. **Retry the failed job.** This would usually pass but would hide rather than
   remove the flaky shutdown path.
3. **Increase the duration.** This changes when the same shutdown race occurs
   and makes CI slower without changing the failure mechanism.

## Design

Change each `fuzz-smoke` command in `.github/workflows/ci.yml` from
`-fuzztime=10s` to `-fuzztime=250000x`. A uniform count keeps the workflow easy
to review and still exercises every target substantially. The workflow's
existing ten-minute job timeout remains the outer safety bound.

Validation has four layers:

1. A YAML-aware static contract rejects duration-based fuzz commands and
   requires exactly four fixed-count commands.
2. Run each fixed-count fuzz command locally with four workers.
3. Parse both workflow YAML files and run the normal full Go test suite.
4. Push the feature branch and require PR #2's GitHub Actions checks to finish
   successfully before merging.

## Repository Completion

After checks pass, merge PR #2 into remote `main`, fast-forward the local
`main`, delete the remote feature branch, detach the retained audit worktree so
its untracked `.superpowers/` evidence is not destroyed, and delete the local
feature branch.
