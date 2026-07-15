# Stable Fuzz Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate duration-shutdown flakes from all four GitHub Actions fuzz-smoke steps and merge the verified PR.

**Architecture:** Keep the existing four independent Go fuzz targets and replace only their duration limits with a uniform fixed execution count. Verify the workflow contract locally, then use GitHub Actions as the authoritative Linux check before merging and deleting the feature branch.

**Tech Stack:** GitHub Actions YAML, Go 1.26 fuzzing, Ruby Psych, Git, GitHub CLI.

## Global Constraints

- Do not change production Go code.
- Keep all four fuzz targets enabled.
- Use exactly `-fuzztime=250000x` for each fuzz-smoke command.
- Do not merge until PR #2 checks have completed successfully.
- Preserve the user's three pre-existing untracked documents and the audit worktree's untracked `.superpowers/` evidence.

---

### Task 1: Make fuzz-smoke deterministic

**Files:**
- Modify: `.github/workflows/ci.yml`
- Test: YAML-aware workflow contract and the four existing Go fuzz targets

**Interfaces:**
- Consumes: Go's documented `Nx` fuzztime syntax.
- Produces: Four fixed-work fuzz-smoke commands without a wall-clock fuzz deadline.

- [ ] **Step 1: Run the YAML-aware contract before editing**

Run a Ruby/Psych assertion that requires four `-fuzztime=250000x` commands and
rejects duration syntax. Expected: FAIL because the workflow still contains
four `-fuzztime=10s` commands.

- [ ] **Step 2: Change all four fuzz-smoke commands**

Replace each `-fuzztime=10s` with `-fuzztime=250000x` in
`.github/workflows/ci.yml`; do not alter target names, packages, CGO settings,
or job timeout.

- [ ] **Step 3: Re-run the workflow contract**

Expected: PASS with exactly four fixed-count commands and zero duration-based
fuzz commands.

- [ ] **Step 4: Run all four fixed-count fuzz targets**

Run the HTML, URL, source-map, and API fuzz targets with four workers. Expected:
all four commands exit zero after 250,000 executions.

- [ ] **Step 5: Run repository verification**

Parse `.github/workflows/ci.yml` and `.github/workflows/release.yml`, run
`git diff --check`, and run `CGO_ENABLED=1 go test -count=1 ./...`. Expected:
all checks pass.

- [ ] **Step 6: Commit and push**

Commit the design, plan, and workflow change with message
`Fix flaky fuzz smoke shutdown`, then push `codex/full-audit-remediation`.

### Task 2: Verify and integrate

**Files:**
- No additional tracked file changes.

**Interfaces:**
- Consumes: PR #2 checks at the pushed commit.
- Produces: remote and local `main` containing the verified fix, with the feature branch removed.

- [ ] **Step 1: Wait for PR checks**

Use `gh pr checks 2 --watch` and inspect any failure logs. Expected: every
required GitHub Actions check completes successfully.

- [ ] **Step 2: Merge PR #2**

Merge only after checks are green, then verify remote `main` contains the
pushed head commit.

- [ ] **Step 3: Synchronize local main**

Fast-forward local `main` to `origin/main` and run the full Go test suite on the
merged result.

- [ ] **Step 4: Delete the feature branch safely**

Delete the remote feature branch. Detach the feature worktree to preserve its
untracked audit evidence, then delete the local feature branch and verify both
branch refs are absent.
