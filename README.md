# stakeout

CI gate that fails a PR when its lockfile diff introduces an npm package
version younger than a configured minimum age (default **7 days**) — unless an
in-repo, CVE-referenced exemption covers it.

Recent npm supply-chain attacks were detected and unpublished within
hours-to-days of release. Refusing freshly published versions removes most of
that exposure window. The check is diff-based: only `(package, version)` pairs
*new* to the lockfile are checked, transitives included. Downgrades and
removals introduce nothing new and pass.

Zero dependencies — one Node script plus a composite GitHub Action.

## Usage

```yaml
# .github/workflows/stakeout.yml in the consuming repo
name: stakeout
on: pull_request
jobs:
  stakeout:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: esbenwiberg/stakeout@main
```

The action diffs `pnpm-lock.yaml` and/or `package-lock.json` at the repo root
against the PR's base branch and exits:

| code | meaning |
|---|---|
| 0 | clean, fully exempted, or `failOn: warn` |
| 1 | violations (version too young, or stale/rejected exemption) |
| 2 | operational error — bad config, unparsable lockfile, registry metadata unavailable. **Fails closed**: a gate that fails open is not a gate. |

A machine-readable `stakeout-report.json` is written to the workspace root and a
summary table is appended to the GitHub step summary.

### Action inputs

| input | default | |
|---|---|---|
| `config` | `.stakeout.yml` | Config path; missing default file → built-in defaults |
| `base-ref` | PR base branch | Override what to diff against |
| `report` | `stakeout-report.json` | JSON report path |

## Configuration (`.stakeout.yml`)

```yaml
minimumAgeDays: 7
failOn: violation        # violation | warn (warn = report but exit 0, for rollout)
registry: https://registry.npmjs.org
verifyCveExemptions: true
skipScopes:              # private scopes that don't exist on the public registry
  - "@contextand"
exemptions:
  - package: lodash
    version: 4.17.25
    reason: CVE-2026-1234   # must be a CVE / GHSA / OSV id
    expires: 2026-07-01     # required; expired exemptions are ignored and flagged stale
```

Unknown keys are rejected. See `.stakeout.yml.example` for a commented copy.

### Exemptions

A version younger than the threshold passes only if an exemption matches its
exact name and version. The reason **must** be a security-advisory id; with
`verifyCveExemptions: true` (the default) the advisory is checked against
[OSV.dev](https://osv.dev) and must actually affect the version being upgraded
away from — fabricated ids are rejected. If OSV itself is unreachable, only
the verification degrades (exemption accepted with a warning and an
`osv: unavailable` flag in the report); the core age check never degrades.

The cheapest fix for a violation is usually to wait: every violation is
reported with the date the version becomes eligible. Rebase after that date.

## Local / CI-less usage

```bash
node stakeout.mjs check --base-ref origin/main            # git mode, like the action
node stakeout.mjs check --base old.lock.yaml --head pnpm-lock.yaml   # explicit files
```

Flags: `--config`, `--report`, `--now <iso>` (test clock), and
`--registry-fixture` / `--osv-fixture` (directories of canned JSON responses,
used by the offline test suite).

## Report schema

`stakeout-report.json`: `{ schemaVersion, now, minimumAgeDays, failOn, results,
summary, exitCode }` where each result is
`{ name, version, baseVersion?, publishedAt?, ageDays?, eligibleOn?, status,
exemption?, note?, error? }` and `status` is one of
`pass | violation | exempted | stale-exemption | skipped | error`.

## Tests

Offline, zero-dependency:

```bash
node --test tests/stakeout.test.mjs
```

## Scope notes

- Lockfiles supported: `pnpm-lock.yaml` v6/v9, `package-lock.json` v2/v3 —
  unknown versions exit 2 with a clear message rather than guessing.
- Lockfiles are discovered at the repo root only (v1).
- Non-registry deps (git/file/link) are skipped — no publish date exists.
- Packages **not found** (404) on the configured registry are skipped with a
  warning rather than failing the run — typical when the repo installs from a
  private feed but stakeout checks the public registry. A package absent from
  the registry can't have been installed from it, so this doesn't weaken the
  gate. Network failures and 5xx still fail closed. Caveat: a private package
  whose *name also exists* on the public registry gets checked against the
  public package's dates — list private scopes in `skipScopes` to avoid that.
- Registry: one metadata fetch per package per run, concurrency-capped at 8,
  3 attempts with exponential backoff, `Retry-After` honored on 429.
