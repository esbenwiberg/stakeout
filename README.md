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

Pin to a specific release tag rather than `@main` — `@main` is a mutable
reference and could change under you:

```yaml
      - uses: esbenwiberg/stakeout@v1
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

### Creating or updating `.stakeout.yml`

The file is optional — if it's absent, built-in defaults apply (`minimumAgeDays: 7`,
`failOn: violation`, public npm registry). Create it in the repo root when you need
to change a default or manage exemptions.

**Common workflows:**

**1. Wait and rebase (no config change needed)**
The check output prints `eligible on YYYY-MM-DD` for each violation. Once that
date passes, rebasing the PR will make the check pass with no config edits.

**2. Add a CVE exemption for a security bump that can't wait**

```yaml
# .stakeout.yml
exemptions:
  - package: lodash
    version: 4.17.25
    reason: CVE-2026-1234   # must be a real CVE / GHSA / OSV id
    expires: 2026-07-01     # set ~2–4 weeks out; expired entries are flagged stale
```

`reason` is verified against OSV.dev by default — it must be an advisory that
actually affects the version you're upgrading *away from*. Set a short `expires`
date; once the version ages past `minimumAgeDays` naturally you can remove the
entry (or leave it — stale exemptions are reported as warnings, not failures).

**3. Skip a private package scope**

If your registry 404s on packages from an internal feed, stakeout skips them
with a warning. To suppress the warning and avoid any accidental public-registry
name collision, list the scope:

```yaml
# .stakeout.yml
skipScopes:
  - "@mycompany"
```

**4. Roll out gradually with `failOn: warn`**

Set `failOn: warn` while bedding the gate in — violations are reported but the
check exits 0, so PRs still merge. Flip to `violation` once the team is used to
the workflow.

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

## Locking `package.json` versions

stakeout catches too-young versions that appear in the lockfile diff, but `^`
and `~` ranges in `package.json` mean a fresh `npm install` or `pnpm install`
can silently resolve to a newer version — bypassing the lockfile if it's ever
regenerated. Use exact versions so the lockfile is the only place versions
change, and every bump surfaces as a diff that stakeout will catch.

**npm** — add to `.npmrc`:
```
save-exact=true
```

**pnpm** — add to `.npmrc`:
```
save-exact=true
```

With exact pins, the only way a new version enters the lockfile is an explicit
`npm update` / `pnpm update`, which produces a lockfile diff on the PR.

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
