// Offline test suite for stakeout. Run with:  node --test stakeout/tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync, mkdtempSync, copyFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  OperationalError,
  DEFAULTS,
  parseConfigYaml,
  validateConfig,
  loadConfig,
  parsePnpmLock,
  parseNpmLock,
  diffLockfiles,
  createRegistryClient,
  runCheck,
} from "../stakeout.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIX = join(ROOT, "fixtures");
const NOW = new Date("2026-06-15T00:00:00Z");
const exec = promisify(execFile);

const lockMap = (entries) => new Map(entries.map(([n, vs]) => [n, new Set(vs)]));
const fixtureConfig = () => loadConfig(join(FIX, "stakeout.yml"));
const fixtureRegistry = { fixtureDir: join(FIX, "registry") };

async function runCli(args) {
  const report = join(mkdtempSync(join(tmpdir(), "stakeout-")), "report.json");
  let exitCode = 0;
  let stdout;
  try {
    ({ stdout } = await exec("node", ["stakeout.mjs", "check", ...args, "--report", report, "--now", NOW.toISOString()], { cwd: ROOT }));
  } catch (e) {
    exitCode = e.code;
    stdout = e.stdout;
  }
  return { exitCode, stdout, report: JSON.parse(readFileSync(report, "utf8")) };
}

// --- config ----------------------------------------------------------------

test("config: defaults applied when no file given", () => {
  assert.deepEqual(loadConfig(undefined), { ...DEFAULTS });
});

test("config: fixture file parses with skipScopes and exemptions", () => {
  const cfg = fixtureConfig();
  assert.equal(cfg.minimumAgeDays, 7);
  assert.deepEqual(cfg.skipScopes, ["@contextand"]);
  assert.equal(cfg.exemptions.length, 2);
  assert.equal(cfg.exemptions[0].reason, "CVE-2026-1234");
});

test("config: unknown keys rejected", () => {
  assert.throws(() => validateConfig({ minimumAge: 7 }, "t"), OperationalError);
});

test("config: exemption with non-advisory reason rejected", () => {
  const raw = parseConfigYaml(
    'exemptions:\n  - package: x\n    version: 1.0.0\n    reason: "because I said so"\n    expires: 2026-12-31\n',
    "t"
  );
  assert.throws(() => validateConfig(raw, "t"), /must be a CVE, GHSA, or OSV advisory id/);
});

test("config: exemption without expires rejected", () => {
  const raw = parseConfigYaml(
    "exemptions:\n  - package: x\n    version: 1.0.0\n    reason: CVE-2026-1234\n",
    "t"
  );
  assert.throws(() => validateConfig(raw, "t"), /missing required field "expires"/);
});

// --- lockfile parsing ------------------------------------------------------

test("pnpm v9: extracts plain, scoped, and peer-suffixed packages", () => {
  const map = parsePnpmLock(readFileSync(join(FIX, "lock-base.yaml"), "utf8"), "t");
  assert.ok(map.get("lodash").has("4.17.21"));
  assert.ok(map.get("@contextand/utils").has("1.0.0"));
  assert.ok(map.get("debug").has("4.4.0")); // peer suffix stripped
  assert.ok(map.get("ms").has("2.1.3"));
});

test("pnpm v6: leading-slash keys parse", () => {
  const text = "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n\n  '/@babel/core@7.24.0(supports-color@8.1.1)':\n    resolution: {integrity: sha512-y}\n";
  const map = parsePnpmLock(text, "t");
  assert.ok(map.get("lodash").has("4.17.21"));
  assert.ok(map.get("@babel/core").has("7.24.0"));
});

test("pnpm: unsupported lockfileVersion exits operationally", () => {
  assert.throws(() => parsePnpmLock("lockfileVersion: '5.4'\npackages:\n", "t"), /unsupported pnpm lockfileVersion/);
});

test("npm v3: extracts packages, skips root and non-registry entries", () => {
  const map = parseNpmLock(readFileSync(join(FIX, "npm", "package-lock-base.json"), "utf8"), "t");
  assert.ok(map.get("lodash").has("4.17.21"));
  assert.ok(map.get("ms").has("2.1.3"));
  assert.ok(!map.has("fixture-app"));
});

test("npm: lockfileVersion 1 rejected", () => {
  assert.throws(() => parseNpmLock('{"lockfileVersion": 1}', "t"), /unsupported npm lockfileVersion/);
});

// --- diff ------------------------------------------------------------------

test("diff: bump yields new pair with baseVersion; unchanged yields none", () => {
  const base = lockMap([["lodash", ["4.17.21"]]]);
  const head = lockMap([["lodash", ["4.17.22"]]]);
  assert.deepEqual(diffLockfiles(base, head, []), [
    { name: "lodash", version: "4.17.22", baseVersion: "4.17.21" },
  ]);
  assert.deepEqual(diffLockfiles(base, base, []), []);
});

test("diff: removal introduces nothing; skipScopes filters", () => {
  const base = lockMap([["lodash", ["4.17.21"]], ["ms", ["2.1.3"]]]);
  const head = lockMap([["lodash", ["4.17.21"]], ["@contextand/utils", ["2.0.0"]]]);
  assert.deepEqual(diffLockfiles(base, head, ["@contextand"]), []);
});

test("unchanged lockfile: exit 0 with zero registry lookups", async () => {
  const same = lockMap([["lodash", ["4.17.21"]]]);
  const report = await runCheck({
    base: same,
    head: same,
    config: { ...DEFAULTS },
    now: NOW,
    registryOpts: { fixtureDir: "/nonexistent" }, // would error on any lookup
  });
  assert.equal(report.exitCode, 0);
  assert.equal(report.summary.checked, 0);
});

// --- age check -------------------------------------------------------------

test("age boundary: exactly minimumAgeDays old passes (>= semantics)", async () => {
  const report = await runCheck({
    base: new Map(),
    head: lockMap([["left-pad", ["1.3.0"]]]), // published exactly 7d before NOW
    config: { ...DEFAULTS },
    now: NOW,
    registryOpts: fixtureRegistry,
  });
  assert.equal(report.results[0].status, "pass");
  assert.equal(report.results[0].ageDays, 7);
  assert.equal(report.exitCode, 0);
});

test("downgrade to an old version passes", async () => {
  const report = await runCheck({
    base: lockMap([["ms", ["2.1.3"]]]),
    head: lockMap([["ms", ["2.0.0"]]]),
    config: { ...DEFAULTS },
    now: NOW,
    registryOpts: fixtureRegistry,
  });
  assert.equal(report.results[0].status, "pass");
});

test("missing publish timestamp is an operational error (exit 2, fail closed)", async () => {
  const report = await runCheck({
    base: new Map(),
    head: lockMap([["ghost", ["1.0.1"]]]), // fixture has no time for 1.0.1
    config: { ...DEFAULTS },
    now: NOW,
    registryOpts: fixtureRegistry,
  });
  assert.equal(report.results[0].status, "error");
  assert.match(report.results[0].error, /no publish timestamp/);
  assert.equal(report.exitCode, 2);
});

test("private package: 404 on configured registry skips gracefully", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    return { status: 404, ok: false, headers: new Map() };
  };
  const report = await runCheck({
    base: new Map(),
    head: lockMap([["internal-tool", ["3.1.0"]]]),
    config: { ...DEFAULTS },
    now: NOW,
    registryOpts: { fetchImpl },
  });
  assert.equal(report.results[0].status, "skipped");
  assert.match(report.results[0].note, /not found at .* assumed private/);
  assert.equal(report.summary.skipped, 1);
  assert.equal(report.exitCode, 0);
  assert.equal(calls, 1); // 404 is definitive — no retries
});

// --- registry client -------------------------------------------------------

test("registry: 429 then success retries through", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    if (calls === 1) return { status: 429, ok: false, headers: new Map() };
    return { status: 200, ok: true, headers: new Map(), json: async () => ({ time: { "1.0.0": "2020-01-01T00:00:00Z" } }) };
  };
  const client = createRegistryClient({ registry: "https://r", backoffMs: 1, fetchImpl });
  assert.equal(await client.publishedAt("x", "1.0.0"), "2020-01-01T00:00:00Z");
  assert.equal(calls, 2);
});

test("registry: persistent failure exhausts retries and fails closed", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    throw new Error("ECONNREFUSED");
  };
  const client = createRegistryClient({ registry: "https://r", backoffMs: 1, fetchImpl });
  await assert.rejects(() => client.publishedAt("x", "1.0.0"), /after 3 attempts/);
  assert.equal(calls, 3);
});

test("registry: document fetched once per package across versions", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    return { status: 200, ok: true, headers: new Map(), json: async () => ({ time: { "1.0.0": "2020-01-01T00:00:00Z", "1.0.1": "2020-02-01T00:00:00Z" } }) };
  };
  const client = createRegistryClient({ registry: "https://r", fetchImpl });
  await Promise.all([client.publishedAt("x", "1.0.0"), client.publishedAt("x", "1.0.1")]);
  assert.equal(calls, 1);
});

// --- exemptions ------------------------------------------------------------

const exemptionConfig = (overrides = {}) => ({
  ...DEFAULTS,
  exemptions: [{ package: "lodash", version: "4.17.25", reason: "CVE-2026-1234", expires: "2026-12-31" }],
  ...overrides,
});

test("exemption: OSV-verified CVE exemption passes", async () => {
  const report = await runCheck({
    base: lockMap([["lodash", ["4.17.21"]]]),
    head: lockMap([["lodash", ["4.17.25"]]]),
    config: exemptionConfig(),
    now: NOW,
    registryOpts: fixtureRegistry,
    osvFixtureDir: join(FIX, "osv"),
  });
  assert.equal(report.results[0].status, "exempted");
  assert.deepEqual(report.results[0].exemption, { reason: "CVE-2026-1234", expires: "2026-12-31", osv: "verified" });
  assert.equal(report.exitCode, 0);
});

test("exemption: OSV rejects a CVE that does not affect the old version", async () => {
  const config = exemptionConfig();
  config.exemptions[0].reason = "CVE-2099-9999"; // not in the OSV fixture for lodash@4.17.21
  const report = await runCheck({
    base: lockMap([["lodash", ["4.17.21"]]]),
    head: lockMap([["lodash", ["4.17.25"]]]),
    config,
    now: NOW,
    registryOpts: fixtureRegistry,
    osvFixtureDir: join(FIX, "osv"),
  });
  assert.equal(report.results[0].status, "violation");
  assert.equal(report.results[0].exemption.osv, "rejected");
  assert.equal(report.exitCode, 1);
});

test("exemption: verifyCveExemptions=false skips OSV entirely", async () => {
  const report = await runCheck({
    base: lockMap([["lodash", ["4.17.21"]]]),
    head: lockMap([["lodash", ["4.17.25"]]]),
    config: exemptionConfig({ verifyCveExemptions: false }),
    now: NOW,
    registryOpts: fixtureRegistry,
    osvFixtureDir: "/nonexistent", // would matter only if OSV were consulted
  });
  assert.equal(report.results[0].status, "exempted");
  assert.equal(report.results[0].exemption.osv, "skipped");
});

test("exemption: expired exemption is ignored and reported stale", async () => {
  const report = await runCheck({
    base: lockMap([["minimist", ["1.2.8"]]]),
    head: lockMap([["minimist", ["1.2.9"]]]),
    config: fixtureConfig(), // minimist exemption expired 2026-01-01
    now: NOW,
    registryOpts: fixtureRegistry,
  });
  assert.equal(report.results[0].status, "stale-exemption");
  assert.equal(report.exitCode, 1);
});

test("failOn: warn reports violations but exits 0", async () => {
  const report = await runCheck({
    base: lockMap([["lodash", ["4.17.21"]]]),
    head: lockMap([["lodash", ["4.17.22"]]]),
    config: { ...DEFAULTS, failOn: "warn" },
    now: NOW,
    registryOpts: fixtureRegistry,
  });
  assert.equal(report.summary.violation, 1);
  assert.equal(report.exitCode, 0);
});

// --- CLI end-to-end (acceptance criteria) ----------------------------------

const cliArgs = (baseFile, headFile) => [
  "--base", join("fixtures", baseFile),
  "--head", join("fixtures", headFile),
  "--config", join("fixtures", "stakeout.yml"),
  "--registry-fixture", join("fixtures", "registry"),
  "--osv-fixture", join("fixtures", "osv"),
];

test("cli: fresh pnpm bump fails with the <7d package as violation", async () => {
  const { exitCode, report } = await runCli(cliArgs("lock-base.yaml", "lock-fresh-bump.yaml"));
  assert.equal(exitCode, 1);
  const v = report.results.find((r) => r.name === "lodash" && r.version === "4.17.22");
  assert.equal(v.status, "violation");
  assert.equal(v.ageDays, 1);
  assert.ok(!report.results.some((r) => r.name.startsWith("@contextand/"))); // scope skipped
});

test("cli: CVE-exempted bump passes with exemption recorded", async () => {
  const { exitCode, report } = await runCli(cliArgs("lock-base.yaml", "lock-cve-exempt-bump.yaml"));
  assert.equal(exitCode, 0);
  const e = report.results.find((r) => r.name === "lodash" && r.version === "4.17.25");
  assert.equal(e.status, "exempted");
  assert.equal(e.exemption.reason, "CVE-2026-1234");
  assert.equal(e.exemption.osv, "verified");
});

test("cli git mode: consumer repo with no .stakeout.yml works on defaults", async () => {
  // Simulates what action.yml runs: a PR branch diffed against a base ref.
  const repo = mkdtempSync(join(tmpdir(), "stakeout-consumer-"));
  const sh = promisify(execFile);
  const g = (...args) => sh("git", args, { cwd: repo });
  await g("init", "-q", "-b", "main");
  await g("config", "user.email", "t@t");
  await g("config", "user.name", "t");
  await g("config", "commit.gpgsign", "false");
  copyFileSync(join(FIX, "lock-base.yaml"), join(repo, "pnpm-lock.yaml"));
  await g("add", "-A");
  await g("commit", "-qm", "base");
  await g("checkout", "-qb", "feature");
  copyFileSync(join(FIX, "lock-fresh-bump.yaml"), join(repo, "pnpm-lock.yaml"));

  const run = async () => {
    try {
      await sh(
        "node",
        [join(ROOT, "stakeout.mjs"), "check", "--base-ref", "main",
         "--registry-fixture", join(FIX, "registry"), "--osv-fixture", join(FIX, "osv"),
         "--now", NOW.toISOString()],
        { cwd: repo }
      );
      return { exitCode: 0, report: JSON.parse(readFileSync(join(repo, "stakeout-report.json"), "utf8")) };
    } catch (e) {
      return { exitCode: e.code, report: JSON.parse(readFileSync(join(repo, "stakeout-report.json"), "utf8")) };
    }
  };

  // No config file -> defaults; diff is only the lodash bump -> violation.
  let { exitCode, report } = await run();
  assert.equal(exitCode, 1);
  assert.equal(report.minimumAgeDays, DEFAULTS.minimumAgeDays);
  assert.deepEqual(report.results.map((r) => `${r.name}@${r.version}:${r.status}`), ["lodash@4.17.22:violation"]);

  // Dropping a weaker .stakeout.yml into the PR is reported, but not trusted.
  writeFileSync(
    join(repo, ".stakeout.yml"),
    "minimumAgeDays: 0\nfailOn: warn\nverifyCveExemptions: false\n"
  );
  ({ exitCode, report } = await run());
  assert.equal(exitCode, 1);
  assert.equal(report.minimumAgeDays, DEFAULTS.minimumAgeDays);
  assert.equal(report.failOn, DEFAULTS.failOn);
  assert.deepEqual(report.policy.configChange, {
    path: ".stakeout.yml",
    status: "added",
    baseRef: "main",
  });
  assert.equal(report.results.find((r) => r.name === "lodash").status, "violation");
});

test("cli git mode: base branch .stakeout.yml is the source of truth", async () => {
  const repo = mkdtempSync(join(tmpdir(), "stakeout-consumer-"));
  const sh = promisify(execFile);
  const g = (...args) => sh("git", args, { cwd: repo });
  await g("init", "-q", "-b", "main");
  await g("config", "user.email", "t@t");
  await g("config", "user.name", "t");
  await g("config", "commit.gpgsign", "false");
  copyFileSync(join(FIX, "lock-base.yaml"), join(repo, "pnpm-lock.yaml"));
  copyFileSync(join(FIX, "stakeout.yml"), join(repo, ".stakeout.yml"));
  await g("add", "-A");
  await g("commit", "-qm", "base with policy");
  await g("checkout", "-qb", "feature");

  const run = async () => {
    try {
      await sh(
        "node",
        [join(ROOT, "stakeout.mjs"), "check", "--base-ref", "main",
         "--registry-fixture", join(FIX, "registry"), "--osv-fixture", join(FIX, "osv"),
         "--now", NOW.toISOString()],
        { cwd: repo }
      );
      return { exitCode: 0, report: JSON.parse(readFileSync(join(repo, "stakeout-report.json"), "utf8")) };
    } catch (e) {
      return { exitCode: e.code, report: JSON.parse(readFileSync(join(repo, "stakeout-report.json"), "utf8")) };
    }
  };

  copyFileSync(join(FIX, "lock-cve-exempt-bump.yaml"), join(repo, "pnpm-lock.yaml"));
  let { exitCode, report } = await run();
  assert.equal(exitCode, 0);
  assert.equal(report.policy.configSource, "main:.stakeout.yml");
  assert.equal(report.policy.configChange, undefined);
  assert.equal(report.results.find((r) => r.name === "lodash").status, "exempted");

  writeFileSync(join(repo, ".stakeout.yml"), "minimumAgeDays: 0\nfailOn: warn\n");
  copyFileSync(join(FIX, "lock-fresh-bump.yaml"), join(repo, "pnpm-lock.yaml"));
  ({ exitCode, report } = await run());
  assert.equal(exitCode, 1);
  assert.equal(report.minimumAgeDays, 7);
  assert.equal(report.failOn, "violation");
  assert.deepEqual(report.policy.configChange, {
    path: ".stakeout.yml",
    status: "modified",
    baseRef: "main",
  });
  assert.equal(report.results.find((r) => r.name === "lodash").status, "violation");
});

test("cli: npm lockfile pair detects the same violation", async () => {
  const { exitCode, report } = await runCli(
    cliArgs(join("npm", "package-lock-base.json"), join("npm", "package-lock-bump.json"))
  );
  assert.equal(exitCode, 1);
  const v = report.results.find((r) => r.name === "lodash" && r.version === "4.17.22");
  assert.equal(v.status, "violation");
});
