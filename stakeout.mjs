#!/usr/bin/env node
// stakeout — CI gate enforcing minimum package age on lockfile diffs.
//
// Diffs a lockfile against the base branch, extracts every (package, version)
// pair that is new to the lockfile, queries the npm registry for each
// version's publish timestamp, and fails if any version is younger than the
// configured minimum age — unless an in-repo CVE exemption covers it.
//
// Zero runtime dependencies: Node >= 20, nothing else.
//
// Exit codes: 0 = clean or fully exempted, 1 = violations, 2 = operational
// error (registry unreachable, unparsable lockfile, bad config).

import { readFileSync, writeFileSync, existsSync, appendFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { join } from "node:path";

export class OperationalError extends Error {}

/** Package absent from the configured registry — assumed private-feed, skipped. */
export class PackageNotFoundError extends Error {}

const DAY_MS = 86_400_000;
const LOCKFILE_NAMES = ["pnpm-lock.yaml", "package-lock.json"];

// ---------------------------------------------------------------------------
// Config (.stakeout.yml) — parsed with a strict, minimal YAML-subset reader.
// Supported: comments, `key: scalar`, `key:` + scalar list, `key:` + list of
// flat mappings. Anything else is rejected — the config schema needs no more.
// ---------------------------------------------------------------------------

export const DEFAULTS = Object.freeze({
  minimumAgeDays: 7,
  failOn: "violation", // violation | warn
  registry: "https://registry.npmjs.org",
  verifyCveExemptions: true,
  skipScopes: [],
  exemptions: [],
});

const ADVISORY_ID = /^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|OSV-\S+)$/i;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

function coerceScalar(raw) {
  const s = raw.replace(/^["']|["']$/g, "");
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(raw)) return Number(raw);
  return s;
}

export function parseConfigYaml(text, source) {
  const root = {};
  let listKey = null; // current top-level key collecting list items
  let mapItem = null; // current `- key: val` mapping being filled
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/(^|\s)#.*$/, "").trimEnd();
    if (!line.trim()) continue;
    const where = `${source}:${i + 1}`;
    let m;
    if ((m = line.match(/^([A-Za-z][A-Za-z0-9]*):\s*(.*)$/))) {
      mapItem = null;
      if (m[2]) {
        root[m[1]] = coerceScalar(m[2]);
        listKey = null;
      } else {
        root[m[1]] = [];
        listKey = m[1];
      }
    } else if ((m = line.match(/^\s+-\s+(.*)$/)) && listKey) {
      const item = m[1];
      const kv = item.match(/^([A-Za-z][A-Za-z0-9]*):\s+(.*)$/);
      if (kv) {
        mapItem = { [kv[1]]: coerceScalar(kv[2]) };
        root[listKey].push(mapItem);
      } else {
        mapItem = null;
        root[listKey].push(coerceScalar(item));
      }
    } else if ((m = line.match(/^\s+([A-Za-z][A-Za-z0-9]*):\s+(.*)$/)) && mapItem) {
      mapItem[m[1]] = coerceScalar(m[2]);
    } else {
      throw new OperationalError(`${where}: cannot parse line "${line.trim()}"`);
    }
  }
  return root;
}

export function validateConfig(raw, source) {
  const cfg = { ...DEFAULTS, skipScopes: [], exemptions: [] };
  for (const [key, value] of Object.entries(raw)) {
    switch (key) {
      case "minimumAgeDays":
        if (typeof value !== "number" || value < 0)
          throw new OperationalError(`${source}: minimumAgeDays must be a non-negative number`);
        cfg.minimumAgeDays = value;
        break;
      case "failOn":
        if (value !== "violation" && value !== "warn")
          throw new OperationalError(`${source}: failOn must be "violation" or "warn"`);
        cfg.failOn = value;
        break;
      case "registry":
        if (typeof value !== "string")
          throw new OperationalError(`${source}: registry must be a string`);
        cfg.registry = value.replace(/\/+$/, "");
        break;
      case "verifyCveExemptions":
        if (typeof value !== "boolean")
          throw new OperationalError(`${source}: verifyCveExemptions must be a boolean`);
        cfg.verifyCveExemptions = value;
        break;
      case "skipScopes":
        if (!Array.isArray(value) || value.some((s) => typeof s !== "string"))
          throw new OperationalError(`${source}: skipScopes must be a list of strings`);
        cfg.skipScopes = value;
        break;
      case "exemptions":
        if (!Array.isArray(value))
          throw new OperationalError(`${source}: exemptions must be a list`);
        cfg.exemptions = value.map((e, i) => validateExemption(e, `${source}: exemptions[${i}]`));
        break;
      default:
        throw new OperationalError(`${source}: unknown key "${key}"`);
    }
  }
  return cfg;
}

function validateExemption(raw, where) {
  if (typeof raw !== "object" || raw === null)
    throw new OperationalError(`${where}: must be a mapping`);
  for (const field of ["package", "version", "reason", "expires"]) {
    if (raw[field] === undefined)
      throw new OperationalError(`${where}: missing required field "${field}"`);
  }
  const reason = String(raw.reason);
  const expires = String(raw.expires);
  if (!ADVISORY_ID.test(reason))
    throw new OperationalError(`${where}: reason "${reason}" must be a CVE, GHSA, or OSV advisory id`);
  if (!ISO_DATE.test(expires) || Number.isNaN(Date.parse(expires)))
    throw new OperationalError(`${where}: expires "${expires}" must be a YYYY-MM-DD date`);
  return { package: String(raw.package), version: String(raw.version), reason, expires };
}

export function loadConfig(path) {
  if (!path) return { ...DEFAULTS };
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new OperationalError(`cannot read config ${path}: ${e.message}`);
  }
  return validateConfig(parseConfigYaml(text, path), path);
}

// ---------------------------------------------------------------------------
// Lockfile parsing → Map<name, Set<version>>
// ---------------------------------------------------------------------------

export function parsePnpmLock(text, source) {
  const versionMatch = text.match(/^lockfileVersion:\s*['"]?([\d.]+)['"]?\s*$/m);
  const lockVersion = versionMatch?.[1];
  if (lockVersion !== "6.0" && lockVersion !== "9.0")
    throw new OperationalError(
      `${source}: unsupported pnpm lockfileVersion "${lockVersion ?? "?"}" (supported: 6.0, 9.0)`
    );
  const out = new Map();
  // Scan the top-level `packages:` section; entry keys sit at 2-space indent.
  //   v6: /lodash@4.17.21:        or  '/@babel/core@7.24.0(...)':
  //   v9: lodash@4.17.21:         or  '@babel/core@7.24.0(...)':
  const lines = text.split(/\r?\n/);
  let inPackages = false;
  for (const line of lines) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line)) inPackages = false; // next top-level section
    if (!inPackages) continue;
    const m = line.match(/^ {2}(\S.*):\s*(\{.*\})?\s*$/);
    if (!m) continue;
    let key = m[1].replace(/^["']|["']$/g, "");
    if (key.startsWith("/")) key = key.slice(1);
    const peer = key.indexOf("(");
    if (peer !== -1) key = key.slice(0, peer);
    const at = key.lastIndexOf("@");
    if (at <= 0) throw new OperationalError(`${source}: cannot parse package key "${m[1]}"`);
    const name = key.slice(0, at);
    const version = key.slice(at + 1);
    // Skip non-registry sources (link:, file:, git URLs) — no publish date exists.
    if (version.includes(":") || version.includes("/")) continue;
    if (!out.has(name)) out.set(name, new Set());
    out.get(name).add(version);
  }
  return out;
}

export function parseNpmLock(text, source) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new OperationalError(`${source}: invalid JSON: ${e.message}`);
  }
  if (doc.lockfileVersion !== 2 && doc.lockfileVersion !== 3)
    throw new OperationalError(
      `${source}: unsupported npm lockfileVersion "${doc.lockfileVersion}" (supported: 2, 3)`
    );
  const out = new Map();
  for (const [path, entry] of Object.entries(doc.packages ?? {})) {
    if (path === "" || !path.includes("node_modules/")) continue; // root / workspace package
    if (entry.link || !entry.version) continue;
    if (entry.resolved && !/^https?:/.test(entry.resolved)) continue; // git/file deps
    const name =
      entry.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
    if (!out.has(name)) out.set(name, new Set());
    out.get(name).add(String(entry.version));
  }
  return out;
}

export function parseLockfile(text, source) {
  if (!text.trim()) return new Map(); // absent in base branch → everything is new
  return /^\s*\{/.test(text) ? parseNpmLock(text, source) : parsePnpmLock(text, source);
}

/** Pairs present in head but not in base, minus skipped scopes. */
export function diffLockfiles(base, head, skipScopes) {
  const out = [];
  for (const [name, versions] of head) {
    if (skipScopes.some((s) => name === s || name.startsWith(s + "/"))) continue;
    for (const version of versions) {
      if (!base.get(name)?.has(version)) {
        const baseVersions = base.get(name);
        out.push({
          name,
          version,
          baseVersion: baseVersions ? [...baseVersions].sort().at(-1) : undefined,
        });
      }
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

// ---------------------------------------------------------------------------
// npm registry client — cached per run, concurrency-capped, retry with backoff.
// Fixture mode reads fixtures/registry/<name with / as __>.json instead.
// ---------------------------------------------------------------------------

const fixtureName = (name) => name.replaceAll("/", "__");

export function createRegistryClient({
  registry,
  fixtureDir,
  concurrency = 8,
  retries = 3,
  backoffMs = 1000,
  fetchImpl = fetch,
}) {
  const cache = new Map();
  let active = 0;
  const queue = [];
  const slot = () =>
    new Promise((resolve) => {
      const run = () => {
        active++;
        resolve(() => {
          active--;
          queue.shift()?.();
        });
      };
      active < concurrency ? run() : queue.push(run);
    });

  async function fetchDoc(name) {
    if (fixtureDir) {
      const path = join(fixtureDir, fixtureName(name) + ".json");
      if (!existsSync(path))
        throw new OperationalError(`registry fixture missing for ${name} (${path})`);
      return JSON.parse(readFileSync(path, "utf8"));
    }
    const url = `${registry}/${name}`;
    let lastErr;
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const res = await fetchImpl(url, { headers: { accept: "application/json" } });
        if (res.status === 404) throw new PackageNotFoundError(`${name} not found at ${registry}`);
        if (res.status === 429 || res.status >= 500) {
          const retryAfter = Number(res.headers.get("retry-after")) * 1000 || backoffMs * 2 ** (attempt - 1);
          lastErr = new Error(`HTTP ${res.status} from ${url}`);
          if (attempt < retries) await new Promise((r) => setTimeout(r, retryAfter));
          continue;
        }
        if (!res.ok) throw new OperationalError(`HTTP ${res.status} from ${url}`);
        return await res.json();
      } catch (e) {
        if (e instanceof OperationalError || e instanceof PackageNotFoundError) throw e;
        lastErr = e;
        if (attempt < retries) await new Promise((r) => setTimeout(r, backoffMs * 2 ** (attempt - 1)));
      }
    }
    throw new OperationalError(`registry fetch failed for ${name} after ${retries} attempts: ${lastErr.message}`);
  }

  return {
    async publishedAt(name, version) {
      if (!cache.has(name)) {
        cache.set(
          name,
          (async () => {
            const release = await slot();
            try {
              return await fetchDoc(name);
            } finally {
              release();
            }
          })()
        );
      }
      const doc = await cache.get(name);
      const ts = doc.time?.[version];
      if (!ts)
        throw new OperationalError(`no publish timestamp for ${name}@${version} in registry metadata`);
      return ts;
    },
  };
}

// ---------------------------------------------------------------------------
// OSV.dev exemption verification. Degrades to "unavailable" (warn, accept) on
// network failure — only verification degrades, never the core age check.
// ---------------------------------------------------------------------------

export async function verifyExemption({ exemption, baseVersion, osvFixtureDir, fetchImpl = fetch }) {
  let vulns;
  if (osvFixtureDir) {
    const file = fixtureName(exemption.package) + (baseVersion ? `@${baseVersion}` : "") + ".json";
    const path = join(osvFixtureDir, file);
    vulns = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")).vulns ?? [] : [];
  } else {
    try {
      const body = { package: { ecosystem: "npm", name: exemption.package } };
      if (baseVersion) body.version = baseVersion;
      const res = await fetchImpl("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) return "unavailable";
      vulns = (await res.json()).vulns ?? [];
    } catch {
      return "unavailable";
    }
  }
  const id = exemption.reason.toUpperCase();
  const matches = vulns.some(
    (v) => v.id?.toUpperCase() === id || (v.aliases ?? []).some((a) => a.toUpperCase() === id)
  );
  return matches ? "verified" : "rejected";
}

// ---------------------------------------------------------------------------
// Core check
// ---------------------------------------------------------------------------

export async function runCheck({ base, head, config, now = new Date(), registryOpts = {}, osvFixtureDir }) {
  const changed = diffLockfiles(base, head, config.skipScopes);
  const results = [];
  if (changed.length > 0) {
    const client = createRegistryClient({ registry: config.registry, ...registryOpts });
    const thresholdMs = config.minimumAgeDays * DAY_MS;
    await Promise.all(
      changed.map(async (pkg) => {
        const result = { name: pkg.name, version: pkg.version, baseVersion: pkg.baseVersion };
        results.push(result);
        let publishedMs;
        try {
          result.publishedAt = await client.publishedAt(pkg.name, pkg.version);
          publishedMs = Date.parse(result.publishedAt);
        } catch (e) {
          if (e instanceof PackageNotFoundError) {
            result.status = "skipped";
            result.note = `${e.message} — assumed private; not age-checked`;
          } else {
            result.status = "error";
            result.error = e.message;
          }
          return;
        }
        const ageMs = now.getTime() - publishedMs;
        result.ageDays = Math.floor(ageMs / DAY_MS);
        result.eligibleOn = new Date(publishedMs + thresholdMs).toISOString().slice(0, 10);
        if (ageMs >= thresholdMs) {
          result.status = "pass";
          return;
        }
        const exemption = config.exemptions.find(
          (e) => e.package === pkg.name && e.version === pkg.version
        );
        if (!exemption) {
          result.status = "violation";
          return;
        }
        if (Date.parse(exemption.expires) + DAY_MS <= now.getTime()) {
          result.status = "stale-exemption";
          result.exemption = { reason: exemption.reason, expires: exemption.expires, osv: "skipped" };
          return;
        }
        const osv = config.verifyCveExemptions
          ? await verifyExemption({ exemption, baseVersion: pkg.baseVersion, osvFixtureDir })
          : "skipped";
        result.exemption = { reason: exemption.reason, expires: exemption.expires, osv };
        result.status = osv === "rejected" ? "violation" : "exempted";
      })
    );
  }
  results.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  const summary = { checked: results.length, pass: 0, violation: 0, exempted: 0, "stale-exemption": 0, skipped: 0, error: 0 };
  for (const r of results) summary[r.status]++;
  let exitCode = 0;
  if (summary.violation + summary["stale-exemption"] > 0) exitCode = config.failOn === "warn" ? 0 : 1;
  if (summary.error > 0) exitCode = 2; // fail closed: missing metadata is never a pass

  return {
    schemaVersion: 1,
    now: now.toISOString(),
    minimumAgeDays: config.minimumAgeDays,
    failOn: config.failOn,
    results,
    summary,
    exitCode,
  };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

export function renderTable(report) {
  if (report.results.length === 0)
    return `stakeout: no new package versions in lockfile diff — nothing to check.\n`;
  const rows = [["PACKAGE", "VERSION", "PUBLISHED", "AGE", "STATUS", "DETAIL"]];
  for (const r of report.results) {
    let detail = "";
    if (r.status === "violation" && r.exemption?.osv === "rejected")
      detail = `exemption ${r.exemption.reason} rejected by OSV (does not affect ${r.baseVersion ?? "this package"})`;
    else if (r.status === "violation") detail = `eligible on ${r.eligibleOn}`;
    else if (r.status === "exempted")
      detail = `${r.exemption.reason} (osv: ${r.exemption.osv}, expires ${r.exemption.expires})`;
    else if (r.status === "stale-exemption")
      detail = `exemption ${r.exemption.reason} expired ${r.exemption.expires}; eligible on ${r.eligibleOn}`;
    else if (r.status === "skipped") detail = r.note;
    else if (r.status === "error") detail = r.error;
    rows.push([
      r.name,
      r.version,
      r.publishedAt?.slice(0, 10) ?? "-",
      r.ageDays !== undefined ? `${r.ageDays}d` : "-",
      r.status,
      detail,
    ]);
  }
  const widths = rows[0].map((_, i) => Math.max(...rows.map((row) => String(row[i]).length)));
  const lines = rows.map((row) => row.map((cell, i) => String(cell).padEnd(widths[i])).join("  ").trimEnd());
  const s = report.summary;
  lines.push(
    "",
    `stakeout: ${s.checked} new version(s) checked — ${s.violation} violation(s), ` +
      `${s.exempted} exempted, ${s["stale-exemption"]} stale exemption(s), ` +
      `${s.skipped} skipped, ${s.error} error(s). Minimum age: ${report.minimumAgeDays} day(s).`
  );
  return lines.join("\n") + "\n";
}

function writeStepSummary(report) {
  const path = process.env.GITHUB_STEP_SUMMARY;
  if (!path || report.results.length === 0) return;
  const lines = [
    `### stakeout — minimum package age ${report.minimumAgeDays}d`,
    "",
    "| package | version | published | age | status |",
    "|---|---|---|---|---|",
    ...report.results.map(
      (r) =>
        `| ${r.name} | ${r.version} | ${r.publishedAt?.slice(0, 10) ?? "-"} | ` +
        `${r.ageDays ?? "-"} | ${r.status} |`
    ),
    "",
  ];
  appendFileSync(path, lines.join("\n"));
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function gitShow(ref, path) {
  try {
    return execFileSync("git", ["show", `${ref}:${path}`], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch {
    return ""; // file absent in base ref → every pair is new
  }
}

export async function main(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      base: { type: "string" },
      head: { type: "string" },
      "base-ref": { type: "string" },
      config: { type: "string" },
      report: { type: "string", default: "stakeout-report.json" },
      "registry-fixture": { type: "string" },
      "osv-fixture": { type: "string" },
      now: { type: "string" },
    },
  });
  if (positionals[0] !== "check")
    throw new OperationalError(`usage: stakeout.mjs check [--base F --head F | --base-ref REF] [--config F]`);

  let configPath = values.config;
  if (!configPath && existsSync(".stakeout.yml")) configPath = ".stakeout.yml";
  const config = loadConfig(configPath);

  const now = values.now ? new Date(values.now) : new Date();
  if (Number.isNaN(now.getTime())) throw new OperationalError(`invalid --now value "${values.now}"`);

  // Resolve base/head lockfile contents: explicit file pair, or git diff mode.
  const base = new Map();
  const head = new Map();
  const merge = (into, parsed) =>
    parsed.forEach((versions, name) => {
      if (!into.has(name)) into.set(name, new Set());
      versions.forEach((v) => into.get(name).add(v));
    });

  if (values.base || values.head) {
    if (!values.base || !values.head)
      throw new OperationalError("--base and --head must be given together");
    merge(base, parseLockfile(readFileSync(values.base, "utf8"), values.base));
    merge(head, parseLockfile(readFileSync(values.head, "utf8"), values.head));
  } else {
    const ref = values["base-ref"];
    if (!ref) throw new OperationalError("either --base/--head or --base-ref is required");
    const present = LOCKFILE_NAMES.filter((f) => existsSync(f));
    if (present.length === 0)
      throw new OperationalError(`no supported lockfile found (looked for: ${LOCKFILE_NAMES.join(", ")})`);
    for (const file of present) {
      const headText = readFileSync(file, "utf8");
      const baseText = gitShow(ref, file);
      if (baseText === headText) continue; // unchanged → no parsing, no registry calls
      merge(base, parseLockfile(baseText, `${ref}:${file}`));
      merge(head, parseLockfile(headText, file));
    }
  }

  const report = await runCheck({
    base,
    head,
    config,
    now,
    registryOpts: values["registry-fixture"] ? { fixtureDir: values["registry-fixture"] } : {},
    osvFixtureDir: values["osv-fixture"],
  });

  process.stdout.write(renderTable(report));
  writeFileSync(values.report, JSON.stringify(report, null, 2) + "\n");
  writeStepSummary(report);
  for (const r of report.results) {
    if (r.status === "violation" || r.status === "stale-exemption")
      console.error(`::error::stakeout: ${r.name}@${r.version} is ${r.ageDays}d old (< ${config.minimumAgeDays}d), eligible on ${r.eligibleOn}`);
    if (r.status === "error") console.error(`::error::stakeout: ${r.name}@${r.version}: ${r.error}`);
    if (r.status === "skipped") console.error(`::warning::stakeout: ${r.name}@${r.version}: ${r.note}`);
    if (r.exemption?.osv === "unavailable")
      console.error(`::warning::stakeout: OSV unavailable — exemption ${r.exemption.reason} for ${r.name}@${r.version} accepted unverified`);
  }
  return report.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`::error::stakeout: ${e.message}`);
      process.exit(2);
    }
  );
}
