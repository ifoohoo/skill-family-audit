#!/usr/bin/env node

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const PLATFORMS = ["claude-code", "codex", "kimi-code", "workbuddy"];
const ABSOLUTE_PATH = /(?:\/Users\/[A-Za-z0-9._-]+\/|\/home\/[A-Za-z0-9._-]+\/|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\)/;

async function files(root, base = "") {
  const result = [];
  for (const entry of (await readdir(path.join(root, base), { withFileTypes: true }))
    .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const relative = base === "" ? entry.name : `${base}/${entry.name}`;
    if (entry.isDirectory()) result.push(...await files(root, relative));
    else if (entry.isFile()) result.push(relative);
    else result.push(`${relative}#non-file`);
  }
  return result.sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
}

async function parseJson(root, relative) {
  return JSON.parse(await readFile(path.join(root, relative), "utf8"));
}

async function foundationClosure(api, root, relativePaths) {
  return api.computeResourceClosure({
    root,
    resources: [...relativePaths].sort().map((relative) => ({
      path: relative,
      role: "input",
    })),
  });
}

async function verifyFoundation(platformRoot, findings) {
  const prefix = "foundation/quickstart-profile";
  let api;
  try {
    api = await import(pathToFileURL(path.join(platformRoot, prefix, "runner.mjs")).href);
  } catch {
    findings.push(`FOUNDATION_BUNDLE_FILE_MISSING:${prefix}/runner.mjs`);
    return null;
  }
  const provenance = await parseJson(platformRoot, `${prefix}/foundation-projection.json`);
  if (provenance.kind !== "skill-family.foundation-projection"
      || provenance.source?.identity !== "skill-family-foundation-workspace"
      || !/^[0-9a-f]{64}$/.test(provenance.source?.closure?.digest ?? "")) {
    findings.push("FOUNDATION_PROVENANCE_INVALID");
    return api;
  }
  const expected = provenance.bundle?.files;
  if (!Array.isArray(expected) || !/^[0-9a-f]{64}$/.test(provenance.bundle?.digest ?? "")) {
    findings.push("FOUNDATION_BUNDLE_INDEX_INVALID");
    return api;
  }
  let closure;
  try {
    closure = await foundationClosure(
      api,
      platformRoot,
      expected.map((item) => `${prefix}/${item.path}`),
    );
  } catch (error) {
    findings.push(`FOUNDATION_BUNDLE_CLOSURE_INVALID:${error.message}`);
    return api;
  }
  const actualByPath = new Map(
    closure.resources.map((item) => [item.path.slice(prefix.length + 1), item.sha256]),
  );
  for (const item of expected) {
    if (actualByPath.get(item.path) !== item.sha256) {
      findings.push(`FOUNDATION_BUNDLE_DIGEST_MISMATCH:${item.path}`);
    }
  }
  const computed = api.digestDocument(
    [...expected].sort((a, b) => a.path.localeCompare(b.path)),
  );
  if (computed !== provenance.bundle.digest) findings.push("FOUNDATION_BUNDLE_DIGEST_INVALID");
  return api;
}

export async function verify(root) {
  const findings = [];
  const allFiles = await files(root);
  for (const relative of allFiles) {
    if (relative.endsWith("#non-file")) findings.push(`NON_REGULAR_ENTRY:${relative}`);
    const bytes = await readFile(path.join(root, relative.replace(/#non-file$/, ""))).catch(() => null);
    if (bytes && ABSOLUTE_PATH.test(bytes.toString("utf8"))) findings.push(`ABSOLUTE_PATH_LEAK:${relative}`);
  }

  const packageJson = await parseJson(root, "package.json");
  const summary = await parseJson(root, "candidate-summary.json");
  if (summary.version !== packageJson.version || summary.familyId !== "skill-family-audit") {
    findings.push("CANDIDATE_IDENTITY_MISMATCH");
  }

  for (const platform of PLATFORMS) {
    const platformRoot = path.join(root, "platforms", platform);
    const manifest = await parseJson(platformRoot, "platform-manifest.json");
    if (manifest.platformId !== platform || manifest.version !== packageJson.version) {
      findings.push(`PLATFORM_IDENTITY_MISMATCH:${platform}`);
    }
    const api = await verifyFoundation(platformRoot, findings);
    if (api === null) continue;
    const digest = (await foundationClosure(
      api,
      platformRoot,
      (await files(platformRoot)).filter((item) => item !== "platform-manifest.json"),
    )).digest;
    if (digest !== manifest.projectionDigest) findings.push(`PLATFORM_DIGEST_MISMATCH:${platform}`);
    const actual = (await files(platformRoot)).filter((item) => item !== "platform-manifest.json").sort();
    const declared = [...(manifest.files ?? [])].sort();
    if (JSON.stringify(actual) !== JSON.stringify(declared)) findings.push(`PLATFORM_CLOSURE_MISMATCH:${platform}`);
  }
  return { verdict: findings.length === 0 ? "PASS" : "FAIL", findings };
}

function rootArg(argv) {
  const index = argv.indexOf("--root");
  return index >= 0 ? argv[index + 1] : ".";
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const result = await verify(path.resolve(rootArg(process.argv.slice(2))));
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = result.verdict === "PASS" ? 0 : 1;
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ verdict: "FAIL", findings: [error.message] })}\n`);
    process.exitCode = 1;
  }
}
