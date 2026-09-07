#!/usr/bin/env node

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const PLATFORMS = ["claude-code", "codex", "kimi-code", "workbuddy"];
const FAMILY_ID = "skill-family-audit";
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
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

async function tryParseJson(root, relative) {
  try {
    return await parseJson(root, relative);
  } catch {
    return null;
  }
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

async function verifyFoundation(root, platformRoot, findings) {
  const prefix = "foundation/quickstart-profile";
  let api;
  try {
    api = await import(pathToFileURL(path.join(platformRoot, prefix, "runner.mjs")).href);
  } catch {
    findings.push(`FOUNDATION_BUNDLE_FILE_MISSING:${prefix}/runner.mjs`);
    return null;
  }
  const provenance = await parseJson(platformRoot, `${prefix}/foundation-projection.json`);
  const profile = provenance.profile ?? {};
  const source = provenance.source ?? {};
  if (provenance.kind !== "skill-family.foundation-projection"
      || profile.id !== "quickstart-profile"
      || profile.version !== 2
      || source.repository !== "ifoohoo/skill-family-foundation-workspace"
      || !HEX40.test(source.baseCommit ?? "")) {
    findings.push("FOUNDATION_PROVENANCE_INVALID");
    return api;
  }
  const expected = provenance.payload?.files;
  if (!Array.isArray(expected) || expected.length === 0
      || !HEX64.test(provenance.payload?.digest ?? "")) {
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
  const declared = new Set(expected.map((item) => item.path));
  for (const relative of await files(platformRoot, prefix)) {
    const member = relative.slice(prefix.length + 1);
    if (member === "foundation-projection.json") continue;
    if (!declared.has(member)) {
      findings.push(`FOUNDATION_BUNDLE_UNDECLARED_MEMBER:${member}`);
    }
  }
  if (api.digestDocument(expected) !== provenance.payload.digest) {
    findings.push("FOUNDATION_BUNDLE_DIGEST_INVALID");
  }
  const consumerSchemas = source.consumerSchemas ?? [];
  if (!Array.isArray(consumerSchemas) || consumerSchemas.length === 0) {
    findings.push("FOUNDATION_CONSUMER_SCHEMA_INDEX_MISSING");
  }
  for (const schema of consumerSchemas) {
    const member = `schemas/consumer/${schema.path}`;
    if (!declared.has(member) || !HEX64.test(schema.sha256 ?? "")) {
      findings.push(`FOUNDATION_CONSUMER_SCHEMA_MISSING:${schema.path}`);
      continue;
    }
    let document;
    try {
      document = JSON.parse(await readFile(path.join(platformRoot, prefix, member), "utf8"));
    } catch {
      findings.push(`FOUNDATION_CONSUMER_SCHEMA_INVALID:${schema.path}`);
      continue;
    }
    if (document.$id !== schema.$id) {
      findings.push(`FOUNDATION_CONSUMER_SCHEMA_ID_MISMATCH:${schema.path}`);
    }
    const sourceBytes = await readFile(path.join(root, "spec", "contracts", schema.path)).catch(() => null);
    if (sourceBytes === null) continue;
    const { createHash } = await import("node:crypto");
    const sourceDigest = createHash("sha256").update(sourceBytes).digest("hex");
    if (sourceDigest !== schema.sha256) {
      findings.push(`FOUNDATION_CONSUMER_SCHEMA_SOURCE_MISMATCH:${schema.path}`);
      continue;
    }
    let sourceDocument;
    try {
      sourceDocument = JSON.parse(sourceBytes.toString("utf8"));
    } catch {
      findings.push(`FOUNDATION_CONSUMER_SCHEMA_SOURCE_INVALID:${schema.path}`);
      continue;
    }
    if (api.canonicalJson(sourceDocument) !== api.canonicalJson(document)) {
      findings.push(`FOUNDATION_CONSUMER_SCHEMA_SEMANTIC_MISMATCH:${schema.path}`);
    }
  }
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

  const summary = await parseJson(root, "candidate-summary.json");
  const packageJson = await tryParseJson(root, "package.json");
  if (summary.familyId !== FAMILY_ID
      || summary.candidateId !== `${FAMILY_ID}:${summary.version}`
      || (packageJson && summary.version !== packageJson.version)) {
    findings.push("CANDIDATE_IDENTITY_MISMATCH");
  }

  let runnerApi = null;
  for (const platform of PLATFORMS) {
    const platformRoot = path.join(root, "platforms", platform);
    const manifest = await parseJson(platformRoot, "platform-manifest.json");
    if (manifest.platformId !== platform || manifest.version !== summary.version) {
      findings.push(`PLATFORM_IDENTITY_MISMATCH:${platform}`);
    }
    const api = await verifyFoundation(root, platformRoot, findings);
    if (api === null) continue;
    runnerApi = api;
    const platformFiles = (await files(platformRoot)).filter((item) => item !== "platform-manifest.json");
    const digest = (await foundationClosure(api, platformRoot, platformFiles)).digest;
    if (digest !== manifest.projectionDigest) findings.push(`PLATFORM_DIGEST_MISMATCH:${platform}`);
    const declared = [...(manifest.files ?? [])].sort();
    if (JSON.stringify(platformFiles.sort()) !== JSON.stringify(declared)) {
      findings.push(`PLATFORM_CLOSURE_MISMATCH:${platform}`);
    }
  }

  if (runnerApi && HEX64.test(summary.candidatePayloadDigest ?? "")) {
    // candidatePayloadDigest is owned by the candidate builder and covers
    // only the candidate payload roots.  README, LICENSE, package metadata,
    // and this verifier are release-wrapper files; they must not silently
    // redefine the candidate approval subject.
    // 1.1.0 起候选根级含 claude 双重映射（.claude-plugin/** 与 skills/**，
    // A1 裁决），与生成器 _populate_candidate 的闭包集合对齐。
    const payloadFiles = allFiles.filter(
      (item) => (item.startsWith("platforms/") || item.startsWith("spec/")
        || item.startsWith(".claude-plugin/") || item.startsWith("skills/"))
        && !item.endsWith("#non-file"),
    );
    const payloadDigest = (await foundationClosure(runnerApi, root, payloadFiles)).digest;
    if (payloadDigest !== summary.candidatePayloadDigest) findings.push("CANDIDATE_PAYLOAD_DIGEST_MISMATCH");
  }
  return { verdict: findings.length === 0 ? "PASS" : "FAIL", findings };
}

async function rootArg(argv) {
  const index = argv.indexOf("--root");
  if (index >= 0) return argv[index + 1];
  const packageRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
  const packageJson = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
  return path.join(packageRoot, "dist", "candidate", packageJson.version);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const result = await verify(path.resolve(await rootArg(process.argv.slice(2))));
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = result.verdict === "PASS" ? 0 : 1;
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ verdict: "FAIL", findings: [error.message] })}\n`);
    process.exitCode = 1;
  }
}
