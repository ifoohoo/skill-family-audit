#!/usr/bin/env node

import crypto from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_FILES = Object.freeze([
  ".agents/plugins/marketplace.json",
  ".codex-plugin/plugin.json",
  "LICENSE",
  "README.md",
  "candidate-summary.json",
  "package.json",
  "platform-manifest.json",
  "registry-v2/adoption-lifecycle.json",
  "registry-v2/contract-attestation.json",
  "registry-v2/family-api.json",
  "registry-v2/implementation.json",
  "runtime-packages.declaration.json",
  "runtime-packages.lock-slice.json",
  "spec/contracts/budget.schema.json",
  "spec/contracts/non-waivable-candidate.schema.json",
  "spec/contracts/platform-lifecycle-receipt.schema.json",
  "spec/contracts/platform-manifest.schema.json",
  "spec/contracts/registry-adoption-lifecycle.schema.json",
  "spec/contracts/release-policy.schema.json",
  "spec/contracts/result.schema.json",
  "spec/contracts/runtime-packages.schema.json",
  "spec/contracts/task.schema.json",
  "spec/methods/behavior-audit.json",
  "spec/methods/conformance-audit.json",
  "spec/methods/release-audit.json",
  "spec/methods/runtime-audit.json",
  "skills/behavior-audit/SKILL.md",
  "skills/conformance-audit/SKILL.md",
  "skills/help/SKILL.md",
  "skills/quickstart/SKILL.md",
  "skills/release-audit/SKILL.md",
  "skills/runtime-audit/SKILL.md",
  "skills/setup/SKILL.md",
]);
const REQUIRED_PLATFORMS = Object.freeze(["claude-code", "codex", "kimi-code", "workbuddy"]);
const FORBIDDEN_SEGMENTS = new Set([
  ".release-skill",
  "artifacts",
  "artifact-graph.config.yaml",
  "public-release.json",
  "public-snapshot",
]);
const MACHINE_PATH_PATTERNS = Object.freeze([
  /\/Users\/[A-Za-z0-9._-]+\//,
  /\/home\/[A-Za-z0-9._-]+\//,
  /[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\/,
]);

export class SnapshotVerificationError extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.name = "SnapshotVerificationError";
    this.code = code;
    this.detail = detail;
  }
}

function fail(code, message, detail = {}) {
  throw new SnapshotVerificationError(code, message, detail);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

async function collectFiles(root, relative = "") {
  const absolute = path.join(root, relative);
  const entries = await readdir(absolute, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en-US"))) {
    const child = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) {
      fail("SYMLINK_FORBIDDEN", "public snapshot contains a symbolic link", { path: child });
    }
    if (entry.isDirectory()) {
      files.push(...await collectFiles(root, child));
    } else if (entry.isFile()) {
      const stat = await lstat(path.join(root, child));
      if (stat.nlink !== 1) {
        fail("HARDLINK_FORBIDDEN", "public snapshot contains a hard-linked file", { path: child });
      }
      files.push(child);
    } else {
      fail("SPECIAL_FILE_FORBIDDEN", "public snapshot contains a special file", { path: child });
    }
  }
  return files;
}

async function parseJson(root, relative) {
  try {
    return JSON.parse(await readFile(path.join(root, relative), "utf8"));
  } catch (error) {
    fail("JSON_INVALID", "public snapshot JSON cannot be parsed", {
      path: relative,
      error: String(error),
    });
  }
}

function normalizeJsonReference(source, reference) {
  const withoutFragment = reference.split("#", 1)[0];
  if (!withoutFragment || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(withoutFragment)) {
    return null;
  }
  const normalized = withoutFragment.startsWith("spec/")
    || withoutFragment.startsWith("registry-v2/")
    ? path.posix.normalize(withoutFragment)
    : path.posix.normalize(path.posix.join(path.posix.dirname(source), withoutFragment));
  if (
    normalized === ".."
    || normalized.startsWith("../")
    || path.posix.isAbsolute(normalized)
  ) {
    fail("PUBLIC_REFERENCE_ESCAPE", "public JSON reference escapes the snapshot", {
      source,
      reference,
    });
  }
  return normalized;
}

function referencedJsonPaths(value, source, found = new Set()) {
  if (Array.isArray(value)) {
    for (const item of value) referencedJsonPaths(item, source, found);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (
        typeof item === "string"
        && (
          key === "$ref"
          || key === "methodContractRef"
          || key.endsWith("Contract")
          || key.endsWith("_ref")
        )
      ) {
        const normalized = normalizeJsonReference(source, item);
        if (normalized) found.add(normalized);
      } else {
        referencedJsonPaths(item, source, found);
      }
    }
  }
  return found;
}

export async function verifyPublicSnapshot(rootValue = ".") {
  const root = await realpath(path.resolve(rootValue));
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    fail("ROOT_INVALID", "public snapshot root must be a real directory");
  }
  const files = await collectFiles(root);
  const fileSet = new Set(files);

  for (const required of REQUIRED_FILES) {
    if (!fileSet.has(required)) {
      fail("REQUIRED_FILE_MISSING", "public snapshot required file is missing", { path: required });
    }
  }
  for (const platform of REQUIRED_PLATFORMS) {
    const manifest = `platforms/${platform}/platform-manifest.json`;
    if (!fileSet.has(manifest)) {
      fail("PLATFORM_MANIFEST_MISSING", "platform projection manifest is missing", {
        platform,
        path: manifest,
      });
    }
  }
  for (const relative of files) {
    const segments = relative.split("/");
    const forbidden = segments.find((segment) => FORBIDDEN_SEGMENTS.has(segment));
    if (forbidden) {
      fail("PRIVATE_PATH_LEAK", "private/control-plane path entered the public snapshot", {
        path: relative,
        segment: forbidden,
      });
    }
    const bytes = await readFile(path.join(root, relative));
    if (!bytes.includes(0)) {
      const text = bytes.toString("utf8");
      if (MACHINE_PATH_PATTERNS.some((pattern) => pattern.test(text))) {
        fail("MACHINE_PATH_LEAK", "machine-specific home path entered the public snapshot", {
          path: relative,
        });
      }
    }
  }

  const packageJson = await parseJson(root, "package.json");
  const summary = await parseJson(root, "candidate-summary.json");
  const familyApi = await parseJson(root, "registry-v2/family-api.json");
  const queued = ["registry-v2/family-api.json"];
  const visited = new Set();
  while (queued.length) {
    const relative = queued.shift();
    if (visited.has(relative)) continue;
    visited.add(relative);
    const document = relative === "registry-v2/family-api.json"
      ? familyApi
      : await parseJson(root, relative);
    for (const reference of referencedJsonPaths(document, relative)) {
      if (!fileSet.has(reference)) {
        fail("PUBLIC_REFERENCE_MISSING", "public JSON reference is absent", {
          source: relative,
          reference,
        });
      }
      queued.push(reference);
    }
  }
  for (const service of familyApi.services ?? []) {
    const reference = service.methodContractRef;
    const actual = sha256(await readFile(path.join(root, reference)));
    const expected = String(service.methodContractDigest ?? "").replace(/^sha256:/, "");
    if (actual !== expected) {
      fail("PUBLIC_REFERENCE_DIGEST_MISMATCH", "method contract digest does not match public bytes", {
        reference,
        expected,
        actual,
      });
    }
  }
  if (
    packageJson.name !== "skill-family-audit"
    || typeof packageJson.version !== "string"
    || !packageJson.version.endsWith("-candidate")
  ) {
    fail("PACKAGE_IDENTITY_INVALID", "public package identity/version is invalid", {
      name: packageJson.name,
      version: packageJson.version,
    });
  }
  if (
    summary.familyId !== "skill-family-audit"
    || summary.version !== packageJson.version
    || summary.candidateId !== `skill-family-audit:${packageJson.version}`
  ) {
    fail("CANDIDATE_IDENTITY_MISMATCH", "candidate summary does not match package identity", {
      packageVersion: packageJson.version,
      candidateId: summary.candidateId,
      candidateVersion: summary.version,
    });
  }
  if (
    !Array.isArray(summary.platforms)
    || summary.platforms.length !== REQUIRED_PLATFORMS.length
    || [...summary.platforms].sort().join("\0") !== [...REQUIRED_PLATFORMS].sort().join("\0")
  ) {
    fail("PLATFORM_SET_MISMATCH", "candidate summary platform set is not the four-platform set", {
      platforms: summary.platforms,
    });
  }

  const digestRows = [];
  for (const relative of files) {
    const bytes = await readFile(path.join(root, relative));
    digestRows.push(`${relative}\0${sha256(bytes)}\0${bytes.length}`);
  }
  return {
    schemaVersion: "1.0.0",
    verdict: "PASS",
    candidateVersion: packageJson.version,
    fileCount: files.length,
    snapshotContentDigest: sha256(Buffer.from(digestRows.join("\n"))),
  };
}

function parseArgs(argv) {
  if (argv.length === 0) return { root: "." };
  if (argv.length === 2 && argv[0] === "--root") return { root: argv[1] };
  fail("ARGUMENT_INVALID", "usage: verify-public-snapshot.mjs [--root <snapshot-root>]");
}

if (
  process.argv[1]
  && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
) {
  try {
    const args = parseArgs(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(await verifyPublicSnapshot(args.root))}\n`);
  } catch (error) {
    const payload = error instanceof SnapshotVerificationError
      ? {
          schemaVersion: "1.0.0",
          verdict: "FAIL",
          code: error.code,
          message: error.message,
          detail: error.detail,
        }
      : {
          schemaVersion: "1.0.0",
          verdict: "FAIL",
          code: "UNEXPECTED_ERROR",
          message: String(error),
        };
    process.stdout.write(`${JSON.stringify(payload)}\n`);
    process.exitCode = 1;
  }
}
