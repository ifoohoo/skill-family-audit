import { constants } from "node:fs";
import { access, lstat, mkdtemp, readFile, realpath, rename, rm } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { canonicalJson, digestDocument, validateDocument } from "skill-family-contracts";
import { writeFileAtomic } from "./atomic.mjs";
import { digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, HarnessError, mechanismError } from "./errors.mjs";
import { classifyPathInput } from "./paths.mjs";

const SCHEMAS = Object.freeze({
  adapterSource: "https://contracts.skill-family.example/v1/adapter-source.json",
  buildManifest: "https://contracts.skill-family.example/v1/adapter-build-manifest.json",
  capabilityFact: "https://contracts.skill-family.example/v1/host-capability-fact.json",
});

function invalidParams(message, details) {
  return new HarnessError("SFC2003", message, { ...(details ?? {}), kind: "invalid-params" });
}

function validateContract(document, schemaId, message) {
  const result = validateDocument(document, { schemaId, dialect: "2020-12", policy: "strict" });
  if (!result.valid) throw mechanismError(HARNESS_ERROR_KINDS.HOST_CONTRACT_INVALID, message, { errors: result.errors });
  return result.data;
}

function assertRelative(relPath, label) {
  const classified = classifyPathInput(relPath);
  const normalized = typeof relPath === "string" ? path.posix.normalize(relPath) : "";
  if (!classified.ok || normalized !== relPath || normalized === "." || normalized.startsWith("../")) {
    throw invalidParams(`${label} must be a normalized contained relative path`, { path: relPath, pathKind: classified.kind ?? "non-normalized" });
  }
  return relPath;
}

function portablePathKey(value) {
  return value.normalize("NFC").toLocaleLowerCase("en-US");
}

function assertUniquePortablePaths(paths, label) {
  const seen = new Map();
  for (const value of paths) {
    const key = portablePathKey(value);
    if (seen.has(key)) {
      throw mechanismError(HARNESS_ERROR_KINDS.PORTABLE_PATH_COLLISION, `${label} contains a portable path collision`, { first: seen.get(key), second: value });
    }
    seen.set(key, value);
  }
}

/** Validates and deterministically normalizes an adapter source closure. */
export function normalizeAdapterSource(input) {
  const source = validateContract(input, SCHEMAS.adapterSource, "adapter source fails its registered contract");
  const skillIds = source.skills.map((skill) => skill.id);
  if (new Set(skillIds).size !== skillIds.length) throw mechanismError(HARNESS_ERROR_KINDS.HOST_CONTRACT_INVALID, "adapter source contains a duplicate skill id");
  assertUniquePortablePaths(skillIds, "adapter skill ids");

  const sources = [];
  for (const skill of source.skills) {
    const filePaths = skill.files.map((file) => assertRelative(file.path, "adapter source file path"));
    if (!filePaths.includes("SKILL.md")) throw invalidParams(`skill ${skill.id} is missing SKILL.md`);
    if (new Set(filePaths).size !== filePaths.length) throw invalidParams(`skill ${skill.id} contains a duplicate path`);
    assertUniquePortablePaths(filePaths, `skill ${skill.id}`);
    for (const file of skill.files) {
      const bytes = Buffer.from(file.content, "utf8");
      sources.push({
        sourcePath: `${skill.id}/${file.path}`,
        skillId: skill.id,
        filePath: file.path,
        content: file.content,
        bytes,
        sha256: digestBytes(bytes),
      });
    }
  }
  assertUniquePortablePaths(sources.map((entry) => entry.sourcePath), "adapter source closure");
  sources.sort((left, right) => left.sourcePath.localeCompare(right.sourcePath));
  return sources;
}

/** Pure adapter build mechanism. Host-specific path categories are injected. */
export function buildAdapterClosure({ hostId, pathCategory, input } = {}) {
  if (!hostId || !pathCategory) throw invalidParams("buildAdapterClosure requires hostId and pathCategory");
  const sources = normalizeAdapterSource(input);
  const sourceMembers = sources.map(({ sourcePath, sha256, bytes }) => ({ sourcePath, sha256, bytes: bytes.length }));
  const sourceClosure = { digest: digestDocument(sourceMembers), members: sourceMembers };
  const files = sources.map((source) => ({
    sourcePath: source.sourcePath,
    target: `${pathCategory.relPath}/${source.sourcePath}`,
    content: source.content,
    sha256: source.sha256,
    bytes: source.bytes.length,
  }));
  assertUniquePortablePaths(files.map((entry) => entry.target), "adapter target closure");
  const manifestBase = {
    schemaVersion: 1,
    kind: "skill-family.adapter-build-manifest",
    hostId,
    pathCategory,
    sourceClosure,
    members: files.map(({ sourcePath, target, sha256, bytes }) => ({ sourcePath, target, sha256, bytes })),
  };
  const manifest = validateContract({ ...manifestBase, digest: digestDocument(manifestBase) }, SCHEMAS.buildManifest, "adapter build manifest fails its registered contract");
  verifyAdapterBuildManifest(manifest, { hostId, pathCategory });
  return { status: "built", manifest, files };
}

/** Recomputes every digest and source-to-target binding before consumption. */
export function verifyAdapterBuildManifest(manifestInput, { hostId, pathCategory } = {}) {
  const manifest = validateContract(manifestInput, SCHEMAS.buildManifest, "adapter build manifest fails its registered contract");
  const { digest, ...base } = manifest;
  if (digestDocument(base) !== digest) throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "adapter manifest digest does not match its content");
  if (digestDocument(manifest.sourceClosure.members) !== manifest.sourceClosure.digest) {
    throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "adapter source closure digest does not match its members");
  }
  if (hostId !== undefined && manifest.hostId !== hostId) throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "adapter manifest host does not match the requested host");
  if (pathCategory !== undefined && canonicalJson(manifest.pathCategory) !== canonicalJson(pathCategory)) {
    throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "adapter manifest category does not match the requested category");
  }

  const sourcePaths = manifest.sourceClosure.members.map((entry) => entry.sourcePath);
  const targetPaths = manifest.members.map((entry) => entry.target);
  assertUniquePortablePaths(sourcePaths, "manifest source closure");
  assertUniquePortablePaths(targetPaths, "manifest target closure");
  if (new Set(sourcePaths).size !== sourcePaths.length || new Set(targetPaths).size !== targetPaths.length) {
    throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "adapter manifest contains duplicate members");
  }
  const sortedSources = [...sourcePaths].sort((left, right) => left.localeCompare(right));
  const outputSources = manifest.members.map((entry) => entry.sourcePath);
  if (canonicalJson(sourcePaths) !== canonicalJson(sortedSources) || canonicalJson(outputSources) !== canonicalJson(sortedSources)) {
    throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "adapter manifest members are not the canonical complete source set");
  }
  const bySource = new Map(manifest.sourceClosure.members.map((entry) => [entry.sourcePath, entry]));
  for (const member of manifest.members) {
    assertRelative(member.sourcePath, "manifest source path");
    assertRelative(member.target, "manifest target path");
    const source = bySource.get(member.sourcePath);
    const expectedTarget = `${manifest.pathCategory.relPath}/${member.sourcePath}`;
    if (!source || source.sha256 !== member.sha256 || source.bytes !== member.bytes || member.target !== expectedTarget) {
      throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "adapter manifest member is not bound to its declared source/category", { sourcePath: member.sourcePath, target: member.target });
    }
  }
  return manifest;
}

/** Atomically publishes one complete, reverified build set. */
export async function materializeAdapterBuild({ targetRoot, build, writer = writeFileAtomic } = {}) {
  if (!path.isAbsolute(targetRoot ?? "")) throw invalidParams("materializeAdapterBuild requires an absolute targetRoot");
  if (!build || build.status !== "built" || !Array.isArray(build.files)) throw invalidParams("materializeAdapterBuild requires a completed in-memory build");
  const manifest = verifyAdapterBuildManifest(build.manifest);
  if (build.files.length !== manifest.members.length) throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "in-memory build is not the manifest's complete target set");
  for (let index = 0; index < manifest.members.length; index += 1) {
    const member = manifest.members[index];
    const file = build.files[index];
    const content = Buffer.from(file?.content ?? "", "utf8");
    if (file?.sourcePath !== member.sourcePath || file?.target !== member.target || digestBytes(content) !== member.sha256 || content.length !== member.bytes) {
      throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "in-memory build bytes do not match the manifest", { index });
    }
  }

  const parent = path.dirname(targetRoot);
  const baseName = path.basename(targetRoot);
  const parentStat = await lstat(parent).catch(() => null);
  if (!parentStat?.isDirectory() || parentStat.isSymbolicLink()) throw mechanismError(HARNESS_ERROR_KINDS.HOST_BUILD_FAILED, "build target parent must be an existing plain directory");
  const resolvedParent = await realpath(parent);
  if (resolvedParent !== path.resolve(parent)) throw mechanismError(HARNESS_ERROR_KINDS.HOST_BUILD_FAILED, "build target parent path cannot contain a symlink ancestor");
  if (await lstat(targetRoot).then(() => true, () => false)) throw mechanismError(HARNESS_ERROR_KINDS.HOST_BUILD_FAILED, "host build target must be absent; no bytes were written");
  const staging = await mkdtemp(path.join(parent, `.${baseName}.host-build-`));
  try {
    for (const file of build.files) await writer(staging, file.target, file.content);
    await writer(staging, "adapter-build-manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
    for (const member of manifest.members) {
      const bytes = await readFile(path.join(staging, member.target));
      if (digestBytes(bytes) !== member.sha256 || bytes.length !== member.bytes) throw mechanismError(HARNESS_ERROR_KINDS.HOST_BUILD_FAILED, "staged adapter bytes do not match the manifest");
    }
    if (await lstat(targetRoot).then(() => true, () => false)) throw mechanismError(HARNESS_ERROR_KINDS.HOST_BUILD_FAILED, "host build target appeared during staging; staged bytes were discarded");
    // Staging is a sibling of targetRoot, so rename is same-filesystem and
    // publishes the verified member set as one namespace operation.
    await rename(staging, targetRoot);
    return { targetRoot, manifest };
  } catch (cause) {
    await rm(staging, { recursive: true, force: true });
    if (cause?.code?.startsWith?.("SFC")) throw cause;
    throw mechanismError(HARNESS_ERROR_KINDS.HOST_BUILD_FAILED, "atomic host build failed; no target was published", { causeCode: cause?.code ?? "unknown" });
  }
}

function fact(hostId, capability, state, evidence, extra = {}) {
  return validateContract({ schemaVersion: 1, kind: "skill-family.host-capability-fact", hostId, capability, state, evidence, ...extra }, SCHEMAS.capabilityFact, "probe emitted an invalid capability fact");
}

function unknownFact(hostId, capability, unknownReason, evidence, manualStep) {
  return fact(hostId, capability, "unknown", [evidence], { unknownReason, manualSteps: [manualStep] });
}

function fillLimited(hostId, capabilities, firstFacts) {
  return [...firstFacts, ...capabilities.slice(2).map((capability) => unknownFact(hostId, capability, "driver-limited", `The frozen version-only driver does not inspect ${capability}.`, `Verify ${capability} manually using the host's documented read-only interface.`))];
}

function parseVersion(output) {
  const match = String(output ?? "").match(/(?:^|[^0-9])v?((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)(?=$|[^0-9A-Za-z.+-])/);
  return match?.[1] ?? null;
}

async function verifyExecutable(executable) {
  if (typeof executable !== "string" || !path.isAbsolute(executable)) throw mechanismError(HARNESS_ERROR_KINDS.UNTRUSTED_EXECUTABLE, "host probe spawn requires an explicit absolute executable path");
  const stat = await lstat(executable).catch(() => null);
  if (!stat?.isFile() || stat.isSymbolicLink()) throw mechanismError(HARNESS_ERROR_KINDS.UNTRUSTED_EXECUTABLE, "host probe executable must be an existing plain file");
  const resolved = await realpath(executable);
  if (resolved !== path.resolve(executable)) throw mechanismError(HARNESS_ERROR_KINDS.UNTRUSTED_EXECUTABLE, "host probe executable path cannot contain symlinks");
  await access(executable, constants.X_OK).catch(() => { throw mechanismError(HARNESS_ERROR_KINDS.UNTRUSTED_EXECUTABLE, "host probe executable is not executable"); });
  return resolved;
}

/** Runs an audited vector; spawn is disabled by default and never uses PATH. */
export async function probeVersionVector({ hostId, capabilities, executable, argv, allowSpawn = false, timeoutMs = 5000, runner = spawnSync } = {}) {
  if (!Array.isArray(capabilities) || capabilities.length < 2 || capabilities[0] !== "cli" || capabilities[1] !== "version") throw invalidParams("probe capabilities must begin with cli and version");
  if (!Array.isArray(argv) || argv.some((value) => typeof value !== "string")) throw invalidParams("probe argv must be a frozen string array");
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw invalidParams("timeoutMs must be an integer from 1 to 30000");
  if (!allowSpawn) return capabilities.map((capability) => unknownFact(hostId, capability, "spawn-restricted", "Process spawning is disabled by default; no host command ran.", "Provide an audited absolute executable and explicitly opt in to the frozen non-interactive version probe."));
  const trustedExecutable = await verifyExecutable(executable);
  let result;
  try {
    result = runner(trustedExecutable, [...argv], {
      cwd: process.cwd(), env: {}, encoding: "utf8", shell: false,
      windowsHide: true, timeout: timeoutMs, maxBuffer: 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (cause) {
    return fillLimited(hostId, capabilities, [fact(hostId, "cli", "error", [`Version probe runner threw ${cause?.name ?? "Error"}.`]), fact(hostId, "version", "error", ["No version output was produced because the probe runner threw."])]);
  }
  if (result?.error) {
    const code = result.error.code ?? "unknown";
    if (code === "ENOENT") return fillLimited(hostId, capabilities, [fact(hostId, "cli", "unavailable", ["The explicitly bound executable was not found."]), fact(hostId, "version", "unavailable", ["A version cannot be observed because the CLI is unavailable."])]);
    const reason = code === "ETIMEDOUT" ? "timeout" : code === "EACCES" || code === "EPERM" ? "permission-denied" : null;
    if (reason) {
      const step = reason === "timeout" ? "Run the same frozen version command manually and inspect whether it completes without interaction." : "Run the same frozen version command in a context with read/execute permission.";
      return fillLimited(hostId, capabilities, [unknownFact(hostId, "cli", reason, `The frozen version probe ended with ${code}.`, step), unknownFact(hostId, "version", reason, "No trustworthy version was observed.", step)]);
    }
    return fillLimited(hostId, capabilities, [fact(hostId, "cli", "error", [`The process API reported spawn error ${code}.`]), fact(hostId, "version", "error", ["No trustworthy version was observed after the spawn error."])]);
  }
  if (result?.status !== 0) return fillLimited(hostId, capabilities, [fact(hostId, "cli", "available", ["The explicitly bound executable started without a spawn error."]), fact(hostId, "version", "error", [`The version command exited with status ${String(result?.status)}.`])]);
  const observedVersion = parseVersion(`${result.stdout ?? ""}\n${result.stderr ?? ""}`);
  if (!observedVersion) return fillLimited(hostId, capabilities, [fact(hostId, "cli", "available", ["The explicitly bound executable completed successfully."]), fact(hostId, "version", "error", ["Successful output did not contain a parseable semantic version."])]);
  return fillLimited(hostId, capabilities, [fact(hostId, "cli", "available", ["The explicitly bound executable completed successfully."]), fact(hostId, "version", "available", ["A semantic version was parsed from the frozen version output."], { observedVersion })]);
}
