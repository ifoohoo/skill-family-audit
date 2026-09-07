import { lstat, opendir } from "node:fs/promises";
import { TextDecoder } from "node:util";
import path from "node:path";
import { canonicalJson, validateDocument } from "skill-family-contracts";
import { classifyPathInput, resolveContained } from "./paths.mjs";
import { createFilesystemRootBinding, readFileBound } from "./bound-read.mjs";
import { buildAdapterClosure } from "./host.mjs";
import { HARNESS_ERROR_KINDS, HarnessError, mechanismError } from "./errors.mjs";

const REQUEST_SCHEMA_ID = "https://contracts.skill-family.example/v1/adapter-peer-verification-request.json";
const RESULT_SCHEMA_ID = "https://contracts.skill-family.example/v1/adapter-peer-verification-result.json";

function invalidParams(message, details) {
  return new HarnessError("SFC2003", message, { ...(details ?? {}), kind: "invalid-params" });
}

function validate(document, schemaId, message) {
  const result = validateDocument(document, { schemaId, dialect: "2020-12", policy: "strict" });
  if (!result.valid) throw mechanismError(HARNESS_ERROR_KINDS.HOST_CONTRACT_INVALID, message, { errors: result.errors });
  return result.data;
}

function relativeChild(parent, name) {
  const rel = parent ? `${parent}/${name}` : name;
  const classified = classifyPathInput(rel);
  if (!classified.ok || path.posix.normalize(rel) !== rel) {
    throw mechanismError(classified.kind ?? HARNESS_ERROR_KINDS.INVALID_PATH, "peer adapter member path is not portable", { input: rel });
  }
  return rel;
}

async function collectFiles(root, rootBinding) {
  const files = [];
  async function walk(relDir) {
    const directoryPath = relDir ? await resolveContained(root, relDir) : root;
    const directoryStat = await lstat(directoryPath).catch((cause) => {
      throw mechanismError(cause?.code === "ENOENT" ? HARNESS_ERROR_KINDS.MISSING_RESOURCE : HARNESS_ERROR_KINDS.READ_FAILED, "peer adapter directory cannot be inspected", { input: relDir || "." });
    });
    if (directoryStat.isSymbolicLink()) throw mechanismError(HARNESS_ERROR_KINDS.SYMLINK_ESCAPE, "peer adapter directory contains a symbolic link", { input: relDir || "." });
    if (!directoryStat.isDirectory()) throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, "peer adapter path is not a directory", { input: relDir || "." });
    let entries;
    try {
      entries = await opendir(directoryPath);
    } catch (cause) {
      throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, "peer adapter directory cannot be enumerated", { input: relDir || ".", code: cause?.code ?? "unknown" });
    }
    try {
      for await (const entry of entries) {
        const relPath = relativeChild(relDir, entry.name);
        const absolutePath = await resolveContained(root, relPath);
        const entryStat = await lstat(absolutePath).catch((cause) => {
          throw mechanismError(cause?.code === "ENOENT" ? HARNESS_ERROR_KINDS.MISSING_RESOURCE : HARNESS_ERROR_KINDS.READ_FAILED, "peer adapter member disappeared during enumeration", { input: relPath });
        });
        if (entryStat.isSymbolicLink()) throw mechanismError(HARNESS_ERROR_KINDS.SYMLINK_ESCAPE, "peer adapter member is a symbolic link", { input: relPath });
        if (entryStat.isDirectory()) {
          await walk(relPath);
        } else if (entryStat.isFile()) {
          const receipt = await readFileBound(root, relPath, { rootBinding });
          let content;
          try {
            content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(receipt.content);
          } catch {
            throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, "peer adapter member is not valid UTF-8", { input: relPath, encoding: "utf8" });
          }
          files.push({ path: relPath, content, sha256: receipt.sha256, bytes: receipt.bytes });
        } else {
          throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, "peer adapter contains a non-regular member", { input: relPath });
        }
      }
    } finally {
      await entries.close().catch(() => {});
    }
  }
  await walk("");
  files.sort((left, right) => left.path.localeCompare(right.path));
  return files;
}

function sourceFromFiles(skillFamilyId, files) {
  const skills = new Map();
  for (const file of files) {
    const slash = file.path.indexOf("/");
    if (slash <= 0 || slash === file.path.length - 1) throw invalidParams("peer adapter files must be nested below a skill directory", { path: file.path });
    const skillId = file.path.slice(0, slash);
    const skillPath = file.path.slice(slash + 1);
    if (!skills.has(skillId)) skills.set(skillId, []);
    skills.get(skillId).push({ path: skillPath, content: file.content });
  }
  return {
    schemaVersion: 1,
    kind: "skill-family.adapter-source",
    skillFamilyId,
    skills: [...skills.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([id, entries]) => ({
      id,
      files: entries.sort((left, right) => left.path.localeCompare(right.path)),
    })),
  };
}

function verifyMappings(peer, manifest) {
  const mappings = peer.logicalMappings;
  const logicalIds = new Set();
  const sourcePaths = new Set();
  const expectedSkillEntries = new Set(manifest.sourceClosure.members
    .filter((member) => member.sourcePath.split("/").length === 2 && member.sourcePath.endsWith("/SKILL.md"))
    .map((member) => member.sourcePath));
  if (mappings.length !== expectedSkillEntries.size) throw mechanismError(HARNESS_ERROR_KINDS.HOST_CONTRACT_INVALID, "peer logicalMappings must cover every skill entry exactly once");
  const output = mappings.map((mapping) => {
    if (logicalIds.has(mapping.logicalId)) throw mechanismError(HARNESS_ERROR_KINDS.HOST_CONTRACT_INVALID, "peer logicalMappings contain a duplicate logicalId", { logicalId: mapping.logicalId });
    logicalIds.add(mapping.logicalId);
    if (sourcePaths.has(mapping.sourcePath)) throw mechanismError(HARNESS_ERROR_KINDS.HOST_CONTRACT_INVALID, "peer logicalMappings contain a duplicate sourcePath", { sourcePath: mapping.sourcePath });
    sourcePaths.add(mapping.sourcePath);
    const sourceParts = mapping.sourcePath.split("/");
    if (sourceParts.length !== 2 || sourceParts[1] !== "SKILL.md" || !expectedSkillEntries.has(mapping.sourcePath)) throw mechanismError(HARNESS_ERROR_KINDS.HOST_CONTRACT_INVALID, "peer logicalMapping must point to a root-level existing SKILL.md", { sourcePath: mapping.sourcePath });
    const expectedSkillId = sourceParts[0];
    if (mapping.skillId !== expectedSkillId) throw mechanismError(HARNESS_ERROR_KINDS.HOST_CONTRACT_INVALID, "peer logicalMapping skillId does not match its sourcePath", { sourcePath: mapping.sourcePath });
    return { ...mapping, target: `${peer.pathCategory.relPath}/${mapping.sourcePath}` };
  }).sort((left, right) => left.logicalId.localeCompare(right.logicalId));
  if (canonicalJson([...sourcePaths].sort()) !== canonicalJson([...expectedSkillEntries].sort())) throw mechanismError(HARNESS_ERROR_KINDS.HOST_CONTRACT_INVALID, "peer logicalMappings do not cover the complete SKILL.md set");
  return output;
}

function mappingSemantics(mappings) {
  return mappings.map(({ logicalId, skillId, sourcePath, entryType, userInvocable }) => ({ logicalId, skillId, sourcePath, entryType, userInvocable }))
    .sort((left, right) => left.logicalId.localeCompare(right.logicalId));
}

function assertRawBytesMatch(files, manifest) {
  const byPath = new Map(files.map((file) => [file.path, file]));
  for (const member of manifest.sourceClosure.members) {
    const file = byPath.get(member.sourcePath);
    if (!file || file.sha256 !== member.sha256 || file.bytes !== member.bytes) {
      throw mechanismError(HARNESS_ERROR_KINDS.MANIFEST_MISMATCH, "adapter manifest does not match the original bound bytes", { sourcePath: member.sourcePath });
    }
  }
}

/** Reads and verifies two or more real peer adapter directories. */
export async function verifyPeerAdapterDirectories({ request, peerRoots } = {}) {
  const verifiedRequest = validate(request, REQUEST_SCHEMA_ID, "peer adapter verification request fails its registered contract");
  if (!peerRoots || typeof peerRoots !== "object" || Array.isArray(peerRoots)) throw invalidParams("verifyPeerAdapterDirectories requires a peerRoots object");
  const requestIds = verifiedRequest.peers.map((peer) => peer.peerId);
  if (new Set(requestIds).size !== requestIds.length) throw invalidParams("peerIds must be unique");
  const rootIds = Object.keys(peerRoots);
  if (canonicalJson([...rootIds].sort()) !== canonicalJson([...requestIds].sort())) throw invalidParams("peerRoots must contain exactly one absolute root for every requested peer");

  const built = [];
  for (const peer of verifiedRequest.peers) {
    const root = peerRoots[peer.peerId];
    if (typeof root !== "string" || !path.isAbsolute(root)) throw invalidParams("peer root must be an absolute path", { peerId: peer.peerId });
    const rootBinding = await createFilesystemRootBinding(root);
    const files = await collectFiles(root, rootBinding);
    const build = buildAdapterClosure({ hostId: peer.hostId, pathCategory: peer.pathCategory, input: sourceFromFiles(verifiedRequest.skillFamilyId, files) });
    assertRawBytesMatch(files, build.manifest);
    const logicalMappings = verifyMappings(peer, build.manifest);
    built.push({ peer, build, logicalMappings });
  }

  const sorted = [...built].sort((left, right) => left.peer.peerId.localeCompare(right.peer.peerId));
  const common = sorted[0].build.manifest.sourceClosure;
  const commonMappings = mappingSemantics(sorted[0].logicalMappings);
  for (const entry of sorted.slice(1)) {
    if (canonicalJson(entry.build.manifest.sourceClosure) !== canonicalJson(common)) {
      throw mechanismError(HARNESS_ERROR_KINDS.CLOSURE_CONFLICT, "peer adapter source closures differ", { peerId: entry.peer.peerId });
    }
    if (canonicalJson(mappingSemantics(entry.logicalMappings)) !== canonicalJson(commonMappings)) {
      throw mechanismError(HARNESS_ERROR_KINDS.CLOSURE_CONFLICT, "peer logical mapping semantics differ", { peerId: entry.peer.peerId });
    }
  }
  const result = {
    schemaVersion: 1,
    kind: "skill-family.adapter-peer-verification-result",
    status: "verified",
    decision: "peer-verification",
    skillFamilyId: verifiedRequest.skillFamilyId,
    commonSourceClosure: common,
    peers: sorted.map(({ peer, build, logicalMappings }) => ({
      peerId: peer.peerId,
      hostId: peer.hostId,
      pathCategory: peer.pathCategory,
      manifest: build.manifest,
      logicalMappings,
    })),
  };
  return validate(result, RESULT_SCHEMA_ID, "peer adapter verification result fails its registered contract");
}
