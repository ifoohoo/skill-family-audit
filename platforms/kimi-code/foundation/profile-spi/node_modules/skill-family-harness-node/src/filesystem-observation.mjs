// @feature FND-FR-014
// @decision FND-ADR-024
// @design FND-DES-018
import path from "node:path";
import process from "node:process";
import { lstat, readdir, readlink } from "node:fs/promises";
import { digestDocument } from "skill-family-contracts";
import { digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { assertRelativePath, createFilesystemRootBinding, readFileBound } from "./bound-read.mjs";
import { loadNativeBoundReadAddon, loadWindowsNativeAddon } from "./native/loader.mjs";
import { canonicalizeWindowsDriveAbsolute } from "./paths.mjs";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SYMLINK_POLICY_KEYS = ["mode"];
export const WINDOWS_SYMLINK_REPARSE_TAG = 0xA000000C;

/**
 * Windows reparse policy. `reject` refuses every reparse point. `record`
 * keeps only a symlink tag; every other tag is refused and is not followed.
 */
export function windowsReparseDecision(policyMode, reparseTag) {
  if (policyMode !== "record" && policyMode !== "reject") {
    throw new TypeError('windows reparse policy must be "record" or "reject"');
  }
  if (!Number.isInteger(reparseTag) || reparseTag < 0 || reparseTag > 0xFFFFFFFF) return "refuse";
  if (policyMode === "reject") return "refuse";
  return reparseTag === WINDOWS_SYMLINK_REPARSE_TAG ? "record-symlink" : "refuse";
}

function compareUnicodeCodePoints(left, right) {
  const leftPoints = Array.from(left, (character) => character.codePointAt(0));
  const rightPoints = Array.from(right, (character) => character.codePointAt(0));
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
  }
  return leftPoints.length - rightPoints.length;
}

function parseSymlinkPolicy(symlinkPolicy) {
  if (symlinkPolicy === undefined) return "reject";
  if (symlinkPolicy === null || typeof symlinkPolicy !== "object" || Array.isArray(symlinkPolicy) ||
      Object.keys(symlinkPolicy).sort().join(",") !== SYMLINK_POLICY_KEYS.join(",") ||
      !["record", "reject"].includes(symlinkPolicy.mode)) {
    throw new TypeError('observeFilesystemTree: symlinkPolicy must be { mode: "record"|"reject" }');
  }
  return symlinkPolicy.mode;
}

function recordBoundary(message, input, cause) {
  throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, message, {
    ...(input === undefined ? {} : { input }),
    boundReadDisposition: "boundary-indeterminate",
    ...(cause === undefined ? {} : { cause: cause?.message ?? String(cause) }),
  });
}

function sameLinkStat(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs;
}

async function readStableSymlink(relative, absolute) {
  let before;
  try {
    before = await lstat(absolute, { bigint: true });
    if (!before.isSymbolicLink()) recordBoundary("filesystem tree link changed before it could be recorded", relative);
    const first = Buffer.from(await readlink(absolute, { encoding: "buffer" }));
    const middle = await lstat(absolute, { bigint: true });
    const second = Buffer.from(await readlink(absolute, { encoding: "buffer" }));
    const after = await lstat(absolute, { bigint: true });
    if (!sameLinkStat(before, middle) || !sameLinkStat(before, after) ||
        !first.equals(second)) {
      recordBoundary("filesystem tree symbolic link changed while being read", relative);
    }
    return {
      path: relative,
      type: "symlink",
      targetBase64: first.toString("base64"),
      bytes: first.length,
      statMode: Number(after.mode),
    };
  } catch (cause) {
    if (cause?.code === "SFC2004") throw cause;
    recordBoundary("filesystem tree symbolic link could not be recorded", relative, cause);
  }
}

async function collectRecordMembers(root, rootBinding, absolute, relativePrefix, members, readPlatform = process.platform) {
  let directoryBefore;
  try {
    directoryBefore = await lstat(absolute, { bigint: true });
    if (!directoryBefore.isDirectory()) {
      recordBoundary("filesystem tree directory changed before it could be read", relativePrefix || undefined);
    }
  } catch (cause) {
    recordBoundary("filesystem tree directory could not be inspected", relativePrefix || undefined, cause);
  }
  let entries;
  try {
    entries = await readdir(absolute, { withFileTypes: true });
  } catch (cause) {
    recordBoundary("filesystem tree directory could not be enumerated", relativePrefix || undefined, cause);
  }
  for (const entry of entries) {
    const relative = relativePrefix ? path.posix.join(relativePrefix, entry.name) : entry.name;
    assertRelativePath(relative);
    const child = path.join(root, ...relative.split("/"));
    let stats;
    try {
      stats = await lstat(child, { bigint: true });
    } catch (cause) {
      recordBoundary("filesystem tree member could not be inspected", relative, cause);
    }
    if (stats.isSymbolicLink()) {
      members.push(await readStableSymlink(relative, child));
      continue;
    }
    if (stats.isDirectory()) {
      members.push({ path: relative, type: "directory", statMode: Number(stats.mode) });
      await collectRecordMembers(root, rootBinding, child, relative, members, readPlatform);
      let after;
      try {
        after = await lstat(child, { bigint: true });
      } catch (cause) {
        recordBoundary("filesystem tree directory changed while being read", relative, cause);
      }
      if (!sameLinkStat(stats, after)) {
        recordBoundary("filesystem tree directory changed while being read", relative);
      }
      continue;
    }
    if (stats.isFile()) {
      if (stats.nlink !== 1n) {
        recordBoundary("filesystem tree contains a multiply-linked regular file", relative);
      }
      let receipt;
      try {
        receipt = await readFileBound(root, relative, { rootBinding, platform: readPlatform });
      } catch (cause) {
        throw cause;
      }
      const bytes = Buffer.from(receipt.content);
      members.push({
        path: relative,
        type: "file",
        sha256: digestBytes(bytes),
        bytes: bytes.length,
        statMode: Number.isInteger(receipt.statMode) ? Number(receipt.statMode) : Number(stats.mode),
        contentBase64: bytes.toString("base64"),
      });
      continue;
    }
    recordBoundary("filesystem tree contains a special file", relative);
  }
  let directoryAfter;
  try {
    directoryAfter = await lstat(absolute, { bigint: true });
  } catch (cause) {
    recordBoundary("filesystem tree directory changed while being read", relativePrefix || undefined, cause);
  }
  if (!sameLinkStat(directoryBefore, directoryAfter)) {
    recordBoundary("filesystem tree directory changed while being read", relativePrefix || undefined);
  }
}

async function observeFilesystemTreeRecord(root, rootBinding, readPlatform = process.platform) {
  const members = [];
  await collectRecordMembers(root, rootBinding, root, "", members, readPlatform);
  return members;
}

async function refuseReparsePoints(root) {
  async function walk(directory, relativePrefix) {
    const entries = await readdir(directory);
    for (const name of entries) {
      const relative = relativePrefix ? path.posix.join(relativePrefix, name) : name;
      const child = path.join(directory, name);
      const stats = await lstat(child);
      if (stats.isSymbolicLink()) {
        throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "Windows reject policy refuses a reparse point and returns no bytes", {
          input: relative,
          failureReason: "reparse",
        });
      }
      if (stats.isDirectory()) await walk(child, relative);
    }
  }
  await walk(root, "");
}

function windowsPermissionObservation(attributes, descriptor) {
  return {
    kind: "windows-security-v1",
    attributes: Number(attributes) >>> 0,
    securityDigest: digestBytes(Buffer.from(descriptor)),
  };
}

async function collectWindowsMembers(root, rootBinding, mode) {
  const loaded = await loadWindowsNativeAddon();
  const captured = loaded.addon.observeFilesystemTreeNative(root, mode === "record");
  if (!captured?.ok || !Array.isArray(captured.members)) {
    recordBoundary("Windows bound tree observation failed", undefined, captured?.failureReason);
  }
  const rootFact = captured.root;
  const binding = digestDocument({ canonicalFinalPath: rootFact.canonicalPath,
    volumeSerial: rootFact.volumeSerial, fileId: rootFact.fileId, type: "directory",
    securityDigest: digestBytes(Buffer.from(rootFact.securityDescriptor)) });
  if (binding !== rootBinding.digest) recordBoundary("Windows bound tree root changed");
  return captured.members.map((member) => {
    assertRelativePath(member.path);
    const permissionObservation = windowsPermissionObservation(member.attributes, member.securityDescriptor);
    if (member.type === "directory") return { path: member.path, type: "directory", statMode: null, permissionObservation };
    if (member.type === "symlink") {
      const target = Buffer.from(member.reparseTarget);
      return { path: member.path, type: "symlink", statMode: null, permissionObservation,
        reparseTag: member.reparseTag, targetBase64: target.toString("base64"), bytes: target.length };
    }
    const bytes = Buffer.from(member.bytes);
    return { path: member.path, type: "file", statMode: null, permissionObservation,
      sha256: digestBytes(bytes), bytes: bytes.length, contentBase64: bytes.toString("base64") };
  });
}

async function observeWindowsNativeTree({ root, rootBinding, mode }) {
  const canonicalRoot = canonicalizeWindowsDriveAbsolute(root);
  if (canonicalRoot === null) throw new TypeError("observeFilesystemTree: root must be a canonical Windows drive path");
  if (!rootBinding || typeof rootBinding !== "object" || typeof rootBinding.digest !== "string" || !SHA256_PATTERN.test(rootBinding.digest)) {
    throw new TypeError("observeFilesystemTree: rootBinding is required");
  }
  const startBinding = await createFilesystemRootBinding(canonicalRoot);
  if (startBinding.digest !== rootBinding.digest) {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "approved root binding does not match the current root", {
      boundReadDisposition: "boundary-indeterminate",
    });
  }
  const members = await collectWindowsMembers(canonicalRoot, rootBinding, mode);
  // Native enumeration and exact handle names honor each directory's actual case rules.
  const endBinding = await createFilesystemRootBinding(canonicalRoot);
  if (endBinding.digest !== rootBinding.digest) {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "root identity changed during filesystem tree observation", {
      boundReadDisposition: "boundary-indeterminate",
    });
  }
  members.sort((left, right) => compareUnicodeCodePoints(left.path, right.path));
  return Object.freeze({
    schemaVersion: 2,
    kind: "skill-family.filesystem-tree-observation",
    rootBinding,
    members: Object.freeze(members.map((member) => Object.freeze(member))),
    membersDigest: digestDocument(members),
  });
}

function rejectCaseAliasMembers(members) {
  const paths = new Set();
  for (const member of members) {
    const alias = member.path.toLowerCase();
    if (paths.has(alias)) {
      throw mechanismError(HARNESS_ERROR_KINDS.INVALID_PATH, "filesystem tree contains duplicate or case-alias member paths");
    }
    paths.add(alias);
  }
}

/**
 * Observe every member of one already bound tree. The default reject path
 * keeps the native 0.14 contract; explicit record mode is a Node/JS
 * best-effort observation of symlinks and reuses readFileBound for files.
 */
export async function observeFilesystemTree({ root, rootBinding, symlinkPolicy, platform = process.platform } = {}) {
  const mode = parseSymlinkPolicy(symlinkPolicy);
  if (platform === "win32" && process.platform === "win32") {
    return observeWindowsNativeTree({ root, rootBinding, mode });
  }
  if (platform === "win32") {
    windowsReparseDecision(mode, WINDOWS_SYMLINK_REPARSE_TAG);
    if (typeof root !== "string" || !path.isAbsolute(root) || path.normalize(root) !== root) {
      throw new TypeError("observeFilesystemTree: root must be a normalized absolute path");
    }
    if (!rootBinding || typeof rootBinding !== "object" ||
        typeof rootBinding.digest !== "string" || !SHA256_PATTERN.test(rootBinding.digest)) {
      throw new TypeError("observeFilesystemTree: rootBinding is required");
    }
    const startBinding = await createFilesystemRootBinding(root);
    if (startBinding.digest !== rootBinding.digest) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "approved root binding does not match the current root", {
        boundReadDisposition: "boundary-indeterminate",
      });
    }
    if (mode === "reject") await refuseReparsePoints(root);
    const members = await observeFilesystemTreeRecord(root, rootBinding, "win32");
    // Native enumeration and exact handle names honor each directory's actual case rules.
    const endBinding = await createFilesystemRootBinding(root);
    if (endBinding.digest !== rootBinding.digest) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "root identity changed during filesystem tree observation", {
        boundReadDisposition: "boundary-indeterminate",
      });
    }
    members.sort((left, right) => compareUnicodeCodePoints(left.path, right.path));
    return Object.freeze({
      schemaVersion: process.platform === "win32" ? 2 : 1,
      kind: "skill-family.filesystem-tree-observation",
      rootBinding,
      members: Object.freeze(members.map((member) => Object.freeze(member))),
      membersDigest: digestDocument(members),
    });
  }
  if (typeof root !== "string" || !path.isAbsolute(root) || path.normalize(root) !== root) {
    throw new TypeError("observeFilesystemTree: root must be a normalized absolute path");
  }
  if (!rootBinding || typeof rootBinding !== "object" ||
      typeof rootBinding.digest !== "string" || !SHA256_PATTERN.test(rootBinding.digest)) {
    throw new TypeError("observeFilesystemTree: rootBinding is required");
  }
  const startBinding = await createFilesystemRootBinding(root);
  if (startBinding.digest !== rootBinding.digest) {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "approved root binding does not match the current root", {
      boundReadDisposition: "boundary-indeterminate",
    });
  }
  if (mode === "record") {
    const members = await observeFilesystemTreeRecord(root, rootBinding);
    rejectCaseAliasMembers(members);
    const endBinding = await createFilesystemRootBinding(root);
    if (endBinding.digest !== rootBinding.digest) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "root identity changed during filesystem tree observation", {
        boundReadDisposition: "boundary-indeterminate",
      });
    }
    members.sort((left, right) => compareUnicodeCodePoints(left.path, right.path));
    return Object.freeze({
      schemaVersion: 1,
      kind: "skill-family.filesystem-tree-observation",
      rootBinding,
      members: Object.freeze(members.map((member) => Object.freeze(member))),
      membersDigest: digestDocument(members),
    });
  }
  const { addon } = await loadNativeBoundReadAddon();
  if (typeof addon.observeFilesystemTreeNative !== "function") {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSUPPORTED_PLATFORM, "native filesystem observation is unavailable in this prebuild");
  }
  let native;
  try {
    native = addon.observeFilesystemTreeNative(root);
  } catch (cause) {
    throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, "filesystem tree observation failed", {
      cause: cause?.message ?? "unknown",
    });
  }
  const endBinding = await createFilesystemRootBinding(root);
  if (endBinding.digest !== rootBinding.digest || native.rootDevice === undefined || native.rootInode === undefined ||
      Number(native.rootMode) !== Number.parseInt(native.rootMode, 10)) {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "root identity changed during filesystem tree observation", {
      boundReadDisposition: "boundary-indeterminate",
    });
  }
  const paths = new Set();
  const members = Array.from(native.members ?? [], (member) => {
    assertRelativePath(member.path);
    const alias = member.path.toLowerCase();
    if (paths.has(alias)) throw mechanismError(HARNESS_ERROR_KINDS.INVALID_PATH, "filesystem tree contains duplicate or case-alias member paths");
    paths.add(alias);
    if (member.type === "directory") {
      return { path: member.path, type: "directory", statMode: Number(member.statMode) };
    }
    const bytes = Buffer.from(member.content);
    return {
      path: member.path,
      type: "file",
      sha256: digestBytes(bytes),
      bytes: bytes.length,
      statMode: Number(member.statMode),
      contentBase64: bytes.toString("base64"),
    };
  }).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return Object.freeze({
    schemaVersion: 1,
    kind: "skill-family.filesystem-tree-observation",
    rootBinding,
    members: Object.freeze(members.map((member) => Object.freeze(member))),
    membersDigest: digestDocument(members),
  });
}
