import path from "node:path";
import { lstat, readdir, readlink } from "node:fs/promises";
import { digestDocument } from "skill-family-contracts";
import { digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { assertRelativePath, createFilesystemRootBinding, readFileBound } from "./bound-read.mjs";
import { loadNativeBoundReadAddon } from "./native/loader.mjs";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SYMLINK_POLICY_KEYS = ["mode"];

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

async function collectRecordMembers(root, rootBinding, absolute, relativePrefix, members) {
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
      await collectRecordMembers(root, rootBinding, child, relative, members);
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
        receipt = await readFileBound(root, relative, { rootBinding });
      } catch (cause) {
        throw cause;
      }
      const bytes = Buffer.from(receipt.content);
      members.push({
        path: relative,
        type: "file",
        sha256: digestBytes(bytes),
        bytes: bytes.length,
        statMode: Number(receipt.statMode),
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

async function observeFilesystemTreeRecord(root, rootBinding) {
  const members = [];
  await collectRecordMembers(root, rootBinding, root, "", members);
  return members;
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
export async function observeFilesystemTree({ root, rootBinding, symlinkPolicy } = {}) {
  const mode = parseSymlinkPolicy(symlinkPolicy);
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
