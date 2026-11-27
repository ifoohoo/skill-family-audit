// @feature FND-FR-003
// @decision FND-ADR-004
// @design FND-DES-003
import { createHash, randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS } from "node:fs";
import { link, lstat, mkdir, open, realpath, rename, rm, unlink } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { digestDocument } from "../contracts/index.mjs";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { loadWindowsNativeAddon } from "./native/loader.mjs";
import { canonicalizeWindowsDriveAbsolute, resolveContained } from "./paths.mjs";

/**
 * `writeFileAtomic` is the compatibility convenience writer. It provides an
 * atomic namespace replacement, but deliberately does not claim exclusive
 * publication, strict post-commit verification, or durable directory sync.
 * Callers that require those guarantees must use `publishFileExclusive` or
 * `replaceFileAtomic`.
 */

let testHooks = null;

function windowsPermissionObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  if (Object.keys(value).length !== 1 || !Object.hasOwn(value, "kind")) return null;
  if (value.kind !== "windows-inherited" && value.kind !== "windows-preserve") return null;
  return Object.freeze({ kind: value.kind });
}

export function publicationPermissionDecision(platform = process.platform, options = {}) {
  if (platform === "win32") {
    if (Object.hasOwn(options, "mode")) {
      throw new TypeError("Windows publication does not accept a POSIX mode");
    }
    if (options.permissions === undefined) {
      return Object.freeze({ mode: null, permissions: Object.freeze({ kind: "windows-inherited" }) });
    }
    const permissions = windowsPermissionObject(options.permissions);
    if (permissions === null) {
      throw new TypeError('Windows publication permissions must be {kind:"windows-inherited"} or {kind:"windows-preserve"}');
    }
    return Object.freeze({ mode: null, permissions });
  }
  if (options.permissions !== undefined) {
    throw new TypeError("POSIX publication does not accept Windows permissions");
  }
  return Object.freeze({ mode: options.mode ?? 0o644, permissions: null });
}

function posixPublicationMode(options) {
  return publicationPermissionDecision(process.platform, options).mode;
}

export function windowsPublicationKind({ targetExists, permissions } = {}) {
  if (permissions === undefined || permissions === null) {
    return targetExists === true ? "windows-preserve" : "windows-inherited";
  }
  const permissionsObject = windowsPermissionObject(permissions);
  if (permissionsObject === null) {
    throw new TypeError('Windows publication kind requires {kind:"windows-inherited"} or {kind:"windows-preserve"}');
  }
  return permissionsObject.kind;
}

const WINDOWS_LOCAL_SYSTEM_SID = Buffer.from([0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00]);
const WINDOWS_ACE_INHERIT_FLAGS = 0x01 | 0x02 | 0x10;

function windowsSid(buffer, offset) {
  if (offset < 0 || offset + 8 > buffer.length || buffer[offset] !== 1) return null;
  const count = buffer[offset + 1];
  const length = 8 + count * 4;
  if (count > 15 || offset + length > buffer.length) return null;
  return buffer.subarray(offset, offset + length);
}

/** Self-relative owner/group/DACL disposition. A wide or inheriting DACL is refused. */
export function windowsSecurityDisposition(descriptor) {
  const refused = { protected: false, inheriting: true };
  if (!Buffer.isBuffer(descriptor) || descriptor.length < 20 || descriptor[0] !== 1) return refused;
  const control = descriptor.readUInt16LE(2);
  const selfRelative = (control & 0x8000) !== 0;
  const daclPresent = (control & 0x0004) !== 0;
  const daclProtected = (control & 0x1000) !== 0;
  if (!selfRelative || !daclPresent || !daclProtected) return refused;
  const owner = windowsSid(descriptor, descriptor.readUInt32LE(4));
  const daclOffset = descriptor.readUInt32LE(16);
  if (owner === null || daclOffset === 0 || daclOffset + 8 > descriptor.length) return refused;
  const aclSize = descriptor.readUInt16LE(daclOffset + 2);
  const aceCount = descriptor.readUInt16LE(daclOffset + 4);
  if (aclSize < 8 || daclOffset + aclSize > descriptor.length || aceCount < 1) return refused;
  let cursor = daclOffset + 8;
  const end = daclOffset + aclSize;
  for (let index = 0; index < aceCount; index += 1) {
    if (cursor + 8 > end) return refused;
    const aceType = descriptor[cursor];
    const flags = descriptor[cursor + 1];
    const size = descriptor.readUInt16LE(cursor + 2);
    if (size < 8 || cursor + size > end || (aceType !== 0 && aceType !== 1)) return refused;
    if ((flags & WINDOWS_ACE_INHERIT_FLAGS) !== 0) return { protected: true, inheriting: true };
    const sid = windowsSid(descriptor, cursor + 8);
    if (sid === null || (!sid.equals(owner) && !sid.equals(WINDOWS_LOCAL_SYSTEM_SID))) return refused;
    cursor += size;
  }
  return { protected: true, inheriting: false };
}

export function acceptWindowsPublication({
  bytesEqual,
  identityEqual,
  daclEqual,
  securityDigest = null,
  attributes = null,
} = {}) {
  const permissionObservation = {
    kind: "windows-security-v1",
    securityDigest,
  };
  if (typeof attributes === "number" && Number.isInteger(attributes) && attributes >= 0 && attributes <= 0xffffffff) {
    permissionObservation.attributes = attributes;
  }
  return Object.freeze({
    publicationState: bytesEqual === true && identityEqual === true && daclEqual === true ? "published" : "not-published",
    permissionObservation: Object.freeze(permissionObservation),
  });
}

export function acceptProtectedMaterialDirectory(input = {}) {
  const isProtected = input.protected === true;
  const inheriting = input.inheriting === true;
  return Object.freeze({ accepted: isProtected === true && inheriting === false });
}

export async function syncForDurability(target, options = {}) {
  const directory = options.directory === true;
  if (process.platform === "win32") {
    const loaded = await loadWindowsNativeAddon();
    const flushed = options.handle?.windowsHandle
      ? loaded.addon.flushFileHandle(options.handle.windowsHandle) === true
      : loaded.addon.flushDirectory(target) === true;
    if (!flushed) {
      const error = new Error("flush-failed");
      error.code = "EIO";
      throw error;
    }
    return;
  }
  if (options.handle) {
    await options.handle.sync();
    return;
  }
  const directoryGuard = directory ? (FS_CONSTANTS.O_NOFOLLOW ?? 0) : 0;
  const handle = await open(target, FS_CONSTANTS.O_RDONLY | directoryGuard);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function publishWindowsFile(action, root, relPath, data, options) {
  const operation = action === "exclusive" ? "publishFileExclusive" : action === "replace" ? "replaceFileAtomic" : "publishFileOrReplace";
  assertWritableData(data, operation);
  const internalProtected = options.internalMaterial === "windows-protected";
  if (internalProtected && (options.permissions !== undefined || Object.hasOwn(options, "mode"))) {
    throw new TypeError("internal protected publication does not accept public permissions or a POSIX mode");
  }
  const decision = internalProtected ? null : publicationPermissionDecision("win32", options);
  const bytes = bytesOf(data);
  const located = await strictTarget(root, relPath, {
    target: action === "exclusive" ? "absent" : action === "replace" ? "regular" : "regular-or-absent",
    createParents: action === "exclusive" && options.createParents === true,
  });
  let loaded;
  try {
    loaded = await loadWindowsNativeAddon();
  } catch (cause) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSUPPORTED_PLATFORM,
      cause?.message ?? "win32-x64 native addon is not built",
      { input: relPath, phase: "pre-commit", publicationState: "not-published" },
    );
  }
  const replacing = located.targetStats !== null;
  const kind = internalProtected
    ? "windows-protected"
    : (options.permissions === undefined
      ? windowsPublicationKind({ targetExists: replacing })
      : decision.permissions.kind);
  const failureKind = action === "exclusive" ? HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLICATION_FAILED : HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED;
  const parent = located.windowsExpectation.parent;
  const approvedTarget = located.windowsExpectation.target;
  if (!parent?.ok || (replacing && !approvedTarget?.ok)) {
    throw strictFailure(failureKind, "Windows publication inspection", new Error("initial identity unavailable"), relPath, false, false);
  }
  const expectation = { parent, target: approvedTarget };
  try {
    await runTestHook(action === "exclusive" ? "beforeExclusiveCommit" : action === "replace" ? "beforeReplaceCommit" : "beforePublishOrReplaceCommit",
      { targetPath: located.targetPath, directory: located.directory });
  } catch (cause) { throw strictFailure(failureKind, "Windows publication", cause, relPath, false, false); }
  const native = loaded.addon.publishProtectedFile(located.targetPath, bytes, kind, replacing, undefined, undefined, expectation);
  const committed = native?.committed === true;
  if (!native?.ok) {
    if (!committed && native?.failureReason === "exists" && action === "exclusive") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLISH_CONFLICT,
        "exclusive publication target already exists",
        { input: relPath, phase: "pre-commit", publicationState: "not-published" },
      );
    }
    throw strictFailure(
      failureKind,
      "Windows publication",
      new Error(native?.failureReason ?? "native-io"),
      relPath,
      committed,
      false,
    );
  }
  let verified = false;
  try {
    await runTestHook(action === "exclusive" ? "afterExclusiveCommit" : action === "replace" ? "afterReplaceCommit" : "afterPublishOrReplaceCommit", { targetPath: located.targetPath });
    const actual = Buffer.isBuffer(native.bytes) ? Buffer.from(native.bytes) : null;
    const postDescriptor = Buffer.isBuffer(native.securityDescriptor) ? Buffer.from(native.securityDescriptor) : null;
    const preDescriptor = Buffer.isBuffer(native.preSecurityDescriptor) ? Buffer.from(native.preSecurityDescriptor) : null;
    if (actual === null || postDescriptor === null || !/^[0-9a-f]{16}$/u.test(native.volumeSerial ?? "") ||
        !/^[0-9a-f]{32}$/u.test(native.fileId ?? "") ||
        (native.preFileId !== undefined && !/^[0-9a-f]{32}$/u.test(native.preFileId))) {
      throw new Error("published bytes, identity, or DACL did not match");
    }
    const postDigest = digest(postDescriptor);
    const preDigest = preDescriptor === null ? null : digest(preDescriptor);
    const identityEqual = native.parentFileId === parent.fileId && native.volumeSerial === parent.volumeSerial &&
      (!replacing || native.preFileId === approvedTarget.fileId);
    const daclEqual = preDigest === null || preDigest === postDigest;
    const accepted = acceptWindowsPublication({
      bytesEqual: actual.equals(bytes),
      identityEqual,
      daclEqual,
      securityDigest: postDigest,
      attributes: Number(native.attributes) >>> 0,
    });
    if (accepted.publicationState !== "published") {
      throw new Error("published bytes, identity, or DACL did not match");
    }
    verified = true;
    await runTestHook(action === "exclusive" ? "beforeExclusiveDirectorySync" : action === "replace" ? "beforeReplaceDirectorySync" : "beforePublishOrReplaceDirectorySync", { targetPath: located.targetPath, directory: located.directory });
    return Object.freeze({
      path: located.targetPath,
      publicationState: accepted.publicationState,
      sha256: digest(bytes),
      bytes: bytes.length,
      mode: null,
      permissions: kind,
      permissionObservation: accepted.permissionObservation,
    });
  } catch (cause) {
    throw strictFailure(failureKind, "Windows publication", cause, relPath, true, verified);
  }
}

function assertWritableData(data, operation) {
  const ok =
    typeof data === "string" ||
    Buffer.isBuffer(data) ||
    ArrayBuffer.isView(data) ||
    data instanceof ArrayBuffer;
  if (!ok) {
    throw new TypeError(
      `${operation}: data must be a string, Buffer, TypedArray, DataView, or ArrayBuffer`,
    );
  }
}

function normalizeMode(mode) {
  if (!Number.isInteger(mode) || mode < 0 || mode > 0o777) {
    throw new TypeError("file mode must be an integer between 0 and 0o777");
  }
  return mode;
}

function bytesOf(data) {
  if (typeof data === "string") return Buffer.from(data);
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function snapshotRegularTarget(target, expectedStats = null) {
  const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  const before = await lstat(target);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.nlink !== 1 ||
    (expectedStats !== null && !sameIdentity(before, expectedStats))
  ) {
    return null;
  }
  const handle = await open(target, FS_CONSTANTS.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat();
    if (!sameIdentity(before, opened) || !opened.isFile() || opened.nlink !== 1) return null;
    const bytes = await handle.readFile();
    return {
      stats: opened,
      mode: opened.mode & 0o777,
      sha256: digest(bytes),
      bytes: bytes.length,
    };
  } finally {
    await handle.close();
  }
}

async function removeQuiet(candidate) {
  try {
    await rm(candidate, { force: true });
  } catch {
    // Compatibility cleanup is intentionally best-effort.
  }
}

async function runTestHook(name, context) {
  if (typeof testHooks?.[name] === "function") await testHooks[name](context);
}

async function createParentDirectory(cursor, relPath) {
  try {
    await mkdir(cursor);
  } catch (cause) {
    // EEXIST is a benign concurrent creation race: re-verify the entry below.
    if (cause?.code !== "EEXIST") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.INVALID_ROOT,
        "strict file operation could not create a missing parent directory",
        { input: relPath, code: cause?.code },
      );
    }
  }
  const created = await lstat(cursor);
  if (created.isSymbolicLink() || !created.isDirectory()) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      "strict file operation requires real intermediate directories",
      { input: relPath },
    );
  }
}

async function strictTarget(root, relPath, { target = "optional", createParents = false } = {}) {
  const lexical = await resolveContained(root, relPath);
  const rootReal = await realpath(root);
  if (process.platform === "win32") {
    const loaded = await loadWindowsNativeAddon();
    const directory = path.dirname(lexical);
    if (createParents) {
      const segments = path.relative(rootReal, directory).split(path.sep).filter(Boolean);
      let cursor = rootReal;
      for (const segment of segments) {
        cursor = path.join(cursor, segment);
        await createParentDirectory(cursor, relPath);
      }
    }
    const parent = loaded.addon.captureSecurity(directory);
    if (!parent?.ok && parent?.failureReason === "member-missing") throw mechanismError(HARNESS_ERROR_KINDS.INVALID_ROOT, "Windows parent does not exist", { input: relPath });
    if (!parent?.ok || (parent.attributes & 0x410) !== 0x10) throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "Windows parent is not one safely bound directory", { input: relPath });
    const actual = loaded.addon.readCapturedFile(lexical);
    const exists = actual?.ok === true;
    if (target === "absent" && !exists && actual?.failureReason !== "member-missing") {
      const existing = loaded.addon.captureSecurity(lexical);
      if (existing?.ok && (existing.attributes & 0x400) === 0) throw mechanismError(
        HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLISH_CONFLICT, "exclusive publication target already exists",
        { input: relPath, phase: "pre-commit", publicationState: "not-published" });
    }
    if (!exists && actual?.failureReason !== "member-missing") throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "Windows target cannot be safely inspected", { input: relPath });
    if (target === "absent" && exists) throw mechanismError(HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLISH_CONFLICT, "exclusive publication target already exists", { input: relPath, phase: "pre-commit", publicationState: "not-published" });
    if (target === "regular" && !exists) throw mechanismError(HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED, "replacement target does not exist", { input: relPath, phase: "pre-commit", publicationState: "not-published" });
    return { targetPath: lexical, directory, targetStats: exists ? await lstat(lexical) : null,
      windowsExpectation: { parent, target: exists ? actual : null } };
  }
  const relative = path.relative(rootReal, lexical);
  const segments = relative.split(path.sep);
  let cursor = rootReal;
  for (let index = 0; index < segments.length - 1; index += 1) {
    cursor = path.join(cursor, segments[index]);
    let stats;
    try {
      stats = await lstat(cursor);
    } catch (cause) {
      if (createParents && cause?.code === "ENOENT") {
        await createParentDirectory(cursor, relPath);
        continue;
      }
      throw mechanismError(
        HARNESS_ERROR_KINDS.INVALID_ROOT,
        "strict file operation requires every parent directory to exist",
        { input: relPath, code: cause?.code },
      );
    }
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
        "strict file operation requires real intermediate directories",
        { input: relPath },
      );
    }
  }
  let stats = null;
  try {
    stats = await lstat(lexical);
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
  }
  if (stats?.isSymbolicLink()) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      "strict file operation refuses a symbolic-link target",
      { input: relPath },
    );
  }
  if (target === "absent" && stats !== null) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLISH_CONFLICT,
      "exclusive publication target already exists",
      { input: relPath, publicationState: "not-published" },
    );
  }
  let targetFingerprint = null;
  if (target === "regular") {
    if (stats === null || !stats.isFile() || stats.nlink !== 1) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
        "atomic replacement requires one existing ordinary file",
        { input: relPath, publicationState: "not-published" },
      );
    }
    targetFingerprint = await snapshotRegularTarget(lexical, stats);
    if (targetFingerprint === null) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
        "atomic replacement target changed during initial inspection",
        { input: relPath, publicationState: "not-published" },
      );
    }
  }
  if (target === "regular-or-absent") {
    if (stats !== null && (!stats.isFile() || stats.nlink !== 1)) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
        "atomic publication requires an absent target or one existing ordinary file",
        { input: relPath, publicationState: "not-published" },
      );
    }
    if (stats !== null) {
      targetFingerprint = await snapshotRegularTarget(lexical, stats);
      if (targetFingerprint === null) {
        throw mechanismError(
          HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
          "atomic publication target changed during initial inspection",
          { input: relPath, publicationState: "not-published" },
        );
      }
    }
  }
  const directory = path.dirname(lexical);
  const directoryStats = await lstat(directory);
  if (directoryStats.isSymbolicLink() || !directoryStats.isDirectory()) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      "strict file operation requires a real parent directory",
      { input: relPath },
    );
  }
  return {
    targetPath: lexical,
    targetStats: stats,
    targetFingerprint,
    directory,
    directoryStats,
    directoryReal: await realpath(directory),
  };
}

async function revalidateDirectory(directory, expectedStats, expectedReal, relPath) {
  const current = await lstat(directory);
  const currentMode = current.mode & 0o777;
  const expectedMode = expectedStats.mode & 0o777;
  if (
    current.isSymbolicLink() ||
    !current.isDirectory() ||
    !sameIdentity(current, expectedStats) ||
    currentMode !== expectedMode ||
    (await realpath(directory)) !== expectedReal
  ) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      "strict file operation parent identity or mode changed before commit",
      { input: relPath },
    );
  }
}

async function writeFresh(file, data, mode) {
  const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  const handle = await open(
    file,
    FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | noFollow,
    mode,
  );
  try {
    await handle.writeFile(data);
    await syncForDurability(file);
    const stats = await handle.stat();
    if (!stats.isFile() || stats.nlink !== 1) throw new Error("staging entry is not one ordinary file");
    return stats;
  } finally {
    await handle.close();
  }
}

async function syncDirectoryStrict(directory) {
  await syncForDurability(directory, { directory: true });
}

async function inspectPublished(target, expectedBytes, expectedMode) {
  const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  const before = await lstat(target);
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) return null;
  const handle = await open(target, FS_CONSTANTS.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat();
    if (!sameIdentity(before, opened) || !opened.isFile() || opened.nlink !== 1) return null;
    const actual = await handle.readFile();
    if (!actual.equals(expectedBytes) || (opened.mode & 0o777) !== expectedMode) return null;
    return opened;
  } finally {
    await handle.close();
  }
}

function strictFailure(kind, operation, cause, relPath, committed, verified) {
  return mechanismError(
    kind,
    `${operation} failed: ${cause?.code ?? cause?.message ?? "unknown"}`,
    {
      input: relPath,
      phase: committed ? "post-commit" : "pre-commit",
      publicationState: committed ? (verified ? "published" : "indeterminate") : "not-published",
    },
  );
}

/**
 * Creates one file without replacing any existing directory entry. Every
 * parent must be a real directory and contain no symlink components; with
 * `createParents` enabled, the missing portion of the parent chain is created
 * as real directories (any symlink component is still refused). The returned
 * receipt is emitted only after byte/mode/identity verification and directory
 * fsync have completed.
 */
export async function publishFileExclusive(
  root,
  relPath,
  data,
  options = {},
) {
  if (process.platform === "win32") return publishWindowsFile("exclusive", root, relPath, data, options);
  assertWritableData(data, "publishFileExclusive");
  const mode = posixPublicationMode(options);
  const createParents = options.createParents === true;
  const normalizedMode = normalizeMode(mode);
  const bytes = bytesOf(data);
  const { targetPath, directory, directoryStats, directoryReal } = await strictTarget(root, relPath, {
    target: "absent",
    createParents,
  });
  const staging = path.join(
    directory,
    `.${path.basename(targetPath)}.${process.pid}.${randomBytes(12).toString("hex")}.publish`,
  );
  let committed = false;
  let verified = false;
  try {
    await writeFresh(staging, bytes, normalizedMode);
    await runTestHook("beforeExclusiveCommit", { targetPath, staging, directory });
    await revalidateDirectory(directory, directoryStats, directoryReal, relPath);
    await link(staging, targetPath);
    committed = true;
    await runTestHook("afterExclusiveCommit", { targetPath, staging });
    await unlink(staging);
    const published = await inspectPublished(targetPath, bytes, normalizedMode);
    if (published === null) throw new Error("published target failed identity, byte, or mode verification");
    verified = true;
    await runTestHook("beforeExclusiveDirectorySync", { targetPath, directory });
    await syncDirectoryStrict(directory);
    return Object.freeze({
      path: targetPath,
      publicationState: "published",
      sha256: digest(bytes),
      bytes: bytes.length,
      mode: normalizedMode,
    });
  } catch (cause) {
    if (!committed && cause?.code === "EEXIST") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLISH_CONFLICT,
        "exclusive publication target already exists",
        { input: relPath, phase: "pre-commit", publicationState: "not-published" },
      );
    }
    throw strictFailure(
      HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLICATION_FAILED,
      "exclusive publication",
      cause,
      relPath,
      committed,
      verified,
    );
  } finally {
    await unlink(staging).catch(() => {});
  }
}

/**
 * Atomically replaces one existing ordinary file. Unlike `writeFileAtomic`,
 * success is reported only after the committed target is re-opened without
 * symlink following, verified byte-for-byte and by mode, and its directory is
 * fsynced. A post-rename failure carries an explicit published/indeterminate
 * publicationState and never claims rollback.
 */
export async function replaceFileAtomic(root, relPath, data, options = {}) {
  if (process.platform === "win32") return publishWindowsFile("replace", root, relPath, data, options);
  const mode = posixPublicationMode(options);
  assertWritableData(data, "replaceFileAtomic");
  const normalizedMode = normalizeMode(mode);
  const bytes = bytesOf(data);
  const { targetPath, targetStats, targetFingerprint, directory, directoryStats, directoryReal } = await strictTarget(
    root,
    relPath,
    { target: "regular" },
  );
  const staging = path.join(
    directory,
    `.${path.basename(targetPath)}.${process.pid}.${randomBytes(12).toString("hex")}.replace`,
  );
  let committed = false;
  let verified = false;
  try {
    await writeFresh(staging, bytes, normalizedMode);
    await runTestHook("beforeReplaceCommit", { targetPath, staging, directory });
    await revalidateDirectory(directory, directoryStats, directoryReal, relPath);
    const current = await snapshotRegularTarget(targetPath, targetStats);
    if (
      current === null ||
      current.mode !== targetFingerprint.mode ||
      current.bytes !== targetFingerprint.bytes ||
      current.sha256 !== targetFingerprint.sha256
    ) {
      throw new Error("replacement target changed before commit");
    }
    await rename(staging, targetPath);
    committed = true;
    await runTestHook("afterReplaceCommit", { targetPath });
    const published = await inspectPublished(targetPath, bytes, normalizedMode);
    if (published === null) throw new Error("replaced target failed identity, byte, or mode verification");
    verified = true;
    await runTestHook("beforeReplaceDirectorySync", { targetPath, directory });
    await syncDirectoryStrict(directory);
    return Object.freeze({
      path: targetPath,
      publicationState: "published",
      sha256: digest(bytes),
      bytes: bytes.length,
      mode: normalizedMode,
    });
  } catch (cause) {
    throw strictFailure(
      HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
      "atomic replacement",
      cause,
      relPath,
      committed,
      verified,
    );
  } finally {
    await unlink(staging).catch(() => {});
  }
}

/**
 * Strictly publishes one ordinary file, creating it when absent and replacing
 * it when already present, in a single no-follow operation. Symlinks and
 * directories are refused, every parent must already exist, and the target
 * fingerprint (when present) is re-verified immediately before commit.
 */
export async function publishFileOrReplace(root, relPath, data, options = {}) {
  if (process.platform === "win32") return publishWindowsFile("or-replace", root, relPath, data, options);
  const mode = posixPublicationMode(options);
  assertWritableData(data, "publishFileOrReplace");
  const normalizedMode = normalizeMode(mode);
  const bytes = bytesOf(data);
  const { targetPath, targetStats, targetFingerprint, directory, directoryStats, directoryReal } = await strictTarget(
    root,
    relPath,
    { target: "regular-or-absent" },
  );
  const staging = path.join(
    directory,
    `.${path.basename(targetPath)}.${process.pid}.${randomBytes(12).toString("hex")}.publish-or-replace`,
  );
  let committed = false;
  let verified = false;
  try {
    await writeFresh(staging, bytes, normalizedMode);
    await runTestHook("beforePublishOrReplaceCommit", { targetPath, staging, directory });
    await revalidateDirectory(directory, directoryStats, directoryReal, relPath);
    if (targetFingerprint !== null) {
      const current = await snapshotRegularTarget(targetPath, targetStats);
      if (
        current === null ||
        current.mode !== targetFingerprint.mode ||
        current.bytes !== targetFingerprint.bytes ||
        current.sha256 !== targetFingerprint.sha256
      ) {
        throw new Error("publication target changed before commit");
      }
    }
    await rename(staging, targetPath);
    committed = true;
    await runTestHook("afterPublishOrReplaceCommit", { targetPath });
    const published = await inspectPublished(targetPath, bytes, normalizedMode);
    if (published === null) throw new Error("published target failed identity, byte, or mode verification");
    verified = true;
    await runTestHook("beforePublishOrReplaceDirectorySync", { targetPath, directory });
    await syncDirectoryStrict(directory);
    return Object.freeze({
      path: targetPath,
      publicationState: "published",
      sha256: digest(bytes),
      bytes: bytes.length,
      mode: normalizedMode,
    });
  } catch (cause) {
    throw strictFailure(
      HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
      "atomic publication",
      cause,
      relPath,
      committed,
      verified,
    );
  } finally {
    await unlink(staging).catch(() => {});
  }
}

/** Test-only hooks. Deliberately not re-exported from the package index. */
export function __setAtomicTestHooks(hooks) {
  if (hooks !== null && (!hooks || typeof hooks !== "object" || Array.isArray(hooks))) {
    throw new TypeError("atomic test hooks must be an object or null");
  }
  testHooks = hooks;
}

/** Compatibility writer; see the module-level guarantee boundary above. */
export async function writeFileAtomic(root, relPath, data, { mode = 0o644 } = {}) {
  assertWritableData(data, "writeFileAtomic");
  let target = await resolveContained(root, relPath);
  try {
    const finalStat = await lstat(target);
    if (finalStat.isSymbolicLink()) target = await realpath(target);
  } catch {
    // Not yet existing: the lexical target is the write destination.
  }
  const dir = path.dirname(target);
  try {
    await mkdir(dir, { recursive: true });
  } catch (cause) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.ATOMIC_WRITE_FAILED,
      `cannot prepare contained directory: ${cause?.code ?? "unknown"}`,
      { input: relPath },
    );
  }
  const tmpPath = path.join(
    dir,
    `.${path.basename(target)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
  );
  let handle = null;
  let phase = "temporary-open";
  try {
    handle = await open(tmpPath, "wx", mode);
    phase = "temporary-write";
    await handle.writeFile(data);
    phase = "temporary-flush";
    await syncForDurability(tmpPath);
    phase = "temporary-close";
    await handle.close();
    handle = null;
    phase = "rename";
    if (process.platform === "win32") {
      const { addon } = await loadWindowsNativeAddon();
      const moved = addon.replaceExistingFile(tmpPath, target);
      // This compatibility API permits another writer to replace our complete
      // version immediately. A completed native rename is enough; it does not
      // claim the strict API's post-commit verification or durable namespace.
      if (moved?.ok !== true && moved?.committed !== true) {
        const error = new Error(moved?.failureReason ?? "native-rename-failed");
        error.code = "EIO";
        throw error;
      }
    } else await rename(tmpPath, target);
  } catch (cause) {
    if (handle) await handle.close().catch(() => {});
    await removeQuiet(tmpPath);
    throw mechanismError(
      HARNESS_ERROR_KINDS.ATOMIC_WRITE_FAILED,
      `atomic write failed during ${phase}: ${cause?.code ?? "unknown"}`,
      { input: relPath },
    );
  }
  try {
    await syncForDurability(dir, { directory: true });
  } catch {
    // Compatibility API intentionally does not claim durable directory sync.
  }
  return target;
}


function assertPreparedRelative(value, { material = false } = {}) {
  if (typeof value !== "string" || value.includes("\\") || value.normalize("NFC") !== value ||
      canonicalizeWindowsDriveAbsolute(`C:/${value}`) !== `C:/${value}` || value.split("/").length > 256 ||
      value.split("/").some(segment => segment.toLowerCase() === ".git" || (!material && segment.toLowerCase() === ".foundation-file-apply"))) {
    throw new TypeError("prepared paths must satisfy the file-set relative path contract");
  }
  return value;
}

function assertPreparedRoot(root, rootBinding) {
  const canonical = canonicalizeWindowsDriveAbsolute(root);
  if (canonical === null || !rootBinding || Object.keys(rootBinding).sort().join(",") !== "basis,digest,digestAlgorithm,kind" ||
      rootBinding.kind !== "trusted-filesystem-root-binding" || rootBinding.digestAlgorithm !== "sha256" ||
      rootBinding.basis !== "canonical-finalpath-volume-fileid-type-security-v1" || !/^[0-9a-f]{64}$/u.test(rootBinding.digest)) {
    throw new TypeError("directory preparation requires a Windows root and its original rootBinding");
  }
  if (process.platform !== "win32") throw mechanismError(HARNESS_ERROR_KINDS.UNSUPPORTED_PLATFORM, "directory preparation requires Windows/NTFS");
  return canonical;
}

async function capturePreparedRoot(root, rootBinding) {
  const { addon } = await loadWindowsNativeAddon();
  const fact = addon.captureSecurity(root);
  if (!fact?.ok || fact.filesystem !== "NTFS" || (fact.attributes & 0x410) !== 0x10 || !Buffer.isBuffer(fact.securityDescriptor) ||
      digestDocument({ canonicalFinalPath: fact.canonicalPath, volumeSerial: fact.volumeSerial, fileId: fact.fileId,
        type: "directory", securityDigest: createHash("sha256").update(fact.securityDescriptor).digest("hex") }) !== rootBinding.digest) {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "the original directory root binding no longer matches");
  }
  return { addon, fact };
}

function preparedRecord(rel, native) {
  if ((native?.attributes & 0x410) !== 0x10 || !Buffer.isBuffer(native?.securityDescriptor) || !/^[0-9a-f]{16}$/u.test(native.volumeSerial) || !/^[0-9a-f]{32}$/u.test(native.fileId)) return null;
  return { path: rel, volumeSerial: native.volumeSerial, fileId: native.fileId, permissionObservation: {
    kind: "windows-security-v1", attributes: native.attributes >>> 0,
    securityDigest: createHash("sha256").update(native.securityDescriptor).digest("hex"),
  } };
}

function preparationError(cause) {
  return { kind: Object.values(HARNESS_ERROR_KINDS).includes(cause?.details?.kind) ? cause.details.kind : HARNESS_ERROR_KINDS.ATOMIC_WRITE_FAILED,
    message: cause?.message ?? String(cause) };
}

async function prepareDirectories(root, rootBinding, directories, privateMaterial) {
  const result = { status: "succeeded", created: [], existing: [], unconfirmed: [], error: null };
  try {
    const { addon, fact } = await capturePreparedRoot(root, rootBinding);
    const approvedParents = new Map();
    for (const rel of directories) {
      const parts = rel.split("/");
      const ancestors = parts.slice(0, -1).map((_, index) => approvedParents.get(parts.slice(0, index + 1).join("/")) ?? null);
      const native = addon.mutatePreparedDirectory(fact.canonicalPath, parts, fact, privateMaterial ? "create-private" : "create-inherited", null, ancestors);
      const record = preparedRecord(rel, native);
      if (native?.created && (!record || native.unconfirmed)) result.unconfirmed.push(rel);
      else if (native?.created) result.created.push(record);
      else if (native?.existing && record) result.existing.push(record);
      if (record) approvedParents.set(rel, native);
      if (!native?.ok || (privateMaterial && (!record || native.currentUserOwner !== true ||
          !acceptProtectedMaterialDirectory(windowsSecurityDisposition(native.securityDescriptor)).accepted))) {
        result.status = result.unconfirmed.length ? "indeterminate" : "failed";
        result.error = { kind: HARNESS_ERROR_KINDS.ATOMIC_WRITE_FAILED, message: `directory preparation rejected ${rel}: ${native?.failureReason ?? "private-security-mismatch"}` };
        break;
      }
    }
  } catch (cause) {
    result.status = result.unconfirmed.length ? "indeterminate" : "failed";
    result.error = preparationError(cause);
  }
  return result;
}

export async function prepareFileSetParents({ root, rootBinding, paths } = {}) {
  root = assertPreparedRoot(root, rootBinding);
  if (!Array.isArray(paths) || paths.length === 0 || paths.length > 1024) throw new TypeError("paths must contain 1..1024 authorized file paths");
  const logical = new Set();
  const directories = new Map();
  for (const rel of paths) {
    assertPreparedRelative(rel);
    const key = rel.toLowerCase();
    if (logical.has(key)) throw new TypeError("file-set paths contain logical aliases");
    logical.add(key);
    const parts = rel.split("/");
    for (let index = 1; index < parts.length; index += 1) {
      const parent = parts.slice(0, index).join("/");
      const folded = parent.toLowerCase();
      if (directories.has(folded) && directories.get(folded) !== parent) throw new TypeError("file-set parents contain logical aliases");
      directories.set(folded, parent);
    }
  }
  if ([...logical].some(file => directories.has(file))) throw new TypeError("a file-set file path is another file's ancestor");
  return prepareDirectories(root, rootBinding, [...directories.values()].sort((a, b) => a.split("/").length - b.split("/").length || (a < b ? -1 : a > b ? 1 : 0)), false);
}

export async function createPrivateMaterialDirectory(root, relPath, { rootBinding } = {}) {
  root = assertPreparedRoot(root, rootBinding);
  assertPreparedRelative(relPath, { material: true });
  if (relPath.includes("/")) throw new TypeError("private material directory must be one direct child");
  return prepareDirectories(root, rootBinding, [relPath], true);
}

export async function removePreparedFileSetParents({ root, rootBinding, directories } = {}) {
  root = assertPreparedRoot(root, rootBinding);
  if (!Array.isArray(directories) || directories.length > 262144) throw new TypeError("directories must be the same-call preparation records");
  const seen = new Set();
  for (const record of directories) {
    if (!record || Object.keys(record).sort().join(",") !== "fileId,path,permissionObservation,volumeSerial" ||
        !/^[0-9a-f]{16}$/u.test(record.volumeSerial) || !/^[0-9a-f]{32}$/u.test(record.fileId)) throw new TypeError("invalid prepared directory record");
    assertPreparedRelative(record.path);
    const observation = record.permissionObservation;
    if (!observation || Object.keys(observation).sort().join(",") !== "attributes,kind,securityDigest" || observation.kind !== "windows-security-v1" ||
        !Number.isInteger(observation.attributes) || observation.attributes < 0 || observation.attributes > 0xFFFFFFFF ||
        !/^[0-9a-f]{64}$/u.test(observation.securityDigest) || seen.has(record.path.toLowerCase())) throw new TypeError("invalid prepared permission or duplicate directory");
    seen.add(record.path.toLowerCase());
  }
  const result = { status: "succeeded", entries: [], error: null };
  let stopped = null;
  const prepared = new Map(directories.map(record => [record.path, record]));
  for (const record of [...directories].sort((a, b) => b.path.split("/").length - a.path.split("/").length || (a.path < b.path ? 1 : a.path > b.path ? -1 : 0))) {
    if (stopped) { result.entries.push({ path: record.path, status: "retained", error: stopped }); continue; }
    try {
      const { addon, fact } = await capturePreparedRoot(root, rootBinding);
      const observed = addon.captureSecurity(`${fact.canonicalPath.replace(/\/$/u, "")}/${record.path}`);
      const actual = preparedRecord(record.path, observed);
      if (observed?.ok && digestDocument(actual) !== digestDocument(record)) {
        throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `prepared directory ${record.path} was replaced or changed`);
      }
      const parts = record.path.split("/");
      const ancestors = parts.slice(0, -1).map((_, index) => {
        const rel = parts.slice(0, index + 1).join("/");
        const expected = prepared.get(rel);
        if (!expected) return null;
        const captured = addon.captureSecurity(`${fact.canonicalPath.replace(/\/$/u, "")}/${rel}`);
        const current = preparedRecord(rel, captured);
        if (!captured?.ok && captured?.failureReason === "member-missing") return {};
        if (!captured?.ok || digestDocument(current) !== digestDocument(expected)) throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `prepared ancestor ${rel} was replaced or changed`);
        return captured;
      });
      const native = addon.mutatePreparedDirectory(fact.canonicalPath, parts, fact, "remove-created", observed?.ok ? observed : {}, ancestors);
      const error = native?.ok ? null : { kind: HARNESS_ERROR_KINDS.WORKSPACE_DISPOSE_FAILED, message: `directory removal rejected ${record.path}: ${native?.failureReason ?? "native-io"}` };
      const status = native?.removed ? "removed" : native?.unconfirmed ? "indeterminate" : native?.alreadyAbsent ? "already-absent" : "retained";
      result.entries.push({ path: record.path, status, error });
      if (error) {
        if (status === "indeterminate" && result.status !== "indeterminate") { result.status = "indeterminate"; result.error = error; }
        else if (result.status === "succeeded") { result.status = "failed"; result.error = error; }
        if (["root-changed", "invalid-root", "directory-changed", "unsafe-directory"].includes(native?.failureReason)) stopped = error;
      }
    } catch (cause) {
      const error = preparationError(cause);
      result.entries.push({ path: record.path, status: "retained", error });
      if (result.status === "succeeded") { result.status = "failed"; result.error = error; }
      stopped = error;
    }
  }
  return result;
}
