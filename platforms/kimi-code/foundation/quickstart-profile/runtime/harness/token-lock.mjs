import { createHash, randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open, realpath, unlink } from "node:fs/promises";
import path from "node:path";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { publishFileExclusive } from "./atomic.mjs";
import { resolveContained } from "./paths.mjs";

const TOKEN_PATTERN = /^[0-9a-f]{64}$/;

function tokenDigest(token) {
  return createHash("sha256").update(token).digest("hex");
}

function assertOwner(owner) {
  if (typeof owner !== "string" || owner.length === 0 || owner.length > 200) {
    throw new TypeError("filesystem lock owner must be a non-empty string of at most 200 characters");
  }
}

async function targetPath(root, relPath) {
  const target = await resolveContained(root, relPath);
  const rootReal = await realpath(root);
  const relative = path.relative(rootReal, target);
  let cursor = rootReal;
  for (const segment of relative.split(path.sep).slice(0, -1)) {
    cursor = path.join(cursor, segment);
    const stats = await lstat(cursor);
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "filesystem lock parent must be a real directory");
    }
  }
  return target;
}

function parseRecord(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw mechanismError(HARNESS_ERROR_KINDS.LOCK_CORRUPT, "filesystem lock record is not valid JSON");
  }
  if (
    !value || value.schemaVersion !== 1 || typeof value.owner !== "string" || value.owner.length === 0 ||
    typeof value.tokenDigest !== "string" || !TOKEN_PATTERN.test(value.tokenDigest) ||
    typeof value.acquiredAt !== "string" || !Number.isFinite(Date.parse(value.acquiredAt)) ||
    Object.keys(value).sort().join(",") !== "acquiredAt,owner,schemaVersion,tokenDigest"
  ) {
    throw mechanismError(HARNESS_ERROR_KINDS.LOCK_CORRUPT, "filesystem lock record is malformed");
  }
  return value;
}

async function readRecord(target, { optional = false } = {}) {
  let before;
  try {
    before = await lstat(target);
  } catch (cause) {
    if (optional && cause?.code === "ENOENT") return null;
    throw cause;
  }
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) {
    throw mechanismError(HARNESS_ERROR_KINDS.LOCK_CORRUPT, "filesystem lock must be one ordinary file");
  }
  const handle = await open(target, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1) {
      throw mechanismError(HARNESS_ERROR_KINDS.LOCK_CORRUPT, "filesystem lock changed during inspection");
    }
    return { record: parseRecord(await handle.readFile("utf8")), stats: opened };
  } finally {
    await handle.close();
  }
}

async function syncParent(target) {
  const handle = await open(path.dirname(target), FS_CONSTANTS.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function unlinkSame(target, stats) {
  const current = await lstat(target);
  if (current.isSymbolicLink() || !current.isFile() || current.nlink !== 1 ||
      current.dev !== stats.dev || current.ino !== stats.ino) {
    throw mechanismError(HARNESS_ERROR_KINDS.STORE_LOCKED, "filesystem lock identity changed before release");
  }
  await unlink(target);
  try {
    await syncParent(target);
  } catch (cause) {
    throw mechanismError(HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLICATION_FAILED, "filesystem lock was removed but directory sync failed", {
      phase: "post-commit",
      publicationState: "published",
      code: cause?.code,
    });
  }
}

/** Nonblocking acquisition: one exclusive create attempt, never a retry. */
export async function acquireFilesystemLock(root, relPath, { owner } = {}) {
  assertOwner(owner);
  const token = randomBytes(32).toString("hex");
  const record = {
    schemaVersion: 1,
    owner,
    tokenDigest: tokenDigest(token),
    acquiredAt: new Date().toISOString(),
  };
  let receipt;
  try {
    receipt = await publishFileExclusive(root, relPath, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  } catch (cause) {
    if (cause?.details?.kind === HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLISH_CONFLICT) {
      throw mechanismError(HARNESS_ERROR_KINDS.STORE_LOCKED, "filesystem lock is already held");
    }
    throw cause;
  }
  const target = await targetPath(root, relPath);
  const observed = await readRecord(target);
  return Object.freeze({
    root: await realpath(root),
    path: relPath,
    token,
    tokenDigest: record.tokenDigest,
    owner,
    acquiredAt: record.acquiredAt,
    identity: Object.freeze({ device: String(observed.stats.dev), inode: String(observed.stats.ino) }),
    publication: receipt,
  });
}

export async function inspectFilesystemLock(root, relPath) {
  const target = await targetPath(root, relPath);
  const observed = await readRecord(target, { optional: true });
  if (observed === null) return Object.freeze({ locked: false });
  return Object.freeze({
    locked: true,
    owner: observed.record.owner,
    tokenDigest: observed.record.tokenDigest,
    acquiredAt: observed.record.acquiredAt,
    identity: Object.freeze({ device: String(observed.stats.dev), inode: String(observed.stats.ino) }),
  });
}

export async function releaseFilesystemLock(handle) {
  if (!handle || typeof handle !== "object" || typeof handle.root !== "string" ||
      typeof handle.path !== "string" || typeof handle.token !== "string" || !TOKEN_PATTERN.test(handle.token)) {
    throw new TypeError("releaseFilesystemLock requires an acquired filesystem lock handle");
  }
  const target = await targetPath(handle.root, handle.path);
  const observed = await readRecord(target);
  if (observed.record.tokenDigest !== tokenDigest(handle.token) ||
      String(observed.stats.dev) !== handle.identity?.device || String(observed.stats.ino) !== handle.identity?.inode) {
    throw mechanismError(HARNESS_ERROR_KINDS.STORE_LOCKED, "filesystem lock token or identity does not match");
  }
  await unlinkSame(target, observed.stats);
  return Object.freeze({ released: true, tokenDigest: observed.record.tokenDigest });
}

/** Explicit operator recovery. No age, retry, PID, or liveness inference. */
export async function recoverFilesystemLock(root, relPath, { expectedTokenDigest, confirmAbandoned } = {}) {
  if (confirmAbandoned !== true) {
    throw mechanismError(HARNESS_ERROR_KINDS.LOCK_RECOVERY_REFUSED, "manual recovery requires confirmAbandoned=true");
  }
  if (typeof expectedTokenDigest !== "string" || !TOKEN_PATTERN.test(expectedTokenDigest)) {
    throw new TypeError("manual recovery requires the inspected tokenDigest");
  }
  const target = await targetPath(root, relPath);
  const observed = await readRecord(target);
  if (observed.record.tokenDigest !== expectedTokenDigest) {
    throw mechanismError(HARNESS_ERROR_KINDS.LOCK_RECOVERY_REFUSED, "filesystem lock changed after inspection");
  }
  await unlinkSame(target, observed.stats);
  return Object.freeze({ recovered: true, tokenDigest: expectedTokenDigest });
}
