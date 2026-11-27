// @feature FND-FR-017
// @decision FND-ADR-026
// @design FND-DES-021
import { createHash } from "node:crypto";
import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open, readdir, realpath, rename, unlink } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { canonicalJson, digestDocument } from "../contracts/index.mjs";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { publishFileExclusive, replaceFileAtomic, syncForDurability } from "./atomic.mjs";
import { readFileBound } from "./bound-read.mjs";
import { loadNativeAddon, loadWindowsNativeAddon, stableNativePlatformKey } from "./fixed-set-publication-loader.mjs";
import { canonicalizeWindowsDriveAbsolute } from "./paths.mjs";

const MANIFEST_KIND = "skill-family.fixed-set-publication-manifest";
const RECEIPT_KIND = "skill-family.fixed-set-publication-receipt";
const ZERO_DIGEST = "0".repeat(64);
const SEGMENT = /^[A-Za-z0-9._-]+$/u;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function primitive(platform) {
  if (platform === "darwin") return "darwin-renameatx-noreplace-v1";
  if (platform === "linux") return "linux-renameat2-noreplace-v1";
  if (platform === "win32") return "windows-rename-noreplace-v1";
  return "none";
}

function rootBindingDigest(canonicalRealpath, identity) {
  return digestDocument({
    canonicalRealpath,
    device: identity.device,
    inode: identity.inode,
    mode: identity.mode,
    type: "directory",
  });
}

function rootBinding(canonicalRealpath, identity) {
  return {
    kind: "trusted-filesystem-root-binding",
    digestAlgorithm: "sha256",
    basis: "canonical-realpath-device-inode-type-mode-v1",
    digest: rootBindingDigest(canonicalRealpath, identity),
  };
}

function directoryIdentity(stats) {
  return {
    type: "directory",
    mode: Number(stats.mode & 0o777n),
    device: String(stats.dev),
    inode: String(stats.ino),
  };
}

function assertNormalizedAbsolutePath(input, label) {
  if (typeof input !== "string" || !path.isAbsolute(input) || input.includes("\0") || path.normalize(input) !== input) {
    throw new TypeError(`${label} must be a normalized absolute path`);
  }
  return input;
}

async function canonicalWindowsDirectory(input, label) {
  const canonical = canonicalizeWindowsDriveAbsolute(input);
  if (canonical === null) throw new TypeError(`${label} must be a canonical Windows drive path`);
  const loaded = await loadWindowsNativeAddon();
  const captured = loaded.addon.captureSecurity(canonical);
  const finalPath = canonicalizeWindowsDriveAbsolute(captured?.canonicalPath);
  const attributes = Number(captured?.attributes) >>> 0;
  if (!captured?.ok || finalPath === null || finalPath !== canonical || (attributes & 0x400) !== 0 || (attributes & 0x10) === 0 ||
      !Buffer.isBuffer(captured.securityDescriptor) || !/^[0-9a-f]{16}$/u.test(captured.volumeSerial ?? "") ||
      !/^[0-9a-f]{32}$/u.test(captured.fileId ?? "")) {
    throw new TypeError(`${label} must be a real directory`);
  }
  const securityDigest = sha256(Buffer.from(captured.securityDescriptor));
  return {
    path: canonical,
    stats: { dev: captured.volumeSerial, ino: captured.fileId, mode: 0n },
    identity: {
      type: "directory",
      volumeSerial: captured.volumeSerial,
      fileId: captured.fileId,
      permissionObservation: {
        kind: "windows-security-v1",
        attributes,
        securityDigest,
      },
    },
    binding: {
      kind: "trusted-filesystem-root-binding",
      digestAlgorithm: "sha256",
      basis: "canonical-finalpath-volume-fileid-type-security-v1",
      digest: digestDocument({
        canonicalFinalPath: canonical,
        volumeSerial: captured.volumeSerial,
        fileId: captured.fileId,
        type: "directory",
        securityDigest,
      }),
    },
  };
}

async function canonicalDirectory(input, label) {
  if (process.platform === "win32") return canonicalWindowsDirectory(input, label);
  assertNormalizedAbsolutePath(input, label);
  const before = await lstat(input, { bigint: true });
  if (before.isSymbolicLink() || !before.isDirectory()) throw new TypeError(`${label} must be a real directory`);
  const canonical = await realpath(input);
  if (canonical !== input) throw new TypeError(`${label} must already be its canonical realpath`);
  const after = await lstat(canonical, { bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode) {
    throw new Error(`${label} identity changed during resolution`);
  }
  return { path: canonical, stats: after, identity: directoryIdentity(after) };
}

function assertSegment(value, label) {
  if (typeof value !== "string" || !SEGMENT.test(value) || value === "." || value === "..") {
    throw new TypeError(`${label} must be one safe path segment`);
  }
  return value;
}

async function scanDirectory(root, { requireMember = true, expectedDevice, approvedBinding } = {}) {
  if (FS_CONSTANTS.O_NOFOLLOW === undefined) throw new Error("O_NOFOLLOW is required");
  const directories = [];
  const members = [];
  async function walk(relative) {
    const absolute = relative === "" ? root : path.join(root, ...relative.split("/"));
    const names = (await readdir(absolute)).sort();
    for (const name of names) {
      assertSegment(name, "filesystem member name");
      const relPath = relative === "" ? name : `${relative}/${name}`;
      const absPath = path.join(root, ...relPath.split("/"));
      const before = await lstat(absPath, { bigint: true });
      if (expectedDevice !== undefined && before.dev !== expectedDevice) throw new Error(`generation member is on another device: ${relPath}`);
      if (before.isSymbolicLink()) throw new TypeError(`fixed-set member must not be a symlink: ${relPath}`);
      if (before.isDirectory()) {
        directories.push({ path: relPath, ...directoryIdentity(before) });
        if (expectedDevice === undefined) await walk(relPath);
        else {
          const handle = await open(absPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_DIRECTORY | FS_CONSTANTS.O_NOFOLLOW);
          try {
            const opened = await handle.stat({ bigint: true });
            if (!opened.isDirectory() || !sameIdentity(directoryIdentity(before), directoryIdentity(opened)) || opened.dev !== expectedDevice) throw new Error(`generation directory changed: ${relPath}`);
            await walk(relPath);
            const after = await lstat(absPath, { bigint: true });
            if (!sameIdentity(directoryIdentity(opened), directoryIdentity(after))) throw new Error(`generation directory changed: ${relPath}`);
          } finally { await handle.close(); }
        }
      } else if (before.isFile() && before.nlink === 1n) {
        const handle = await open(absPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW);
        try {
          const opened = await handle.stat({ bigint: true });
          if ((expectedDevice !== undefined && opened.dev !== expectedDevice) || opened.dev !== before.dev || opened.ino !== before.ino || opened.mode !== before.mode || opened.nlink !== 1n) {
            throw new Error(`fixed-set member changed during open: ${relPath}`);
          }
          const bytes = approvedBinding === undefined ? await handle.readFile()
            : Buffer.from((await readFileBound(root, relPath, { rootBinding: approvedBinding })).content);
          if (approvedBinding !== undefined) {
            const after = await lstat(absPath, { bigint: true });
            if (!after.isFile() || after.dev !== expectedDevice || after.dev !== opened.dev || after.ino !== opened.ino || after.mode !== opened.mode || after.nlink !== 1n) throw new Error(`generation file changed: ${relPath}`);
          }
          members.push({
            path: relPath,
            type: "regular",
            mode: Number(opened.mode & 0o777n),
            bytes: bytes.length,
            sha256: sha256(bytes),
          });
        } finally {
          await handle.close();
        }
      } else {
        throw new TypeError(`fixed-set member must be an ordinary file or directory: ${relPath}`);
      }
    }
  }
  await walk("");
  if (requireMember && members.length === 0) throw new TypeError("fixed-set source must contain at least one regular file");
  return { directories, members };
}

async function describeWindowsSource(sourceRoot, { expectedRoot } = {}) {
  const root = await canonicalWindowsDirectory(sourceRoot, "sourceRoot");
  if (expectedRoot && root.binding.digest !== expectedRoot.binding.digest) throw new Error("generation root changed before observation");
  const loaded = await loadWindowsNativeAddon();
  const captured = loaded.addon.observeFilesystemTreeNative(root.path, false);
  if (!captured?.ok || !Array.isArray(captured.members)) throw new Error("fixed-set bound tree could not be observed");
  const rootFact = captured.root;
  if (rootFact.fileId !== root.identity.fileId || rootFact.volumeSerial !== root.identity.volumeSerial ||
      rootFact.attributes !== root.identity.permissionObservation.attributes || sha256(Buffer.from(rootFact.securityDescriptor)) !== root.identity.permissionObservation.securityDigest) {
    throw new Error("fixed-set root changed during observation");
  }
  const directories = [], members = [];
  for (const item of captured.members.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)) {
    if (expectedRoot && item.volumeSerial !== expectedRoot.identity.volumeSerial) throw new Error("generation member is on another volume");
    const permissionObservation = { kind: "windows-security-v1", attributes: item.attributes,
      securityDigest: sha256(Buffer.from(item.securityDescriptor)) };
    if (item.type === "directory") directories.push({ path: item.path, type: "directory",
      volumeSerial: item.volumeSerial, fileId: item.fileId, permissionObservation });
    else if (item.type === "file") {
      const bytes = Buffer.from(item.bytes);
      members.push({ path: item.path, type: "regular", permissionObservation, bytes: bytes.length, sha256: sha256(bytes) });
    } else throw new Error("fixed-set source contains a non-ordinary member");
  }
  if (members.length === 0) throw new TypeError("fixed-set source must contain at least one regular file");
  const source = { rootBinding: root.binding, root: root.identity, directories,
    closureDigest: digestDocument({ root: root.identity, directories, members }) };
  return { root, source, members };
}

async function describeSource(sourceRoot, { expectedRoot, expectedDevice } = {}) {
  if (process.platform === "win32") return describeWindowsSource(sourceRoot, { expectedRoot });
  const root = await canonicalDirectory(sourceRoot, "sourceRoot");
  if (expectedRoot && !sameIdentity(root.identity, expectedRoot.identity)) throw new Error("generation root changed before observation");
  if (expectedDevice !== undefined && root.stats.dev !== expectedDevice) throw new Error("generation root is on another device");
  const closure = await scanDirectory(root.path, { expectedDevice,
    approvedBinding: expectedRoot ? rootBinding(root.path, expectedRoot.identity) : undefined });
  if (expectedRoot) {
    const after = await canonicalDirectory(root.path, "generationRoot");
    if (!sameIdentity(after.identity, expectedRoot.identity)) throw new Error("generation root changed during observation");
  }
  const source = {
    rootBinding: rootBinding(root.path, root.identity),
    root: root.identity,
    directories: closure.directories,
    closureDigest: digestDocument({ root: root.identity, directories: closure.directories, members: closure.members }),
  };
  return { root, source, members: closure.members };
}

async function describeTree(rootPath, label, { requireMember = true } = {}) {
  const root = await canonicalDirectory(rootPath, label);
  const closure = await scanDirectory(root.path, { requireMember });
  return {
    root,
    snapshot: {
      root: root.identity,
      directories: closure.directories,
      members: closure.members,
      closureDigest: digestDocument({
        root: root.identity,
        directories: closure.directories,
        members: closure.members,
      }),
    },
  };
}

function sameIdentity(left, right) {
  return left?.type === "directory" && right?.type === "directory" &&
    left.device === right.device && left.inode === right.inode && left.mode === right.mode;
}

function sameSnapshot(left, right) {
  return left?.closureDigest === right?.closureDigest && canonicalJson(left) === canonicalJson(right);
}

function replacementTuple({
  phase,
  publicationState,
  commitState,
  verification,
  durability,
}) {
  return { phase, publicationState, commitState, verification, durability };
}

const PRE_COMMIT_NOT_RUN = Object.freeze(replacementTuple({
  phase: "pre-commit",
  publicationState: "not-published",
  commitState: "not-committed",
  verification: "not-run",
  durability: "not-requested",
}));

const PRE_COMMIT_VERIFIED = Object.freeze(replacementTuple({
  phase: "pre-commit",
  publicationState: "not-published",
  commitState: "not-committed",
  verification: "original-mapping-verified",
  durability: "not-requested",
}));

const POST_COMMIT_PUBLISHED = Object.freeze(replacementTuple({
  phase: "post-commit",
  publicationState: "published",
  commitState: "exchange-committed",
  verification: "verified",
  durability: "indeterminate",
}));

const POST_COMMIT_INDETERMINATE = Object.freeze(replacementTuple({
  phase: "post-commit",
  publicationState: "indeterminate",
  commitState: "indeterminate",
  verification: "failed",
  durability: "indeterminate",
}));

function replacementError(message, tuple, cause, kind = HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED) {
  const diagnostic = cause?.code ?? cause?.message;
  return mechanismError(
    kind,
    diagnostic ? `${message}: ${diagnostic}` : message,
    { ...tuple },
  );
}

async function observeReplacementMapping({ sourceRoot, targetPath, targetParent, parent, source, target }) {
  try {
    const liveParent = await canonicalDirectory(targetParent, "targetParent");
    if (!sameIdentity(liveParent.identity, parent.identity)) return "other";
    const liveSource = await describeTree(sourceRoot, "sourceRoot", { requireMember: false });
    const liveTarget = await describeTree(targetPath, "target", { requireMember: false });
    if (sameSnapshot(liveSource.snapshot, source.snapshot) && sameSnapshot(liveTarget.snapshot, target.snapshot)) {
      return "original";
    }
    if (sameSnapshot(liveSource.snapshot, target.snapshot) && sameSnapshot(liveTarget.snapshot, source.snapshot)) {
      return "exchanged";
    }
  } catch {
    // An unobservable side is neither a proved original nor exchanged mapping.
  }
  return "other";
}

async function syncDirectoryBound(directory, expectedIdentity) {
  if (FS_CONSTANTS.O_NOFOLLOW === undefined || FS_CONSTANTS.O_DIRECTORY === undefined) {
    throw new Error("O_NOFOLLOW and O_DIRECTORY are required for directory synchronization");
  }
  const handle = await open(
    directory,
    FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_DIRECTORY | FS_CONSTANTS.O_NOFOLLOW,
  );
  try {
    const current = await handle.stat({ bigint: true });
    if (!current.isDirectory() || !sameIdentity(directoryIdentity(current), expectedIdentity)) {
      throw new Error("directory identity changed before synchronization");
    }
    await syncForDurability(directory, { directory: true });
  } finally {
    await handle.close();
  }
}

function trustedNativeResult(value, expectedPlatform) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !Number.isInteger(value.status) || typeof value.committed !== "boolean" ||
      value.platform !== expectedPlatform) {
    return null;
  }
  const keys = Object.keys(value).sort().join(",");
  if (value.status === 0) {
    if (value.committed !== true || keys !== "committed,platform,status") return null;
  } else if (keys !== "committed,error,platform,status" ||
      typeof value.error !== "string" || value.error.length === 0) {
    return null;
  }
  return value;
}

/** Mechanically freezes one sibling-directory publication manifest. */
export async function createFixedSetPublicationManifest({ sourceRoot, targetParent, targetSegment } = {}) {
  const segment = assertSegment(targetSegment, "targetSegment");
  const described = await describeSource(sourceRoot);
  const parent = await canonicalDirectory(targetParent, "targetParent");
  if ((process.platform === "win32" ? path.posix.dirname(described.root.path) : path.dirname(described.root.path)) !== parent.path) {
    throw new TypeError("sourceRoot and target must share the same canonical parent");
  }
  if (path.basename(described.root.path) === segment) throw new TypeError("source and target segments must differ");
  try {
    await lstat(path.join(parent.path, segment));
    throw new TypeError("target must be absent when the manifest is created");
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
  }
  const target = {
    rootBinding: process.platform === "win32" ? parent.binding : rootBinding(parent.path, parent.identity),
    root: parent.identity,
    directories: [],
    closureDigest: digestDocument({ root: parent.identity, directories: [], expectation: "absent", targetSegment: segment }),
    expectation: "absent",
  };
  const unsigned = {
    schemaVersion: process.platform === "win32" ? 2 : 1,
    kind: MANIFEST_KIND,
    source: described.source,
    target: process.platform === "win32"
      ? { ...target, rootBinding: parent.binding, root: parent.identity }
      : target,
    members: described.members,
  };
  return Object.freeze({ ...unsigned, digest: digestDocument(unsigned) });
}

function invalidReceipt(manifest, code, message, targetState = "absent") {
  let manifestDigest = ZERO_DIGEST;
  try { manifestDigest = digestDocument(manifest); } catch { /* invalid input is represented by the sentinel */ }
  const targetRootBinding = manifest?.target?.rootBinding?.digest ? manifest.target.rootBinding : {
    kind: "trusted-filesystem-root-binding",
    digestAlgorithm: "sha256",
    basis: "canonical-realpath-device-inode-type-mode-v1",
    digest: ZERO_DIGEST,
  };
  return Object.freeze({
    schemaVersion: 1,
    kind: RECEIPT_KIND,
    manifestDigest,
    targetRootBinding,
    platform: "other",
    primitive: "none",
    status: "refused",
    targetState,
    commitState: "not-committed",
    verification: "not-run",
    durability: "not-attempted",
    error: { code, message: String(message).slice(0, 300) },
  });
}

function platformReceipt(manifest, platform, fields) {
  return Object.freeze({
    schemaVersion: 1,
    kind: RECEIPT_KIND,
    manifestDigest: digestDocument(manifest),
    targetRootBinding: manifest.target.rootBinding,
    platform,
    primitive: primitive(platform),
    ...fields,
  });
}

async function assertLiveManifest(input, manifest) {
  const live = await createFixedSetPublicationManifest(input);
  if (canonicalJson(live) !== canonicalJson(manifest)) throw new Error("publication manifest differs from the live exact closure");
}

async function verifyPublished(targetPath, manifest) {
  const described = await describeSource(targetPath);
  if (canonicalJson(described.source.root) !== canonicalJson(manifest.source.root) ||
      canonicalJson(described.source.directories) !== canonicalJson(manifest.source.directories) ||
      canonicalJson(described.members) !== canonicalJson(manifest.members) ||
      described.source.closureDigest !== manifest.source.closureDigest) {
    throw new Error("published fixed-set closure differs from the frozen source closure");
  }
}

const WINDOWS_PUBLICATION_BASIS = "canonical-finalpath-volume-fileid-type-security-v1";

function windowsPublicationReceipt(manifest, fields) {
  let manifestDigest = ZERO_DIGEST;
  try { manifestDigest = digestDocument(manifest); } catch { /* invalid input keeps the sentinel */ }
  const targetRootBinding = manifest?.target?.rootBinding?.basis === WINDOWS_PUBLICATION_BASIS
    ? manifest.target.rootBinding
    : {
      kind: "trusted-filesystem-root-binding",
      digestAlgorithm: "sha256",
      basis: WINDOWS_PUBLICATION_BASIS,
      digest: ZERO_DIGEST,
    };
  return Object.freeze({
    schemaVersion: 2,
    kind: RECEIPT_KIND,
    manifestDigest,
    targetRootBinding,
    platform: "win32",
    primitive: "windows-rename-noreplace-v1",
    ...fields,
  });
}

async function verifyWindowsPublished(targetPath, manifest, loaded) {
  if (!Array.isArray(manifest.members) || manifest.members.length === 0) {
    throw new Error("Windows publication manifest has no members");
  }
  for (const member of manifest.members) {
    if (member?.type !== "regular" || typeof member.path !== "string" || typeof member.sha256 !== "string" ||
        member.permissionObservation?.kind !== "windows-security-v1") {
      throw new Error("Windows publication member is not a verifiable file");
    }
    const filePath = path.join(targetPath, ...member.path.split("/"));
    const captured = loaded.addon.readCapturedFile(filePath);
    if (!captured?.ok || !Buffer.isBuffer(captured.bytes) || !Buffer.isBuffer(captured.securityDescriptor)) {
      throw new Error("published member could not be read from the same handle");
    }
    const bytes = Buffer.from(captured.bytes);
    if (sha256(Buffer.from(captured.securityDescriptor)) !== member.permissionObservation.securityDigest ||
        bytes.length !== member.bytes || sha256(bytes) !== member.sha256) {
      throw new Error("published member bytes, identity, or DACL do not match the manifest");
    }
  }
  const root = loaded.addon.captureSecurity(targetPath);
  if (!root?.ok || !Buffer.isBuffer(root.securityDescriptor) ||
      root.volumeSerial !== manifest.source?.root?.volumeSerial ||
      root.fileId !== manifest.source?.root?.fileId ||
      sha256(Buffer.from(root.securityDescriptor)) !== manifest.source?.root?.permissionObservation?.securityDigest) {
    throw new Error("published root identity or DACL does not match the manifest");
  }
  for (const directory of manifest.source?.directories ?? []) {
    const directoryPath = path.join(targetPath, ...String(directory.path).split("/"));
    const captured = loaded.addon.captureSecurity(directoryPath);
    if (!captured?.ok || !Buffer.isBuffer(captured.securityDescriptor) ||
        captured.volumeSerial !== directory.volumeSerial || captured.fileId !== directory.fileId ||
        sha256(Buffer.from(captured.securityDescriptor)) !== directory.permissionObservation?.securityDigest) {
      throw new Error("published directory identity or DACL does not match the manifest");
    }
  }
}

async function publishFixedSetWindows({ sourceRoot, targetParent, targetSegment, manifest } = {}) {
  if (manifest?.schemaVersion !== 2 || manifest?.kind !== MANIFEST_KIND ||
      manifest?.source?.rootBinding?.basis !== WINDOWS_PUBLICATION_BASIS ||
      manifest?.target?.rootBinding?.basis !== WINDOWS_PUBLICATION_BASIS) {
    return windowsPublicationReceipt(manifest, {
      status: "refused",
      targetState: "absent",
      commitState: "not-committed",
      verification: "not-run",
      durability: "not-attempted",
      error: { code: "MANIFEST_INVALID", message: "Windows publication requires a version 2 manifest" },
    });
  }
  let loaded;
  try {
    loaded = await loadWindowsNativeAddon();
  } catch (cause) {
    return windowsPublicationReceipt(manifest, {
      status: "failed",
      targetState: "absent",
      commitState: "not-committed",
      verification: "not-run",
      durability: "not-attempted",
      error: { code: "UNSUPPORTED_PLATFORM", message: String(cause?.message ?? "win32-x64 native addon is not built").slice(0, 300) },
    });
  }
  try {
    const live = await createFixedSetPublicationManifest({ sourceRoot, targetParent, targetSegment });
    if (canonicalJson(live) !== canonicalJson(manifest)) {
      return windowsPublicationReceipt(manifest, {
        status: "refused",
        targetState: "absent",
        commitState: "not-committed",
        verification: "not-run",
        durability: "not-attempted",
        error: { code: "SOURCE_DRIFT", message: "publication manifest differs from the live exact closure" },
      });
    }
  } catch (cause) {
    return windowsPublicationReceipt(manifest, {
      status: "refused",
      targetState: /target must be absent/u.test(cause?.message ?? "") ? "existing" : "absent",
      commitState: "not-committed",
      verification: "not-run",
      durability: "not-attempted",
      error: { code: cause instanceof TypeError ? "PATH_UNSAFE" : "SOURCE_DRIFT", message: String(cause?.message ?? "live closure check failed").slice(0, 300) },
    });
  }
  let parentHandle;
  let nativeResult;
  try {
    parentHandle = loaded.addon.openParentDirectory(targetParent);
    if (!parentHandle?.ok) {
      return windowsPublicationReceipt(manifest, {
        status: "failed",
        targetState: "absent",
        commitState: "not-committed",
        verification: "not-run",
        durability: "not-attempted",
        error: { code: "PUBLICATION_FAILED", message: parentHandle?.failureReason ?? "parent directory could not be opened" },
      });
    }
    nativeResult = loaded.addon.renameDirectoryNoReplace(parentHandle, path.basename(sourceRoot), targetSegment);
  } finally {
    if (parentHandle?.ok) loaded.addon.closeParentDirectory(parentHandle);
  }
  if (!nativeResult?.ok || nativeResult.committed !== true || nativeResult.status !== 0) {
    if (nativeResult?.committed === true) {
      return windowsPublicationReceipt(manifest, {
        status: "indeterminate",
        targetState: "indeterminate",
        commitState: "indeterminate",
        verification: "not-run",
        durability: "indeterminate",
        error: { code: "PUBLICATION_FAILED", message: nativeResult?.error ?? "rename outcome is unknown" },
      });
    }
    const exists = nativeResult?.status === 17;
    return windowsPublicationReceipt(manifest, {
      status: exists ? "refused" : "failed",
      targetState: exists ? "existing" : "absent",
      commitState: "not-committed",
      verification: "not-run",
      durability: "not-attempted",
      error: { code: exists ? "TARGET_EXISTS" : "PUBLICATION_FAILED", message: nativeResult?.error ?? "rename failed" },
    });
  }
  const targetPath = path.join(targetParent, targetSegment);
  try {
    await verifyWindowsPublished(targetPath, manifest, loaded);
  } catch (cause) {
    return windowsPublicationReceipt(manifest, {
      status: "indeterminate",
      targetState: "indeterminate",
      commitState: "rename-committed",
      verification: "failed",
      durability: "indeterminate",
      error: { code: "POST_VERIFY_FAILED", message: cause?.message ?? "published bytes, identity, or DACL did not match" },
    });
  }
  const flushed = loaded.addon.flushDirectory(targetPath) === true && loaded.addon.flushDirectory(targetParent) === true;
  if (!flushed) {
    return windowsPublicationReceipt(manifest, {
      status: "indeterminate",
      targetState: "published",
      commitState: "rename-committed",
      verification: "verified",
      durability: "indeterminate",
      publishedClosureDigest: manifest.digest,
      memberCount: manifest.members.length,
      error: { code: "DIRECTORY_FSYNC_FAILED", message: "directory flush failed" },
    });
  }
  return windowsPublicationReceipt(manifest, {
    status: "succeeded",
    targetState: "published",
    commitState: "rename-committed",
    verification: "verified",
    durability: "flush-requested",
    publishedClosureDigest: manifest.digest,
    memberCount: manifest.members.length,
  });
}

/** Stable operation. It never falls back to a JavaScript exists+rename sequence. */
export async function publishFixedSet({ sourceRoot, targetParent, targetSegment, manifest } = {}) {
  if (process.platform === "win32") return publishFixedSetWindows({ sourceRoot, targetParent, targetSegment, manifest });
  const input = { sourceRoot, targetParent, targetSegment };
  if (manifest?.schemaVersion !== 1 || manifest?.kind !== MANIFEST_KIND) {
    return invalidReceipt(manifest, "MANIFEST_INVALID", "manifest kind or version is invalid");
  }
  try {
    await assertLiveManifest(input, manifest);
  } catch (cause) {
    const code = cause instanceof TypeError ? "PATH_UNSAFE" : "SOURCE_DRIFT";
    const targetState = /target must be absent/u.test(cause?.message ?? "") ? "existing" : "absent";
    return invalidReceipt(manifest, code, cause?.message ?? "manifest verification failed", targetState);
  }

  let loaded;
  try {
    loaded = await loadNativeAddon();
  } catch (cause) {
    return invalidReceipt(manifest, "UNSUPPORTED_PLATFORM", cause?.message ?? "stable native closure unavailable");
  }
  const platform = loaded.addon.platform;
  let parentHandle;
  try {
    parentHandle = loaded.addon.openParentDirectory(targetParent);
    if (parentHandle?.status) {
      return platformReceipt(manifest, platform, {
        status: "failed", targetState: "absent", commitState: "not-committed",
        verification: "not-run", durability: "not-attempted",
        error: { code: "PUBLICATION_FAILED", message: parentHandle.error },
      });
    }
    const nativeResult = loaded.addon.renameDirectoryNoReplace(parentHandle, path.basename(sourceRoot), targetSegment, {
      device: manifest.source.root.device,
      inode: manifest.source.root.inode,
      mode: manifest.source.root.mode,
    });
    if (nativeResult.status !== 0) {
      if (nativeResult.committed) {
        return platformReceipt(manifest, platform, {
          status: "indeterminate", targetState: "indeterminate", commitState: "rename-committed",
          verification: "failed", durability: "indeterminate",
          error: { code: "POST_VERIFY_FAILED", message: nativeResult.error },
        });
      }
      const exists = nativeResult.status === 17;
      return platformReceipt(manifest, platform, {
        status: exists ? "refused" : "failed", targetState: exists ? "existing" : "absent",
        commitState: "not-committed", verification: "not-run", durability: "not-attempted",
        error: { code: exists ? "TARGET_EXISTS" : "PUBLICATION_FAILED", message: nativeResult.error },
      });
    }
  } finally {
    if (parentHandle && !parentHandle.status) loaded.addon.closeParentDirectory(parentHandle);
  }

  const targetPath = path.join(targetParent, targetSegment);
  try {
    await verifyPublished(targetPath, manifest);
  } catch (cause) {
    return platformReceipt(manifest, platform, {
      status: "indeterminate", targetState: "indeterminate", commitState: "rename-committed",
      verification: "failed", durability: "indeterminate",
      error: { code: "POST_VERIFY_FAILED", message: cause?.message ?? "post-verification failed" },
    });
  }
  try {
    for (const directory of [targetPath, targetParent]) {
      await syncForDurability(directory, { directory: true });
    }
  } catch (cause) {
    return platformReceipt(manifest, platform, {
      status: "indeterminate", targetState: "published", commitState: "rename-committed",
      verification: "verified", durability: "indeterminate", publishedClosureDigest: manifest.digest,
      memberCount: manifest.members.length,
      error: { code: "DIRECTORY_FSYNC_FAILED", message: cause?.message ?? "directory fsync failed" },
    });
  }
  return platformReceipt(manifest, platform, {
    status: "succeeded", targetState: "published", commitState: "rename-committed",
    verification: "verified", durability: "synced", publishedClosureDigest: manifest.digest,
    memberCount: manifest.members.length,
  });
}

/**
 * Atomically exchanges one complete staged fixed set with one existing target.
 * A successful call leaves the displaced target at sourceRoot. This operation
 * never deletes either side, retries the exchange, or attempts rollback.
 */
export function replaceFixedSetAtomicDecision(platform = process.platform) {
  return platform === "darwin" || platform === "linux" ? "native-exchange" : "refused";
}

export async function replaceFixedSetAtomic({ sourceRoot, targetParent, targetSegment } = {}) {
  if (replaceFixedSetAtomicDecision() === "refused") {
    throw replacementError(
      "fixed-set directory exchange is refused; publish a generation instead",
      PRE_COMMIT_NOT_RUN,
      null,
      HARNESS_ERROR_KINDS.UNSUPPORTED_PLATFORM,
    );
  }
  assertNormalizedAbsolutePath(sourceRoot, "sourceRoot");
  assertNormalizedAbsolutePath(targetParent, "targetParent");
  const segment = assertSegment(targetSegment, "targetSegment");

  let parent;
  let sourceRootIdentity;
  try {
    parent = await canonicalDirectory(targetParent, "targetParent");
    sourceRootIdentity = await canonicalDirectory(sourceRoot, "sourceRoot");
  } catch (cause) {
    throw replacementError("fixed-set replacement input cannot be observed", PRE_COMMIT_NOT_RUN, cause);
  }
  if (path.dirname(sourceRootIdentity.path) !== parent.path) {
    throw new TypeError("sourceRoot and target must share the same canonical parent");
  }
  const sourceSegment = path.basename(sourceRootIdentity.path);
  if (sourceSegment === segment) throw new TypeError("source and target segments must differ");
  const targetPath = path.join(parent.path, segment);

  let source;
  let target;
  try {
    source = await describeTree(sourceRootIdentity.path, "sourceRoot");
    target = await describeTree(targetPath, "target", { requireMember: false });
  } catch (cause) {
    throw replacementError("fixed-set replacement trees are unsafe", PRE_COMMIT_NOT_RUN, cause);
  }
  const context = {
    sourceRoot: sourceRootIdentity.path,
    targetPath,
    targetParent: parent.path,
    parent,
    source,
    target,
  };

  const runtimePlatform = stableNativePlatformKey();
  if (runtimePlatform === null) {
    throw replacementError(
      "fixed-set replacement is unsupported on this runtime",
      PRE_COMMIT_NOT_RUN,
      null,
      HARNESS_ERROR_KINDS.UNSUPPORTED_PLATFORM,
    );
  }

  let loaded;
  try {
    loaded = await loadNativeAddon();
    if (loaded?.platform !== runtimePlatform) {
      throw new Error("stable native closure platform does not match the runtime");
    }
  } catch (cause) {
    throw replacementError("stable native closure cannot be loaded", PRE_COMMIT_NOT_RUN, cause);
  }

  if ((await observeReplacementMapping(context)) !== "original") {
    throw replacementError("fixed-set replacement input drifted before commit", PRE_COMMIT_NOT_RUN);
  }

  const addon = loaded?.addon;
  let parentHandle = null;
  let nativeResult;
  let exchangeFailure = null;
  let closeFailure = null;
  try {
    if (!addon || typeof addon.openParentDirectory !== "function" ||
        typeof addon.closeParentDirectory !== "function" ||
        typeof addon.exchangeDirectories !== "function") {
      throw new Error("stable native addon does not expose the directory exchange closure");
    }
    parentHandle = addon.openParentDirectory(parent.path);
    if (parentHandle?.status) {
      throw new Error(parentHandle.error ?? "parent directory could not be opened");
    }
    nativeResult = addon.exchangeDirectories(
      parentHandle,
      sourceSegment,
      segment,
      parent.identity,
      source.snapshot.root,
      target.snapshot.root,
    );
  } catch (cause) {
    exchangeFailure = cause;
  } finally {
    if (parentHandle && !parentHandle.status && typeof addon?.closeParentDirectory === "function") {
      try {
        const closed = addon.closeParentDirectory(parentHandle);
        if (closed !== true) throw new Error(closed?.error ?? "parent directory handle did not close cleanly");
      } catch (cause) {
        closeFailure = cause;
      }
    }
  }

  const trusted = exchangeFailure === null
    ? trustedNativeResult(nativeResult, runtimePlatform.startsWith("darwin-") ? "darwin" : "linux")
    : null;
  const mapping = await observeReplacementMapping(context);
  const successfulExchange = closeFailure === null && trusted?.status === 0 &&
    trusted.committed === true && mapping === "exchanged";

  if (!successfulExchange) {
    const cause = exchangeFailure ?? closeFailure ??
      new Error(trusted?.error ?? "native directory exchange result is not trustworthy");
    if (mapping === "original" && trusted?.committed !== true) {
      throw replacementError("directory exchange did not commit", PRE_COMMIT_VERIFIED, cause);
    }
    if (mapping === "exchanged") {
      throw replacementError("directory exchange committed without a trustworthy success result", POST_COMMIT_PUBLISHED, cause);
    }
    throw replacementError("directory exchange state is indeterminate", POST_COMMIT_INDETERMINATE, cause);
  }

  try {
    await syncDirectoryBound(targetPath, source.snapshot.root);
    await syncDirectoryBound(sourceRootIdentity.path, target.snapshot.root);
    await syncDirectoryBound(parent.path, parent.identity);
  } catch (cause) {
    throw replacementError("directory exchange synchronization failed", POST_COMMIT_PUBLISHED, cause);
  }

  return Object.freeze({
    path: targetPath,
    displacedTargetPath: sourceRootIdentity.path,
    publicationState: "published",
    commitState: "exchange-committed",
    verification: "verified",
    durability: "namespace-synced",
    publishedClosureDigest: source.snapshot.closureDigest,
    displacedClosureDigest: target.snapshot.closureDigest,
  });
}

const GENERATION_NAME = /^[a-z0-9][a-z0-9-]{0,63}$/u;
const POINTER_FILE = "current.json";
const POINTER_KIND = "skill-family.fixed-set-generation-pointer";
const RESULT_KIND = "skill-family.fixed-set-generation-result";
const RESOLUTION_KIND = "skill-family.fixed-set-generation-resolution";
const POSIX_BASIS = "canonical-realpath-device-inode-type-mode-v1";
const WINDOWS_BASIS = "canonical-finalpath-volume-fileid-type-security-v1";
let generationRenameFault = null;

/** Test-only fault injected immediately before the pointer rename. Not a package-index export. */
export function __setGenerationRenameFault(fault) {
  generationRenameFault = fault;
}

function assertGenerationName(generation) {
  if (typeof generation !== "string" || !GENERATION_NAME.test(generation) || generation === "current") {
    throw new TypeError("generation must be one safe generation segment");
  }
  return generation;
}

function isGenerationPointer(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  return value.schemaVersion === 1
    && value.kind === POINTER_KIND
    && typeof value.generation === "string"
    && GENERATION_NAME.test(value.generation)
    && value.generation !== "current"
    && typeof value.closureDigest === "string"
    && /^[0-9a-f]{64}$/u.test(value.closureDigest)
    && Object.keys(value).length === 4;
}

function generationBasis(platform) {
  return platform === "win32" ? WINDOWS_BASIS : POSIX_BASIS;
}

function successDurability(platform) {
  return platform === "win32" ? "flush-requested" : "namespace-synced";
}

function generationResult(fields) {
  return Object.freeze({
    schemaVersion: 1,
    kind: RESULT_KIND,
    status: fields.status,
    commitState: fields.commitState,
    verification: fields.verification,
    durability: fields.durability,
    generationRoot: fields.generationRoot,
    pointer: fields.pointer ?? null,
    previous: fields.previous ?? null,
    error: fields.error ?? null,
  });
}

function preCommitFailure(generationRoot, message, previous = null, pointer = null) {
  return generationResult({
    status: "failed",
    commitState: "not-committed",
    verification: "not-performed",
    durability: "not-requested",
    generationRoot,
    previous,
    pointer,
    error: { kind: HARNESS_ERROR_KINDS.CLOSURE_CONFLICT, message },
  });
}

async function readGenerationPointer(storePath, binding) {
  const pointerPath = path.join(storePath, POINTER_FILE);
  let receipt;
  try { receipt = await readFileBound(storePath, POINTER_FILE, { rootBinding: binding }); }
  catch (cause) {
    if (cause?.details?.kind === HARNESS_ERROR_KINDS.MISSING_RESOURCE) return { state: "absent", pointerPath };
    return { state: "unreadable", pointerPath, cause };
  }
  let parsed;
  try { parsed = JSON.parse(Buffer.from(receipt.content).toString("utf8")); }
  catch { return { state: "corrupt", pointerPath }; }
  if (!isGenerationPointer(parsed)) return { state: "corrupt", pointerPath };
  return { state: "present", pointerPath, pointer: parsed };
}

async function collectGenerationClosure(root) {
  const described = await describeSource(root.path, { expectedRoot: root, expectedDevice: root.stats.dev });
  return { root: described.source.root, directories: described.source.directories, members: described.members,
    rootBinding: described.source.rootBinding };
}

function generationClosureDigest(platform, closure) {
  return digestDocument({ platform, basis: generationBasis(platform), root: closure.root,
    directories: closure.directories, members: closure.members });
}

async function commitGenerationPointer(temporary, pointerPath, store, current) {
  if (process.platform !== "win32") {
    await rename(temporary, pointerPath);
    return null;
  }
  const read = await readFileBound(store.path, path.basename(temporary), { rootBinding: store.binding });
  try {
    if (current.state === "absent") await publishFileExclusive(store.path, POINTER_FILE, read.content);
    else await replaceFileAtomic(store.path, POINTER_FILE, read.content);
  } catch (cause) {
    // Only the strict primitive can establish this fact. A fault thrown
    // before entering it must never manufacture a committed pointer.
    if (cause?.details?.phase !== "post-commit") throw cause;
    return cause;
  }
  try { await unlink(temporary); }
  catch (cause) { return cause; }
  return null;
}

export async function publishFixedSetGeneration({ storeRoot, sourceRoot, generation, expectedCurrent } = {}) {
  assertGenerationName(generation);
  if (expectedCurrent !== null && !isGenerationPointer(expectedCurrent)) {
    throw new TypeError("expectedCurrent must be null or a generation pointer");
  }
  const store = await canonicalDirectory(storeRoot, "storeRoot");
  const source = await canonicalDirectory(sourceRoot, "sourceRoot");
  if (source.path !== (process.platform === "win32" ? path.posix.join(store.path, generation) : path.join(store.path, generation))) {
    throw new TypeError("sourceRoot must be the canonical generation directory inside storeRoot");
  }
  if (source.stats.dev !== store.stats.dev) {
    return preCommitFailure(source.path, "generation source is on another volume");
  }

  const platform = process.platform;
  let closure;
  try {
    closure = await collectGenerationClosure(source);
  } catch (cause) {
    return preCommitFailure(source.path, cause?.message ?? "generation source is unsafe");
  }
  const closureDigest = generationClosureDigest(platform, closure);
  const pointer = {
    schemaVersion: 1,
    kind: POINTER_KIND,
    generation,
    closureDigest,
  };
  const current = await readGenerationPointer(store.path, store.binding ?? rootBinding(store.path, store.identity));
  if (current.state === "corrupt" || current.state === "unreadable") {
    return preCommitFailure(source.path, "existing generation pointer cannot be read safely", null, pointer);
  }
  if (expectedCurrent === null && current.state !== "absent") {
    return preCommitFailure(source.path, "a generation pointer already exists", current.pointer, pointer);
  }
  if (expectedCurrent !== null && (current.state !== "present" || canonicalJson(current.pointer) !== canonicalJson(expectedCurrent))) {
    return preCommitFailure(source.path, "generation pointer does not match expectedCurrent", current.state === "present" ? current.pointer : null, pointer);
  }
  if (current.state === "present" && current.pointer.generation === generation) {
    return preCommitFailure(source.path, "generation pointer already names this generation", current.pointer, pointer);
  }

  const temporary = path.join(store.path, `.${generation}.pointer.tmp`);
  const previousCanonical = current.state === "present" ? canonicalJson(current.pointer) : null;
  let createdTemporary = false;
  let postCommitError = null;
  try {
    const payload = canonicalJson(pointer);
    if (platform === "win32") {
      const loaded = await loadWindowsNativeAddon();
      const published = loaded.addon.publishProtectedFile(temporary, Buffer.from(payload), "windows-protected", false);
      if (!published?.ok) throw new Error(published?.failureReason ?? "generation pointer temporary was not created");
      createdTemporary = true;
    } else {
      const handle = await open(
        temporary,
        FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_WRONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
        0o600,
      );
      createdTemporary = true;
      try {
        await handle.writeFile(payload);
        await syncForDurability(temporary, { handle });
      } finally {
        await handle.close();
      }
    }
    if (typeof generationRenameFault === "function") {
      const fault = generationRenameFault;
      generationRenameFault = null;
      await fault({ storePath: store.path, temporary, pointerPath: current.pointerPath });
    }
    postCommitError = await commitGenerationPointer(temporary, current.pointerPath, store, current);
  } catch (cause) {
    const after = await readGenerationPointer(store.path, store.binding ?? rootBinding(store.path, store.identity));
    const unchanged = current.state === "absent"
      ? after.state === "absent"
      : after.state === "present" && canonicalJson(after.pointer) === previousCanonical;
    if (createdTemporary) await unlink(temporary).catch(() => {});
    if (unchanged) {
      return preCommitFailure(source.path, cause?.message ?? "generation pointer was not committed", current.pointer ?? null, pointer);
    }
    return generationResult({
      status: "indeterminate",
      commitState: "indeterminate",
      verification: "not-performed",
      durability: "indeterminate",
      generationRoot: source.path,
      pointer,
      previous: current.pointer ?? null,
      error: { kind: HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED, message: cause?.message ?? "generation commit outcome is unknown" },
    });
  }

  const verified = await readGenerationPointer(store.path, store.binding ?? rootBinding(store.path, store.identity));
  const pointerMatches = verified.state === "present" && canonicalJson(verified.pointer) === canonicalJson(pointer);
  if (!pointerMatches) {
    return generationResult({
      status: "failed",
      commitState: "committed",
      verification: "failed",
      durability: "indeterminate",
      generationRoot: source.path,
      pointer,
      previous: current.pointer ?? null,
      error: { kind: HARNESS_ERROR_KINDS.CLOSURE_CONFLICT, message: "committed generation pointer did not verify" },
    });
  }
  try {
    const recomputed = generationClosureDigest(platform, await collectGenerationClosure(source));
    if (recomputed !== closureDigest) {
      return generationResult({
        status: "failed",
        commitState: "committed",
        verification: "failed",
        durability: "indeterminate",
        generationRoot: source.path,
        pointer,
        previous: current.pointer ?? null,
        error: { kind: HARNESS_ERROR_KINDS.CLOSURE_CONFLICT, message: "committed generation closure does not match the pointer" },
      });
    }
  } catch (cause) {
    return generationResult({
      status: "failed",
      commitState: "committed",
      verification: "failed",
      durability: "indeterminate",
      generationRoot: source.path,
      pointer,
      previous: current.pointer ?? null,
      error: { kind: HARNESS_ERROR_KINDS.CLOSURE_CONFLICT, message: cause?.message ?? "committed generation closure could not be reread" },
    });
  }
  if (postCommitError !== null) {
    return generationResult({
      status: "failed", commitState: "committed", verification: "verified", durability: "indeterminate",
      generationRoot: source.path, pointer, previous: current.pointer ?? null,
      error: { kind: postCommitError?.details?.kind ?? HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
        message: postCommitError?.message ?? "generation pointer committed but finalization failed" },
    });
  }
  try {
    await syncForDurability(store.path, { directory: true });
  } catch (cause) {
    return generationResult({
      status: "failed",
      commitState: "committed",
      verification: "verified",
      durability: "indeterminate",
      generationRoot: source.path,
      pointer,
      previous: current.pointer ?? null,
      error: { kind: HARNESS_ERROR_KINDS.ATOMIC_WRITE_FAILED, message: cause?.message ?? "generation directory flush failed" },
    });
  }
  return generationResult({
    status: "succeeded",
    commitState: "committed",
    verification: "verified",
    durability: successDurability(platform),
    generationRoot: source.path,
    pointer,
    previous: current.pointer ?? null,
  });
}

export async function resolveFixedSetGeneration({ storeRoot } = {}) {
  const store = await canonicalDirectory(storeRoot, "storeRoot");
  const current = await readGenerationPointer(store.path, store.binding ?? rootBinding(store.path, store.identity));
  if (current.state !== "present") {
    throw mechanismError(
      HARNESS_ERROR_KINDS.READ_FAILED,
      "generation pointer cannot be resolved",
      { state: current.state },
    );
  }
  const generationRoot = path.join(store.path, current.pointer.generation);
  let generation;
  try {
    generation = await canonicalDirectory(generationRoot, "generationRoot");
  } catch (cause) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      "generation root does not match the pointer",
      { cause: cause?.message ?? "unreadable" },
    );
  }
  if (generation.stats.dev !== store.stats.dev || (process.platform === "win32" ? path.posix.dirname(generation.path) : path.dirname(generation.path)) !== store.path ||
      path.basename(generation.path) !== current.pointer.generation) {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "generation root does not match the pointer");
  }
  const platform = process.platform;
  let closureDigest, closure;
  try {
    closure = await collectGenerationClosure(generation);
    closureDigest = generationClosureDigest(platform, closure);
  } catch (cause) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      cause?.message ?? "generation members do not match the pointer",
    );
  }
  if (closureDigest !== current.pointer.closureDigest) {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "generation closure does not match the pointer");
  }
  try {
    const finalRoot = await canonicalDirectory(generation.path, "generationRoot");
    const finalBinding = finalRoot.binding ?? rootBinding(finalRoot.path, finalRoot.identity);
    if (finalBinding.digest !== closure.rootBinding.digest || canonicalJson(finalRoot.identity) !== canonicalJson(closure.root)) throw new Error("generation root changed after closure verification");
  } catch (cause) {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, cause?.message ?? "generation root cannot be verified");
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: RESOLUTION_KIND,
    pointer: current.pointer,
    generationRoot: generation.path,
    rootBinding: closure.rootBinding,
  });
}

