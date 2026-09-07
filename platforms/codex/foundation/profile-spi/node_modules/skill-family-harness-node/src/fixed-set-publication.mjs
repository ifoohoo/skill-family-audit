import { createHash } from "node:crypto";
import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { canonicalJson, digestDocument } from "skill-family-contracts";
import { loadNativeAddon } from "./fixed-set-publication-loader.mjs";

const MANIFEST_KIND = "skill-family.fixed-set-publication-manifest";
const RECEIPT_KIND = "skill-family.fixed-set-publication-receipt";
const ZERO_DIGEST = "0".repeat(64);
const SEGMENT = /^[A-Za-z0-9._-]+$/u;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function primitive(platform) {
  return platform === "darwin" ? "darwin-renameatx-noreplace-v1" :
    platform === "linux" ? "linux-renameat2-noreplace-v1" : "none";
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

async function canonicalDirectory(input, label) {
  if (typeof input !== "string" || !path.isAbsolute(input) || input.includes("\0") || path.normalize(input) !== input) {
    throw new TypeError(`${label} must be a normalized absolute path`);
  }
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

async function scanDirectory(root) {
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
      if (before.isSymbolicLink()) throw new TypeError(`fixed-set member must not be a symlink: ${relPath}`);
      if (before.isDirectory()) {
        directories.push({ path: relPath, ...directoryIdentity(before) });
        await walk(relPath);
      } else if (before.isFile() && before.nlink === 1n) {
        const handle = await open(absPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW);
        try {
          const opened = await handle.stat({ bigint: true });
          if (opened.dev !== before.dev || opened.ino !== before.ino || opened.mode !== before.mode || opened.nlink !== 1n) {
            throw new Error(`fixed-set member changed during open: ${relPath}`);
          }
          const bytes = await handle.readFile();
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
  if (members.length === 0) throw new TypeError("fixed-set source must contain at least one regular file");
  return { directories, members };
}

async function describeSource(sourceRoot) {
  const root = await canonicalDirectory(sourceRoot, "sourceRoot");
  const closure = await scanDirectory(root.path);
  const source = {
    rootBinding: rootBinding(root.path, root.identity),
    root: root.identity,
    directories: closure.directories,
    closureDigest: digestDocument({ root: root.identity, directories: closure.directories, members: closure.members }),
  };
  return { root, source, members: closure.members };
}

/** Mechanically freezes one sibling-directory publication manifest. */
export async function createFixedSetPublicationManifest({ sourceRoot, targetParent, targetSegment } = {}) {
  const segment = assertSegment(targetSegment, "targetSegment");
  const described = await describeSource(sourceRoot);
  const parent = await canonicalDirectory(targetParent, "targetParent");
  if (path.dirname(described.root.path) !== parent.path) {
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
    rootBinding: rootBinding(parent.path, parent.identity),
    root: parent.identity,
    directories: [],
    closureDigest: digestDocument({ root: parent.identity, directories: [], expectation: "absent", targetSegment: segment }),
    expectation: "absent",
  };
  const unsigned = { schemaVersion: 1, kind: MANIFEST_KIND, source: described.source, target, members: described.members };
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

/** Stable operation. It never falls back to a JavaScript exists+rename sequence. */
export async function publishFixedSet({ sourceRoot, targetParent, targetSegment, manifest } = {}) {
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
      const handle = await open(directory, FS_CONSTANTS.O_RDONLY);
      try { await handle.sync(); } finally { await handle.close(); }
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
