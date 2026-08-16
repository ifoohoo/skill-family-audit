import { createHash } from "node:crypto";
import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open, readFile, readdir, realpath } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = path.join(PACKAGE_ROOT, "prebuild-manifest.json");
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const EXPECTED_EXPORTS = Object.freeze([
  "closeParentDirectory",
  "openParentDirectory",
  "platform",
  "renameDirectoryNoReplace",
]);
const PLATFORM_KEYS = Object.freeze([
  "darwin-arm64",
  "darwin-x64",
  "linux-arm64-gnu",
  "linux-x64-gnu",
]);

function fail(message) {
  throw new Error(`renameDirectoryNoReplace: ${message}`);
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseManifest(text) {
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    fail("prebuild manifest is not valid JSON");
  }
  const keys = Object.keys(document ?? {}).sort().join(",");
  if (keys !== "entries,kind,schemaVersion,status" || document.schemaVersion !== 2 ||
      document.kind !== "skill-family.rename-directory-no-replace-prebuild-manifest" ||
      document.status !== "candidate" || !Array.isArray(document.entries) || document.entries.length !== 4) {
    fail("prebuild manifest has an unexpected shape");
  }
  if (JSON.stringify(document.entries.map((entry) => entry.platformKey)) !== JSON.stringify(PLATFORM_KEYS)) {
    fail("prebuild manifest platform keys are not the fixed candidate matrix");
  }
  for (const entry of document.entries) {
    const expected = entry.platformKey.startsWith("darwin-")
      ? { os: "darwin", arch: entry.platformKey.slice("darwin-".length), libc: "none" }
      : { os: "linux", arch: entry.platformKey.slice("linux-".length, -"-gnu".length), libc: "glibc" };
    if (Object.keys(entry ?? {}).sort().join(",") !== "arch,binary,exports,libc,mode,napi,os,platformKey,sha256" ||
        entry.os !== expected.os || entry.arch !== expected.arch || entry.libc !== expected.libc || entry.napi !== 10 ||
        entry.binary !== `prebuilds/${entry.platformKey}/rename_directory_no_replace.${entry.platformKey}.node` ||
        entry.mode !== 0o644 || !SHA256_PATTERN.test(entry.sha256 ?? "") ||
        JSON.stringify(entry.exports) !== JSON.stringify(EXPECTED_EXPORTS)) {
      fail(`prebuild manifest entry is invalid: ${entry.platformKey}`);
    }
  }
  return document.entries;
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size;
}

async function assertExactPrebuildClosure(entries) {
  const platformDirectories = (await readdir(path.join(PACKAGE_ROOT, "prebuilds"))).sort();
  if (JSON.stringify(platformDirectories) !== JSON.stringify([...PLATFORM_KEYS].sort())) {
    fail("prebuild directory contains an unexpected platform entry");
  }
  for (const entry of entries) {
    const platformMembers = (await readdir(path.join(PACKAGE_ROOT, "prebuilds", entry.platformKey))).sort();
    if (JSON.stringify(platformMembers) !== JSON.stringify([path.basename(entry.binary)])) {
      fail(`${entry.platformKey} prebuild directory is not the exact fixed closure`);
    }
  }
}

export function candidatePlatformKey({ platform, arch, glibcVersionRuntime }) {
  if (platform === "darwin" && ["arm64", "x64"].includes(arch)) return `darwin-${arch}`;
  if (platform === "linux" && ["arm64", "x64"].includes(arch)) {
    if (typeof glibcVersionRuntime === "string" && glibcVersionRuntime.length > 0) return `linux-${arch}-gnu`;
  }
  return null;
}

export async function loadNativeAddon() {
  const entries = parseManifest(await readFile(MANIFEST_PATH, "utf8"));
  const platformKey = candidatePlatformKey({
    platform: process.platform,
    arch: process.arch,
    glibcVersionRuntime: process.report?.getReport?.()?.header?.glibcVersionRuntime,
  });
  const entry = entries.find((candidate) => candidate.platformKey === platformKey);
  if (!entry) fail(`UNSUPPORTED: fixed candidate matrix has no runtime ${process.platform}-${process.arch}`);
  if (FS_CONSTANTS.O_NOFOLLOW === undefined) fail("O_NOFOLLOW is unavailable");
  await assertExactPrebuildClosure(entries);

  const binaryPath = path.join(PACKAGE_ROOT, entry.binary);
  const beforeLink = await lstat(binaryPath);
  if (beforeLink.isSymbolicLink() || !beforeLink.isFile() || beforeLink.nlink !== 1 ||
      (beforeLink.mode & 0o777) !== entry.mode) {
    fail("prebuild must be one ordinary non-symlink file with exact mode and nlink=1");
  }
  const packageReal = await realpath(PACKAGE_ROOT);
  const binaryReal = await realpath(binaryPath);
  if (!binaryReal.startsWith(`${packageReal}${path.sep}`)) fail("prebuild realpath escapes package root");

  const handle = await open(binaryPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW);
  let opened;
  try {
    opened = await handle.stat();
    if (!sameFile(beforeLink, opened)) fail("prebuild identity changed during open");
    if (digest(await handle.readFile()) !== entry.sha256) fail("prebuild sha256 mismatch");
  } finally {
    await handle.close();
  }

  let addon;
  try {
    addon = createRequire(import.meta.url)(binaryReal);
  } catch (cause) {
    throw new Error(`renameDirectoryNoReplace: native load failed: ${cause?.message ?? "unknown"}`, { cause });
  }
  const actualExports = Object.keys(addon).sort();
  if (JSON.stringify(actualExports) !== JSON.stringify(EXPECTED_EXPORTS) ||
      addon.platform !== entry.os || typeof addon.openParentDirectory !== "function" ||
      typeof addon.closeParentDirectory !== "function" || typeof addon.renameDirectoryNoReplace !== "function") {
    fail("native exports do not match the fixed manifest");
  }

  const after = await lstat(binaryPath);
  if (!sameFile(opened, after) || digest(await readFile(binaryPath)) !== entry.sha256) {
    fail("prebuild identity or bytes changed during load");
  }
  return Object.freeze({ addon, platform: platformKey, manifestEntry: Object.freeze(entry) });
}
