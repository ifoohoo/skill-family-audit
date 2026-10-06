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
const EXPECTED_EXPORTS = Object.freeze(["closeParentDirectory", "exchangeDirectories", "observeFilesystemTreeNative", "openParentDirectory", "platform", "readFileBoundNative", "renameDirectoryNoReplace"]);
const PLATFORM_KEYS = Object.freeze(["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]);

function fail(message) {
  throw new Error(`filesystemBoundRead: ${message}`);
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function stableNativePlatformKey({
  platform = process.platform,
  arch = process.arch,
  glibcVersionRuntime = process.report?.getReport?.()?.header?.glibcVersionRuntime,
} = {}) {
  if (platform === "darwin" && ["arm64", "x64"].includes(arch)) return `darwin-${arch}`;
  if (platform === "linux" && ["arm64", "x64"].includes(arch) &&
      typeof glibcVersionRuntime === "string") {
    return `linux-${arch}-gnu`;
  }
  return null;
}

async function parseManifest() {
  let document;
  try { document = JSON.parse(await readFile(MANIFEST_PATH, "utf8")); } catch { fail("prebuild manifest is not valid JSON"); }
  if (Object.keys(document ?? {}).sort().join(",") !== "entries,kind,schemaVersion,status" ||
      document.schemaVersion !== 1 || document.kind !== "skill-family.filesystem-bound-read-prebuild-manifest" ||
      document.status !== "stable" || !Array.isArray(document.entries) || document.entries.length !== 4 ||
      JSON.stringify(document.entries.map((entry) => entry.platformKey)) !== JSON.stringify(PLATFORM_KEYS)) {
    fail("prebuild manifest has an unexpected fixed matrix");
  }
  for (const entry of document.entries) {
    const expected = entry.platformKey.startsWith("darwin-")
      ? { os: "darwin", arch: entry.platformKey.slice("darwin-".length), libc: "none" }
      : { os: "linux", arch: entry.platformKey.slice("linux-".length, -"-gnu".length), libc: "glibc" };
    if (Object.keys(entry ?? {}).sort().join(",") !== "arch,binary,exports,libc,mode,napi,os,platformKey,sha256" ||
        entry.os !== expected.os || entry.arch !== expected.arch || entry.libc !== expected.libc || entry.napi !== 10 ||
        entry.binary !== `prebuilds/${entry.platformKey}/bound_read.${entry.platformKey}.node` || entry.mode !== 0o644 ||
        !SHA256_PATTERN.test(entry.sha256 ?? "") || JSON.stringify(entry.exports) !== JSON.stringify(EXPECTED_EXPORTS)) {
      fail(`prebuild manifest entry is invalid: ${entry.platformKey}`);
    }
  }
  return document.entries;
}

async function verifyClosure(entries) {
  const directories = (await readdir(path.join(PACKAGE_ROOT, "prebuilds"))).sort();
  if (JSON.stringify(directories) !== JSON.stringify([...PLATFORM_KEYS].sort())) fail("prebuild directory is not the fixed matrix");
  for (const entry of entries) {
    const members = (await readdir(path.join(PACKAGE_ROOT, "prebuilds", entry.platformKey))).sort();
    if (JSON.stringify(members) !== JSON.stringify([path.basename(entry.binary)])) fail(`${entry.platformKey} closure is not exact`);
  }
}

export async function loadNativeBoundReadAddon() {
  if (FS_CONSTANTS.O_NOFOLLOW === undefined || FS_CONSTANTS.O_DIRECTORY === undefined) fail("required no-follow flags are unavailable");
  const entries = await parseManifest();
  await verifyClosure(entries);
  const key = stableNativePlatformKey();
  const entry = entries.find((candidate) => candidate.platformKey === key);
  if (!entry) fail(`UNSUPPORTED: fixed platform matrix has no runtime ${process.platform}-${process.arch}`);
  const binaryPath = path.join(PACKAGE_ROOT, entry.binary);
  const before = await lstat(binaryPath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (before.mode & 0o777) !== entry.mode) fail("prebuild is not one ordinary exact-mode file");
  const packageReal = await realpath(PACKAGE_ROOT);
  const binaryReal = await realpath(binaryPath);
  if (!binaryReal.startsWith(`${packageReal}${path.sep}`)) fail("prebuild escapes package root");
  const handle = await open(binaryPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW);
  let opened;
  try {
    opened = await handle.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.mode !== before.mode || opened.nlink !== before.nlink || digest(await handle.readFile()) !== entry.sha256) fail("prebuild identity or digest mismatch");
  } finally { await handle.close(); }
  let addon;
  try { addon = createRequire(import.meta.url)(binaryReal); } catch (cause) { throw new Error(`filesystemBoundRead: native load failed: ${cause?.message ?? "unknown"}`, { cause }); }
  if (JSON.stringify(Object.keys(addon).sort()) !== JSON.stringify([...EXPECTED_EXPORTS].sort()) || addon.platform !== entry.os ||
      typeof addon.readFileBoundNative !== "function" || typeof addon.openParentDirectory !== "function" ||
      typeof addon.closeParentDirectory !== "function" || typeof addon.exchangeDirectories !== "function" ||
      typeof addon.renameDirectoryNoReplace !== "function") {
    fail("native exports do not match the fixed manifest");
  }
  const after = await lstat(binaryPath);
  if (after.dev !== opened.dev || after.ino !== opened.ino || after.mode !== opened.mode || digest(await readFile(binaryPath)) !== entry.sha256) fail("prebuild changed during load");
  return Object.freeze({ addon, platform: key, manifestEntry: Object.freeze(entry) });
}
