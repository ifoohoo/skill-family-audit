// @feature FND-FR-027
// @decision FND-ADR-034
// @design FND-DES-037
import { createHash } from "node:crypto";
import { constants as FS_CONSTANTS } from "node:fs";
import { lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
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
export const WINDOWS_NATIVE_KEY = "win32-x64";
export const WINDOWS_NATIVE_EXPORTS = Object.freeze([
  "applySecurityMaterial",
  "assignProcessToJob",
  "captureSecurity",
  "closeJob",
  "closeParentDirectory",
  "createKillOnCloseJob",
  "createProtectedDirectory",
  "mutatePreparedDirectory",
  "flushDirectory",
  "flushFileHandle",
  "jobActiveProcessCount",
  "openParentDirectory",
  "observeFilesystemTreeNative",
  "processExitStatus",
  "readPipe",
  "publishProtectedFile",
  "readCapturedFile",
  "readFileBoundNative",
  "renameDirectoryNoReplace",
  "replaceExistingFile",
  "resumePrimaryThread",
  "spawnSuspended",
  "terminateJob",
  "terminateProcess",
  "windowsRestoreCapable",
  "writeFileHandle",
]);

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

export function windowsNativePlatformKey({
  platform = process.platform,
  arch = process.arch,
} = {}) {
  return platform === "win32" && arch === "x64" ? WINDOWS_NATIVE_KEY : null;
}

function acceptWindowsAddon(addon, entry) {
  if (addon?.platform !== "win32" || JSON.stringify(Object.getOwnPropertyNames(addon).sort()) !== JSON.stringify(entry.exports)) fail("win32-x64 native exports differ from the manifest");
  for (const name of WINDOWS_NATIVE_EXPORTS) {
    if (typeof addon[name] !== "function") fail(`win32-x64 native export is missing: ${name}`);
  }
  return Object.freeze({ addon, platform: WINDOWS_NATIVE_KEY, manifestEntry: Object.freeze(entry) });
}

export function loadWindowsNativeAddonSync() {
  if (windowsNativePlatformKey() !== WINDOWS_NATIVE_KEY) fail(`UNSUPPORTED: win32-x64 native addon is not the host runtime ${process.platform}-${process.arch}`);
  let entries;
  try { entries = validateManifest(JSON.parse(readFileSync(MANIFEST_PATH, "utf8"))); } catch (cause) { fail(`prebuild manifest cannot be loaded: ${cause.message}`); }
  verifyClosureSync(entries);
  const entry = entries.find(item => item.platformKey === WINDOWS_NATIVE_KEY);
  if (!entry) fail("UNSUPPORTED: fixed platform matrix has no win32-x64 prebuild");
  const binaryPath = path.join(PACKAGE_ROOT, entry.binary);
  const before = lstatSync(binaryPath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || digest(readFileSync(binaryPath)) !== entry.sha256) fail("win32-x64 prebuild identity or digest mismatch");
  const packageReal = realpathSync(PACKAGE_ROOT);
  const binaryReal = realpathSync(binaryPath);
  if (!binaryReal.startsWith(`${packageReal}${path.sep}`)) fail("win32-x64 prebuild escapes package root");
  let addon;
  try { addon = createRequire(import.meta.url)(binaryReal); } catch (cause) { throw new Error(`filesystemBoundRead: win32-x64 native load failed: ${cause.message}`, { cause }); }
  const after = lstatSync(binaryPath);
  if (after.dev !== before.dev || after.ino !== before.ino || after.nlink !== 1 || digest(readFileSync(binaryPath)) !== entry.sha256) fail("win32-x64 prebuild changed during load");
  return acceptWindowsAddon(addon, entry);
}

export async function loadWindowsNativeAddon() {
  // The private-directory and process paths also need a synchronous bootstrap;
  // both entry points therefore consume exactly the same verified distribution.
  return loadWindowsNativeAddonSync();
}

function validateManifest(document) {
  const keys = document?.entries?.map(entry => entry.platformKey);
  const validMatrix = JSON.stringify(keys) === JSON.stringify(PLATFORM_KEYS) || JSON.stringify(keys) === JSON.stringify([...PLATFORM_KEYS, WINDOWS_NATIVE_KEY]);
  if (Object.keys(document ?? {}).sort().join(",") !== "entries,kind,schemaVersion,status" || document.schemaVersion !== 1 ||
      document.kind !== "skill-family.filesystem-bound-read-prebuild-manifest" || document.status !== "stable" || !validMatrix) fail("prebuild manifest has an unexpected fixed matrix");
  for (const entry of document.entries) {
    const windows = entry.platformKey === WINDOWS_NATIVE_KEY;
    const expected = windows ? { os: "win32", arch: "x64", libc: "none" } : entry.platformKey.startsWith("darwin-")
      ? { os: "darwin", arch: entry.platformKey.slice("darwin-".length), libc: "none" }
      : { os: "linux", arch: entry.platformKey.slice("linux-".length, -"-gnu".length), libc: "glibc" };
    const exports = windows ? ["platform", ...WINDOWS_NATIVE_EXPORTS].sort() : EXPECTED_EXPORTS;
    if (Object.keys(entry ?? {}).sort().join(",") !== "arch,binary,exports,libc,mode,napi,os,platformKey,sha256" ||
        entry.os !== expected.os || entry.arch !== expected.arch || entry.libc !== expected.libc || entry.napi !== 10 ||
        entry.binary !== `prebuilds/${entry.platformKey}/bound_read.${entry.platformKey}.node` || entry.mode !== 0o644 ||
        !SHA256_PATTERN.test(entry.sha256 ?? "") || JSON.stringify(entry.exports) !== JSON.stringify(exports)) fail(`prebuild manifest entry is invalid: ${entry.platformKey}`);
  }
  return document.entries;
}

function verifyClosureSync(entries) {
  const root = path.join(PACKAGE_ROOT, "prebuilds");
  const rootStats = lstatSync(root);
  if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) fail("prebuild root is not an ordinary directory");
  if (JSON.stringify(readdirSync(root).sort()) !== JSON.stringify(entries.map(item => item.platformKey).sort())) fail("prebuild directory is not the fixed matrix");
  for (const entry of entries) {
    const directory = path.join(root, entry.platformKey);
    const stats = lstatSync(directory);
    if (!stats.isDirectory() || stats.isSymbolicLink() || JSON.stringify(readdirSync(directory).sort()) !== JSON.stringify([path.basename(entry.binary)])) fail(`${entry.platformKey} closure is not exact`);
  }
}

async function parseManifest() {
  let document;
  try { document = JSON.parse(await readFile(MANIFEST_PATH, "utf8")); } catch { fail("prebuild manifest is not valid JSON"); }
  return validateManifest(document);
}

async function verifyClosure(entries) { verifyClosureSync(entries); }

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
