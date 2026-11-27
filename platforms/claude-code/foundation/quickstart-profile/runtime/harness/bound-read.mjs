// @feature FND-FR-026
// @feature FND-FR-027
// @decision FND-ADR-034
// @design FND-DES-035
// @design FND-DES-037
import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { digestDocument } from "../contracts/index.mjs";
import { digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, HarnessError, mechanismError } from "./errors.mjs";
import { canonicalizeWindowsDriveAbsolute, classifyPathInput } from "./paths.mjs";
import { loadNativeBoundReadAddon, loadWindowsNativeAddon } from "./native/loader.mjs";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const ROOT_BINDING_KIND = "trusted-filesystem-root-binding";
const ROOT_BINDING_BASIS = "canonical-realpath-device-inode-type-mode-v1";
const WINDOWS_ROOT_BINDING_BASIS = "canonical-finalpath-volume-fileid-type-security-v1";

function supportedPlatform() {
  if (process.platform === "darwin" && ["arm64", "x64"].includes(process.arch)) {
    return true;
  }
  if (process.platform === "linux" && ["arm64", "x64"].includes(process.arch) &&
      typeof process.report?.getReport?.()?.header?.glibcVersionRuntime === "string") {
    return true;
  }
  return false;
}

function assertSupportedPlatform() {
  if (!supportedPlatform()) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSUPPORTED_PLATFORM,
      "bound filesystem reads are unsupported on this runtime",
    );
  }
}

function assertCanonicalAbsolute(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) ||
      value.includes("\\") || value.includes("\0") || path.normalize(value) !== value) {
    throw new TypeError(`${label} must be a normalized absolute path`);
  }
}

function assertRootBindingShape(binding) {
  if (binding === null || typeof binding !== "object" || Array.isArray(binding) ||
      Object.keys(binding).sort().join(",") !== "basis,digest,digestAlgorithm,kind" ||
      binding.kind !== ROOT_BINDING_KIND ||
      binding.digestAlgorithm !== "sha256" ||
      (binding.basis !== ROOT_BINDING_BASIS && binding.basis !== WINDOWS_ROOT_BINDING_BASIS) ||
      typeof binding.digest !== "string" || !SHA256_PATTERN.test(binding.digest)) {
    throw new TypeError("rootBinding is not a filesystem-root-binding value");
  }
}

function identityFromStats(stats) {
  return {
    type: "directory",
    mode: Number(stats.mode & 0o777n),
    device: String(stats.dev),
    inode: String(stats.ino),
  };
}

function makeBinding(canonicalPath, identity) {
  return Object.freeze({
    kind: ROOT_BINDING_KIND,
    digestAlgorithm: "sha256",
    basis: ROOT_BINDING_BASIS,
    digest: digestDocument({
      canonicalRealpath: canonicalPath,
      device: identity.device,
      inode: identity.inode,
      mode: identity.mode,
      type: identity.type,
    }),
  });
}

function openFlags(directory) {
  const noFollow = FS_CONSTANTS.O_NOFOLLOW;
  if (noFollow === undefined || FS_CONSTANTS.O_DIRECTORY === undefined) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSUPPORTED_PLATFORM,
      "bound filesystem reads require O_NOFOLLOW and O_DIRECTORY",
    );
  }
  return FS_CONSTANTS.O_RDONLY | noFollow | (directory ? FS_CONSTANTS.O_DIRECTORY : 0) |
    (FS_CONSTANTS.O_CLOEXEC ?? 0);
}

function mapOpenFailure(cause, relPath, label) {
  if (cause instanceof HarnessError) throw cause;
  if (cause?.code === "ELOOP") {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      `${label} became a symbolic link during bound read`,
      { input: relPath },
    );
  }
  if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") {
    throw mechanismError(
      HARNESS_ERROR_KINDS.MISSING_RESOURCE,
      `${label} does not exist during bound read`,
      { input: relPath },
    );
  }
  throw mechanismError(
    HARNESS_ERROR_KINDS.READ_FAILED,
    `${label} could not be opened: ${cause?.code ?? "unknown"}`,
    { input: relPath },
  );
}

async function captureRoot(root) {
  assertCanonicalAbsolute(root, "root");
  let before;
  try {
    before = await lstat(root, { bigint: true });
  } catch (cause) {
    throw mechanismError(HARNESS_ERROR_KINDS.INVALID_ROOT, "root cannot be inspected", {
      code: cause?.code,
    });
  }
  if (before.isSymbolicLink() || !before.isDirectory()) {
    throw mechanismError(HARNESS_ERROR_KINDS.INVALID_ROOT, "root must be one real directory");
  }
  let canonical;
  try {
    canonical = await realpath(root);
  } catch (cause) {
    throw mechanismError(HARNESS_ERROR_KINDS.INVALID_ROOT, "root canonical path cannot be resolved", {
      code: cause?.code,
    });
  }
  if (canonical !== root) {
    throw mechanismError(HARNESS_ERROR_KINDS.INVALID_ROOT, "root must already be its canonical realpath");
  }
  let handle;
  try {
    handle = await open(canonical, openFlags(true));
  } catch (cause) {
    mapOpenFailure(cause, "", "root");
  }
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isDirectory() || opened.dev !== before.dev || opened.ino !== before.ino ||
        opened.mode !== before.mode) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "root identity changed during capture");
    }
    return { canonical, identity: identityFromStats(opened), handle };
  } catch (cause) {
    await handle.close();
    throw cause;
  }
}

function windowsRootBinding(canonicalFinalPath, volumeSerial, fileId, securityDigest) {
  return Object.freeze({
    kind: ROOT_BINDING_KIND,
    digestAlgorithm: "sha256",
    basis: WINDOWS_ROOT_BINDING_BASIS,
    digest: digestDocument({
      canonicalFinalPath,
      volumeSerial,
      fileId,
      type: "directory",
      securityDigest,
    }),
  });
}

function permissionObservation(attributes, descriptor) {
  return Object.freeze({
    kind: "windows-security-v1",
    attributes: Number(attributes) >>> 0,
    securityDigest: digestBytes(Buffer.from(descriptor)),
  });
}

async function createWindowsRootBinding(root) {
  const requested = canonicalizeWindowsDriveAbsolute(root);
  if (requested === null) throw new TypeError("root must be a canonical Windows drive path");
  const loaded = await loadWindowsNativeAddon();
  const captured = loaded.addon.captureSecurity(requested);
  const canonicalFinalPath = canonicalizeWindowsDriveAbsolute(captured?.canonicalPath);
  if (!captured?.ok || canonicalFinalPath === null || (Number(captured.attributes) & 0x410) !== 0x10 || !Buffer.isBuffer(captured.securityDescriptor)) {
    throw mechanismError(HARNESS_ERROR_KINDS.INVALID_ROOT, "Windows root security descriptor could not be captured");
  }
  const observation = permissionObservation(captured.attributes, captured.securityDescriptor);
  return windowsRootBinding(canonicalFinalPath, captured.volumeSerial, captured.fileId, observation.securityDigest);
}

export async function createFilesystemRootBinding(root) {
  if (process.platform === "win32") return createWindowsRootBinding(root);
  assertSupportedPlatform();
  const captured = await captureRoot(root);
  try {
    return makeBinding(captured.canonical, captured.identity);
  } finally {
    await captured.handle.close();
  }
}

export function assertRelativePath(relPath) {
  if (typeof relPath !== "string" || relPath.length === 0 || relPath.includes("\0") ||
      relPath.includes("\\") || path.posix.isAbsolute(relPath)) {
    throw mechanismError(HARNESS_ERROR_KINDS.INVALID_PATH, "bound read path is not a contained relative path");
  }
  const segments = relPath.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    throw mechanismError(HARNESS_ERROR_KINDS.PATH_TRAVERSAL, "bound read path contains an unsafe segment");
  }
  if (segments.some((segment) => /^[A-Za-z]:/u.test(segment))) {
    throw mechanismError(HARNESS_ERROR_KINDS.WINDOWS_DRIVE_PATH, "bound read path contains a drive path");
  }
  return segments;
}

// The only closed set of native failure reasons that can prove a static
// member policy violation. Anything else — unknown reasons, missing root
// identity, root identity drift, or "native-io" — stays
// boundary-indeterminate. This set is the stable branching fact between the
// harness and the Kit; it must never be derived from errno values or error
// messages.
const MEMBER_POLICY_FAILURE_REASONS = Object.freeze([
  "member-missing",
  "intermediate-not-real-directory",
  "leaf-symbolic-link",
  "leaf-not-regular",
  "leaf-multiple-links",
]);
const MEMBER_POLICY_FAILURE_REASON_SET = new Set(MEMBER_POLICY_FAILURE_REASONS);

function nativeBoundReadDisposition(native, captured) {
  if (process.platform === "win32") {
    if (native?.rootVolumeSerial !== captured.volumeSerial || native?.rootFileId !== captured.fileId ||
        native?.rootCanonicalPath !== captured.canonicalPath || native?.rootAttributes !== captured.attributes ||
        !Buffer.isBuffer(native.rootSecurityDescriptor) || !Buffer.isBuffer(captured.securityDescriptor) ||
        !native.rootSecurityDescriptor.equals(captured.securityDescriptor)) return "boundary-indeterminate";
    const reason = ({ "member-missing": "member-missing", "not-directory": "intermediate-not-real-directory",
      reparse: "leaf-symbolic-link", "not-regular": "leaf-not-regular" })[native.failureReason];
    return MEMBER_POLICY_FAILURE_REASON_SET.has(reason) ? "member-policy-violation" : "boundary-indeterminate";
  }
  if (native?.rootDevice !== captured.identity.device || native?.rootInode !== captured.identity.inode ||
      Number(native?.rootMode) !== captured.identity.mode) {
    return "boundary-indeterminate";
  }
  return MEMBER_POLICY_FAILURE_REASON_SET.has(native?.failureReason)
    ? "member-policy-violation"
    : "boundary-indeterminate";
}

function assertWindowsMemberPath(relPath, platform) {
  if (platform !== "win32") return;
  const classification = classifyPathInput(relPath, "win32");
  if (!classification.ok) {
    throw mechanismError(
      classification.kind,
      "bound read path is not a contained Windows relative path",
      { input: typeof relPath === "string" ? relPath : typeof relPath },
    );
  }
}

function throwWindowsReadFailure(reason, relPath, actual, boundReadDisposition) {
  const details = { input: relPath, ...(boundReadDisposition === undefined ? {} : { boundReadDisposition }), ...(actual === "directory" ? { actual } : {}) };
  if (reason === "case-alias" || reason === "invalid-path") {
    throw mechanismError(HARNESS_ERROR_KINDS.INVALID_PATH, "bound read refuses the path and returns no bytes", {
      ...details,
      failureReason: reason,
    });
  }
  if (reason === "reparse" || reason === "leaf-symbolic-link" || reason === "not-regular" || reason === "cross-volume") {
    throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "bound read refuses the path and returns no bytes", {
      ...details,
      failureReason: reason,
    });
  }
  if (reason === "member-missing") {
    throw mechanismError(HARNESS_ERROR_KINDS.MISSING_RESOURCE, "bound path does not exist during read", details);
  }
  throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, `bound path could not be read: ${reason ?? "native-io"}`, details);
}

function assertReadOptions(encoding, expectedSha256) {
  if (encoding !== undefined && encoding !== "utf8") {
    throw new TypeError('readFileBound: encoding must be "utf8" or undefined');
  }
  if (expectedSha256 !== undefined &&
      (typeof expectedSha256 !== "string" || !SHA256_PATTERN.test(expectedSha256))) {
    throw new TypeError("readFileBound: expectedSha256 must be a lowercase sha256 hex digest");
  }
}

function freezeReadReceipt({ path: filePath, bytes, encoding, sha256, mode, statMode, rootMode, permissionObservation: observation, rootPermissionObservation, securityDescriptor }) {
  return Object.freeze({
    path: filePath,
    content: encoding === "utf8" ? bytes.toString("utf8") : bytes,
    sha256,
    bytes: bytes.length,
    mode,
    statMode,
    rootMode,
    ...(observation === undefined ? {} : { permissionObservation: observation }),
    ...(rootPermissionObservation === undefined ? {} : { rootPermissionObservation }),
    ...(securityDescriptor === undefined ? {} : { securityDescriptor }),
  });
}

async function readAnchoredFromRoot(rootCanonical, rootDevice, relPath) {
  const segments = relPath.split("/");
  let directory = rootCanonical;
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    let names;
    try {
      names = await readdir(directory);
    } catch (cause) {
      throwWindowsReadFailure(cause?.code === "ENOENT" ? "member-missing" : "native-io", relPath);
    }
    if (!names.includes(segment)) {
      const folded = names.some((name) => name.toLowerCase() === segment.toLowerCase());
      throwWindowsReadFailure(folded ? "case-alias" : "member-missing", relPath);
    }
    const child = path.join(directory, segment);
    let stats;
    try {
      stats = await lstat(child, { bigint: true });
    } catch (cause) {
      throwWindowsReadFailure(cause?.code === "ENOENT" ? "member-missing" : "native-io", relPath);
    }
    if (stats.isSymbolicLink()) throwWindowsReadFailure("reparse", relPath);
    if (String(stats.dev) !== rootDevice) throwWindowsReadFailure("cross-volume", relPath);
    const last = index === segments.length - 1;
    if (!last) {
      if (!stats.isDirectory()) throwWindowsReadFailure("intermediate-not-real-directory", relPath);
      directory = child;
      continue;
    }
    if (!stats.isFile() || stats.nlink !== 1n) throwWindowsReadFailure("not-regular", relPath);
    const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
    const handle = await open(child, FS_CONSTANTS.O_RDONLY | noFollow);
    try {
      const opened = await handle.stat({ bigint: true });
      if (opened.dev !== stats.dev || opened.ino !== stats.ino || !opened.isFile() || opened.nlink !== 1n) {
        throwWindowsReadFailure("reparse", relPath);
      }
      return { bytes: await handle.readFile(), path: child };
    } finally {
      await handle.close();
    }
  }
  throwWindowsReadFailure("member-missing", relPath);
}

async function readFileBoundWindows(root, relPath, { rootBinding, encoding, expectedSha256 }) {
  if (process.platform === "win32") {
    const canonicalRoot = canonicalizeWindowsDriveAbsolute(root);
    if (canonicalRoot === null) throw new TypeError("root must be a canonical Windows drive path");
    root = canonicalRoot;
  } else {
    assertCanonicalAbsolute(root, "root");
  }
  assertRelativePath(relPath);
  assertReadOptions(encoding, expectedSha256);
  if (process.platform === "win32") {
    const loaded = await loadWindowsNativeAddon();
    const captured = loaded.addon.captureSecurity(root);
    if (!captured?.ok || !Buffer.isBuffer(captured.securityDescriptor)) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "approved root cannot be verified before bound read", {
        input: relPath, boundReadDisposition: "boundary-indeterminate",
      });
    }
    const canonicalFinalPath = canonicalizeWindowsDriveAbsolute(captured.canonicalPath);
    if (canonicalFinalPath === null) throwWindowsReadFailure("native-io", relPath);
    const observation = permissionObservation(captured.attributes, captured.securityDescriptor);
    const binding = windowsRootBinding(canonicalFinalPath, captured.volumeSerial, captured.fileId, observation.securityDigest);
    if (rootBinding?.digest !== binding.digest || rootBinding?.basis !== WINDOWS_ROOT_BINDING_BASIS) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "approved root binding does not match the current root", {
        input: relPath,
        boundReadDisposition: "boundary-indeterminate",
      });
    }
    const native = loaded.addon.readFileBoundNative(root, relPath.split("/"));
    if (!native?.ok || !Buffer.isBuffer(native.bytes) || !Buffer.isBuffer(native.securityDescriptor)) {
      throwWindowsReadFailure(native?.failureReason ?? "native-io", relPath, native?.actual, nativeBoundReadDisposition(native, captured));
    }
    if (native.rootVolumeSerial !== captured.volumeSerial || native.rootFileId !== captured.fileId) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "root identity changed during bound read", {
        input: relPath,
        boundReadDisposition: "boundary-indeterminate",
      });
    }
    const memberCanonical = canonicalizeWindowsDriveAbsolute(native.canonicalPath);
    if (memberCanonical === null || path.posix.basename(memberCanonical) !== path.posix.basename(relPath)) {
      throwWindowsReadFailure("native-io", relPath);
    }
    if (!Buffer.isBuffer(native.rootSecurityDescriptor)) throwWindowsReadFailure("native-io", relPath);
    const rootObservation = permissionObservation(native.rootAttributes, native.rootSecurityDescriptor);
    if (rootObservation.securityDigest !== observation.securityDigest || native.rootAttributes !== captured.attributes) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "root security changed during bound read", {
        input: relPath,
        boundReadDisposition: "boundary-indeterminate",
      });
    }
    const bytes = Buffer.from(native.bytes);
    const sha256 = digestBytes(bytes);
    if (expectedSha256 !== undefined && sha256 !== expectedSha256) {
      throw mechanismError(HARNESS_ERROR_KINDS.CONTENT_GUARD_REJECTED, "bound read digest differs from the expected frozen digest", {
        input: relPath,
        expectedSha256,
        actualSha256: sha256,
      });
    }
    return freezeReadReceipt({
      path: memberCanonical,
      rootPermissionObservation: rootObservation,
      bytes,
      encoding,
      sha256,
      mode: null,
      statMode: null,
      rootMode: null,
      permissionObservation: permissionObservation(native.attributes, native.securityDescriptor),
      securityDescriptor: Buffer.from(native.securityDescriptor),
    });
  }
  assertRootBindingShape(rootBinding);
  const captured = await captureRoot(root);
  try {
    const currentBinding = makeBinding(captured.canonical, captured.identity);
    if (currentBinding.digest !== rootBinding.digest) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "approved root binding does not match the current root", {
        input: relPath,
        boundReadDisposition: "boundary-indeterminate",
      });
    }
    const read = await readAnchoredFromRoot(captured.canonical, captured.identity.device, relPath);
    const sha256 = digestBytes(read.bytes);
    if (expectedSha256 !== undefined && sha256 !== expectedSha256) {
      throw mechanismError(HARNESS_ERROR_KINDS.CONTENT_GUARD_REJECTED, "bound read digest differs from the expected frozen digest", {
        input: relPath,
        expectedSha256,
        actualSha256: sha256,
      });
    }
    return freezeReadReceipt({
      path: read.path,
      bytes: read.bytes,
      encoding,
      sha256,
      mode: null,
      statMode: null,
      rootMode: null,
    });
  } finally {
    await captured.handle.close().catch(() => {});
  }
}

export async function readWindowsContainedFile(root, relPath, { encoding, expectedSha256 } = {}) {
  const rootBinding = await createFilesystemRootBinding(root);
  let receipt;
  try {
    receipt = await readFileBound(root, relPath, { rootBinding, encoding, expectedSha256, platform: "win32" });
  } catch (cause) {
    if (cause?.code === "SFC2004" && cause.details?.kind === HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY
        && cause.details?.actual === "directory") {
      throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, "strict read requires one ordinary file", {
        input: relPath, actual: "directory",
      });
    }
    throw cause;
  }
  return Object.freeze({
    path: receipt.path,
    content: receipt.content,
    sha256: receipt.sha256,
    bytes: receipt.bytes,
    mode: receipt.mode,
  });
}

export async function readFileBound(root, relPath, options = {}) {
  const { rootBinding, encoding, expectedSha256, platform = process.platform } = options;
  assertWindowsMemberPath(relPath, platform);
  if (platform === "win32") {
    return readFileBoundWindows(root, relPath, { rootBinding, encoding, expectedSha256 });
  }
  assertSupportedPlatform();
  assertCanonicalAbsolute(root, "root");
  assertRelativePath(relPath);
  assertRootBindingShape(rootBinding);
  if (encoding !== undefined && encoding !== "utf8") {
    throw new TypeError('readFileBound: encoding must be "utf8" or undefined');
  }
  if (expectedSha256 !== undefined &&
      (typeof expectedSha256 !== "string" || !SHA256_PATTERN.test(expectedSha256))) {
    throw new TypeError("readFileBound: expectedSha256 must be a lowercase sha256 hex digest");
  }

  const segments = relPath.split("/");
  const captured = await captureRoot(root);
  try {
    const currentBinding = makeBinding(captured.canonical, captured.identity);
    if (currentBinding.digest !== rootBinding.digest) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
        "approved root binding does not match the current root",
        { boundReadDisposition: "boundary-indeterminate" },
      );
    }
    const { addon } = await loadNativeBoundReadAddon();
    const native = addon.readFileBoundNative(captured.canonical, segments);
    if (!native?.ok) {
      // Disposition is decided only by the two documented conditions: the
      // native root identity must equal the captured binding, and the native
      // failureReason must be one of the five closed-set member policy
      // reasons. The reason also selects the stable details.kind; it is never
      // derived from errno values or error messages.
      const boundReadDisposition = nativeBoundReadDisposition(native, captured);
      const details = { input: relPath, boundReadDisposition };
      const reason = native?.failureReason;
      if (reason === "intermediate-not-real-directory") {
        throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "an intermediate component is not a real directory", details);
      }
      if (reason === "leaf-symbolic-link") {
        throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "bound path became a symbolic link during read", details);
      }
      if (reason === "member-missing") {
        throw mechanismError(HARNESS_ERROR_KINDS.MISSING_RESOURCE, "bound path does not exist during read", details);
      }
      throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, `bound path could not be read: ${reason ?? "native-io"}`, details);
    }
    if (native.rootDevice !== captured.identity.device || native.rootInode !== captured.identity.inode ||
        Number(native.rootMode) !== captured.identity.mode) {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "root identity changed during bound read", {
        input: relPath,
        boundReadDisposition: "boundary-indeterminate",
      });
    }
    const bytes = Buffer.from(native.bytes);
    const sha256 = digestBytes(bytes);
    if (expectedSha256 !== undefined && sha256 !== expectedSha256) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.CONTENT_GUARD_REJECTED,
        "bound read digest differs from the expected frozen digest",
        { input: relPath, expectedSha256, actualSha256: sha256 },
      );
    }
    return Object.freeze({
      path: path.join(captured.canonical, ...segments),
      content: encoding === "utf8" ? bytes.toString("utf8") : bytes,
      sha256,
      bytes: bytes.length,
      mode: Number(native.leafMode),
      statMode: Number(native.statMode),
      rootMode: captured.identity.mode,
    });
  } finally {
    await captured.handle.close().catch(() => {});
  }
}
