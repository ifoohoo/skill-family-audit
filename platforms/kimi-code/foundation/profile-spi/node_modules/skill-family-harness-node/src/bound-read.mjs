import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { digestDocument } from "skill-family-contracts";
import { digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, HarnessError, mechanismError } from "./errors.mjs";
import { loadNativeBoundReadAddon } from "./native/loader.mjs";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const ROOT_BINDING_KIND = "trusted-filesystem-root-binding";
const ROOT_BINDING_BASIS = "canonical-realpath-device-inode-type-mode-v1";

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
      binding.basis !== ROOT_BINDING_BASIS ||
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

export async function createFilesystemRootBinding(root) {
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
  if (native?.rootDevice !== captured.identity.device || native?.rootInode !== captured.identity.inode ||
      Number(native?.rootMode) !== captured.identity.mode) {
    return "boundary-indeterminate";
  }
  return MEMBER_POLICY_FAILURE_REASON_SET.has(native?.failureReason)
    ? "member-policy-violation"
    : "boundary-indeterminate";
}

export async function readFileBound(root, relPath, { rootBinding, encoding, expectedSha256 } = {}) {
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
