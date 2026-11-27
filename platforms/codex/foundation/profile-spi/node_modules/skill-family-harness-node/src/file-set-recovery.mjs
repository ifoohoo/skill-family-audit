// @feature FND-FR-024
// @decision FND-ADR-032
// @design FND-DES-032
import { constants as FS_CONSTANTS } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, open, readdir, rmdir, unlink } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { compileSchema, digestDocument, findSchemaByObject } from "skill-family-contracts";
import {
  acceptProtectedMaterialDirectory,
  publishFileOrReplace,
  replaceFileAtomic,
  syncForDurability,
  windowsSecurityDisposition,
} from "./atomic.mjs";
import { createFilesystemRootBinding, readFileBound } from "./bound-read.mjs";
import { HARNESS_ERROR_KINDS } from "./errors.mjs";
import { loadWindowsNativeAddon } from "./native/loader.mjs";
import { canonicalizeWindowsDriveAbsolute, classifyPathInput, resolveContained } from "./paths.mjs";
import {
  appendEvent,
  closeStateStore,
  openStateStore,
  readEvents,
  readStateStoreEventsReadOnly,
  recoverStateStoreLock,
} from "./state-store.mjs";
import { validateContractDocument } from "./validation.mjs";

/**
 * Multi-path ordinary-file apply and recovery protocol.
 *
 * Mechanism only. This module owns the file-set protocol (whole-group
 * preflight, durable materials, per-path intent facts, inverse operations,
 * domain-validation binding and explicit restart recovery). It reuses the
 * published strict single-file primitives for every business write, the
 * published bound read for original-byte observation and the published
 * durable state store for the single cooperative writer lock, event ordering
 * and hash chain. It defines no second log, lock, sequence or digest chain,
 * never cleans state-store internal files, and never touches a business path
 * without a durable `apply-intent` fact for that path.
 *
 * Journal interpretation owned here (payload shape owned by Contracts):
 *   prepared            once; frozen request projection, digests, entries
 *   apply-intent(i)     at most once per index
 *   applied(i)          once per index; the modification is observed
 *   restore-intent(i)   repeatable across recovery attempts
 *   restored(i)         repeatable; the original state is observed again
 *   validation-started / validation-finished   once
 *   committed           business terminal; never rewritten by recovery
 *   rolled-back         business terminal
 *   recovery-required   not terminal; a later recovery attempt may finish it
 *   prune-intent / pruned                      material lifecycle only
 *
 * Result facts follow contracts/API.md section 3. `current` records the last
 * safe observation taken before this call acted on that path (the site state
 * the recovery decision was made from). It is not rewritten after a
 * successful restoration, because API.md requires an interruption between
 * apply-intent and applied to stay `apply=unknown, current=expected-new` even
 * while the same result reports `restore=restored`.
 */

const RECOVERY_REL_PATH = ".foundation-file-apply";
const JOURNAL_DIR_NAME = "journal";
const OPERATIONS_DIR_NAME = "operations";
const BEFORE_DIR_NAME = "before";
const AFTER_DIR_NAME = "after";
const EVENT_PREFIX = "file-set.";
const PAYLOAD_SCHEMA_VERSION = 1;
const PRODUCER = "skill-family-harness-node.file-set-recovery";
const MAX_TOTAL_BYTES = 268435456;
const MATERIAL_DIR_MODE = 0o700;
const MATERIAL_FILE_MODE = 0o600;
const RECOVERY_ROOT_MODE = 0o700;
const RESERVED_SEGMENTS = new Set([".", "..", ".git", RECOVERY_REL_PATH]);
// Primitive staging names the request explicitly authorizes (dot prefix,
// target basename, pid, random value, atomic writer suffix). A restart never
// removes such an entry by suffix; it only reports that an unowned entry of
// this shape may remain.
const ADJACENT_STAGING_PATTERN = /^\..+\.[0-9]+\.[0-9a-f]{8,32}\.(?:publish|publish-or-replace|replace)$/u;

const EVENT_TYPES = Object.freeze([
  "prepared",
  "apply-intent",
  "applied",
  "restore-intent",
  "restored",
  "validation-started",
  "validation-finished",
  "committed",
  "rolled-back",
  "recovery-required",
  "prune-intent",
  "pruned",
]);

const APPLY_REQUEST_SCHEMA_ID = findSchemaByObject("file-set-apply-request").$id;
const RECOVERY_REQUEST_SCHEMA_ID = findSchemaByObject("file-set-recovery-request").$id;
const PRUNE_REQUEST_SCHEMA_ID = findSchemaByObject("file-set-prune-request").$id;
const EVENT_PAYLOAD_SCHEMA_ID = findSchemaByObject("file-set-event-payload").$id;

function eventPayloadSchema(type) {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    allOf: [
      { $ref: EVENT_PAYLOAD_SCHEMA_ID },
      { type: "object", properties: { type: { const: type } }, required: ["type"] },
    ],
  };
}

/** Payload schemas registered with the state store. Version 2 keeps version 1 history decodable. */
const PAYLOAD_SCHEMAS = Object.freeze(Object.fromEntries(
  EVENT_TYPES.map((type) => [
    `${EVENT_PREFIX}${type}`,
    { 1: eventPayloadSchema(type), 2: eventPayloadSchema(type) },
  ]),
));

const PAYLOAD_VALIDATORS = new Map(EVENT_TYPES.map((type) => [
  type,
  {
    1: compileSchema({ schema: PAYLOAD_SCHEMAS[`${EVENT_PREFIX}${type}`][1] }, { dialect: "2020-12", policy: "strict" }),
    2: compileSchema({ schema: PAYLOAD_SCHEMAS[`${EVENT_PREFIX}${type}`][2] }, { dialect: "2020-12", policy: "strict" }),
  },
]));

const RESULT_ERROR_KINDS = new Set([
  "invalid-request", "unsupported-environment", "unsafe-path", "precondition-mismatch",
  "locked", "unfinished-operation", "operation-id-reused", "commit-unconfirmed",
  "persistence-failed", "apply-failed", "validation-failed", "validation-incomplete",
  "restore-conflict", "restore-failed", "recovery-corrupt", "root-changed",
  "ownership-lost", "operation-not-found", "prune-refused", "lock-release-failed",
]);

let testHooks = null;

async function runHook(name, context = {}) {
  const hook = testHooks?.[name];
  if (typeof hook === "function") await hook(context);
}

/** Value-returning hook variant, for hooks that substitute an observed fact. */
async function runHookValue(name, context = {}) {
  const hook = testHooks?.[name];
  return typeof hook === "function" ? await hook(context) : undefined;
}

/** Test-only hook registry. Deliberately not re-exported by index.mjs. */
export function __setFileSetTestHooks(hooks) {
  if (hooks !== null && (!hooks || typeof hooks !== "object" || Array.isArray(hooks))) {
    throw new TypeError("file-set test hooks must be an object or null");
  }
  testHooks = hooks;
}

// ---------------------------------------------------------------------------
// Failure and result scaffolding
// ---------------------------------------------------------------------------

class FileSetFailure extends Error {
  constructor(kind, phase, message, relPath, indeterminate = false) {
    super(message);
    this.name = "FileSetFailure";
    this.kind = kind;
    this.phase = phase;
    this.indeterminate = indeterminate === true;
    if (relPath !== undefined) this.relPath = relPath;
  }
}

function fail(kind, phase, message, relPath) {
  if (!RESULT_ERROR_KINDS.has(kind)) throw new TypeError(`file-set failure kind is not contracted: ${kind}`);
  throw new FileSetFailure(kind, phase, message, relPath);
}

function baseResult(operation, operationId) {
  return {
    schemaVersion: 1,
    kind: "skill-family.file-set-result",
    operationId,
    operation,
    outcome: "rejected",
    preflight: "not-run",
    businessWrite: "none",
    validation: { status: "not-run", reason: null },
    recovery: { attempted: false, status: "not-needed" },
    paths: [],
    errors: [],
    materials: {
      relPath: RECOVERY_REL_PATH,
      status: "none",
      durable: false,
      adjacentStaging: "none-observed",
    },
  };
}

function newPathResult(operation) {
  return {
    path: operation.path,
    action: operation.action,
    apply: "not-started",
    restore: "not-needed",
    current: "unknown",
    errorKinds: [],
  };
}

function pushError(result, kind, message, phase, relPath) {
  const details = { kind, phase };
  if (relPath !== undefined) details.path = relPath;
  const entry = { code: "SFC2004", message, details };
  const duplicate = result.errors.some((existing) =>
    existing.details.kind === entry.details.kind && existing.details.path === entry.details.path &&
    existing.message === entry.message);
  if (!duplicate) result.errors.push(entry);
  return entry;
}

function notePath(state, index, fields) {
  const target = state.result.paths[index];
  if (target) Object.assign(target, fields);
}

function notePathError(state, index, kind) {
  const target = state.result.paths[index];
  if (target && !target.errorKinds.includes(kind)) target.errorKinds.push(kind);
}

function finalizeBusinessWrite(state) {
  const result = state.result;
  if (result.outcome === "committed") {
    result.businessWrite = "started";
    return;
  }
  let started = false;
  let unknown = false;
  for (const entry of result.paths) {
    if (entry.apply === "applied") started = true;
    else if (entry.apply === "intent-recorded") {
      if (entry.current === "original") {
        // An apply intent plus a recorded already-original restore is the same
        // ambiguity as an `unknown` apply fact: the already-original branch
        // writes restore-intent/restored for a path whose bytes it never
        // touched, so the original site cannot rule out a write that a restore
        // brought back. The roll-up stays `unknown` instead of claiming `none`.
        if (entry.restore === "already-original") unknown = true;
        continue;
      }
      started = true;
    } else if (entry.apply === "unknown") {
      // An `unknown` apply fact with the site back at its original state is
      // not proof that the file was modified: the original bytes are also what
      // a completed restore leaves behind. Only a site that is not at its
      // original state, or a restore that really performed the inverse write
      // (`restore=restored` is only reported after one), keeps the history
      // started; anything else stays `unknown` instead of being flattened to
      // `none` (API.md section 3: businessWrite states whether this operation
      // historically modified a file, and a completed recovery never rewrites
      // it back to none).
      if (entry.current === "unknown") unknown = true;
      else if (entry.current === "original" && entry.restore !== "restored") unknown = true;
      else started = true;
    }
  }
  if (started) result.businessWrite = "started";
  else if (unknown) result.businessWrite = "unknown";
  else result.businessWrite = "none";
}

/**
 * The apply history of one path as the ledger actually supports it.
 *
 * A durable `applied` fact proves the write. A site that is back at its
 * original state only proves "no write" while no restore was recorded for that
 * path: the same original state is what a completed restore leaves behind, and
 * the already-original branch records restore-intent/restored without any
 * write ever having happened. Evidence that cannot separate "never modified"
 * from "modified and restored" stays `unknown`; the history is never rewritten
 * to "never modified".
 */
function recordedApplyHistory(summary, index, classification) {
  if (summary.applied.has(index)) return "applied";
  if (classification !== "original") return "unknown";
  if (summary.restored.has(index) || summary.restoreIntents.has(index)) return "unknown";
  return "intent-recorded";
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function randomToken(bytes = 8) {
  return randomBytes(bytes).toString("hex");
}

function monotonicNow() {
  return process.hrtime.bigint();
}

function currentUmask() {
  return process.umask();
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function ownKeys(value) {
  return isPlainObject(value) ? Object.keys(value).sort().join(",") : "";
}

function modeIsUsable(mode, label) {
  if (!Number.isInteger(mode) || mode < 0 || mode > 0o777) {
    fail("invalid-request", "input", `${label} must be a POSIX permission integer between 0000 and 0777`);
  }
  if ((mode & 0o400) !== 0o400) fail("invalid-request", "input", `${label} must keep the owner-read bit set`);
  if ((mode & 0o7000) !== 0) fail("invalid-request", "input", `${label} must not carry setuid, setgid or sticky bits`);
  if ((mode & currentUmask()) !== 0) {
    fail("invalid-request", "input", `${label} has permission bits masked by the process umask`);
  }
  return mode;
}

/**
 * Runtime byte binding; the machine projection never carries bytes. Every
 * allowed view is checked for shared backing memory before it is copied:
 * Buffer, Uint8Array and any other typed-array view over a SharedArrayBuffer
 * are rejected alike, so no view family can bypass the byte-binding contract.
 */
function copyOperationBytes(value, label) {
  if (!Buffer.isBuffer(value) && !Uint8Array.prototype.isPrototypeOf(value)) {
    fail("invalid-request", "input", `${label} must be a Buffer or Uint8Array`);
  }
  if (value.buffer instanceof SharedArrayBuffer) {
    fail("invalid-request", "input", `${label} must not be backed by a SharedArrayBuffer`);
  }
  return Buffer.from(value);
}

function assertSchemaValid(document, schemaId, label) {
  const checked = validateContractDocument(document, { schemaId });
  if (!checked.valid) {
    const first = checked.errors?.[0]?.message ?? "document does not match its registered contract";
    fail("invalid-request", "input", `${label} violates its contract: ${first}`);
  }
}

function assertPathShape(relPath, label) {
  const classification = classifyPathInput(relPath);
  if (!classification.ok) {
    fail("unsafe-path", "preflight", `${label} is not a supported POSIX relative path (${classification.kind})`, relPath);
  }
  const segments = relPath.split("/");
  // Reserved components are compared case-insensitively: on a case-insensitive
  // filesystem `.GIT` addresses the same entry as `.git`, and the whole
  // protocol already treats request paths as case-insensitive identities.
  if (segments.some((segment) => segment.length === 0 || RESERVED_SEGMENTS.has(segment.toLowerCase()))) {
    fail("unsafe-path", "preflight", `${label} contains an empty or mechanism-reserved path segment`, relPath);
  }
  if (relPath.normalize("NFC") !== relPath) {
    fail("unsafe-path", "preflight", `${label} must be NFC-normalized`, relPath);
  }
  return segments;
}

/**
 * Compares one safe observation against the frozen entry. `original` and
 * `expected-new` are state labels, not existence labels: for a create the
 * original state is "absent" and for a delete the new state is "absent".
 */
function sideMatches(observed, side, bytesOnly) {
  if (observed.status !== "file" || side === null || side === undefined) return false;
  if (observed.sha256 !== side.sha256 || observed.size !== side.size) return false;
  if (side.securityMaterial || side.permissions?.kind === "windows-security-v1") {
    if (bytesOnly) return true;
    const expectedAttributes = windowsPromisedAttributes(side.permissions?.attributes ?? side.securityMaterial?.attributes ?? 0);
    return observed.securityDigest === side.permissions?.securityDigest
      && windowsPromisedAttributes(observed.attributes ?? 0) === expectedAttributes;
  }
  if (side.permissions?.kind === "windows-inherited" || side.permissions?.kind === "windows-preserve") return true;
  return observed.mode === side.mode;
}

function classifyObserved(observed, entry) {
  if (observed.status === "unsafe" || observed.status === "unknown") return "unknown";
  const originalMatches = entry.before === null
    ? observed.status === "missing"
    : sideMatches(observed, entry.before, false);
  if (originalMatches) return "original";
  const newMatches = entry.after === null
    ? observed.status === "missing"
    : sideMatches(observed, entry.after, entry.before === null);
  if (newMatches) return "expected-new";
  return "other";
}

async function syncDirectoryStrict(directory) {
  await syncForDurability(directory, { directory: true });
}

async function syncDirectoriesStrict(directories, phase) {
  for (const directory of [...new Set(directories)]) {
    await runHook("beforeJournalSync", { directory, phase });
    try {
      await syncDirectoryStrict(directory);
    } catch (cause) {
      fail("persistence-failed", phase, `strict directory sync failed for ${directory} (${cause?.code ?? "unknown"})`);
    }
  }
}

async function observeWindowsTarget(absPath) {
  let loaded;
  try {
    loaded = await loadWindowsNativeAddon();
  } catch {
    return { status: "unknown", code: "native-addon" };
  }
  const captured = loaded.addon.readCapturedFile(absPath);
  if (!captured?.ok || !Buffer.isBuffer(captured.bytes) || !Buffer.isBuffer(captured.securityDescriptor)) {
    if (captured?.failureReason === "member-missing") return { status: "missing" };
    if (captured?.failureReason === "reparse" || captured?.failureReason === "not-regular") {
      return { status: "unsafe", mode: null };
    }
    return { status: "unknown", code: captured?.failureReason ?? "security-unreadable" };
  }
  const descriptor = Buffer.from(captured.securityDescriptor);
  const bytes = Buffer.from(captured.bytes);
  return {
    status: "file",
    sha256: digest(bytes),
    size: bytes.length,
    mode: null,
    attributes: Number(captured.attributes) >>> 0,
    securityDigest: digest(descriptor),
    securityDescriptor: descriptor,
    volumeSerial: captured.volumeSerial,
    fileId: captured.fileId,
  };
}

async function observeTarget(absPath) {
  if (windowsRuntime()) return observeWindowsTarget(absPath);
  let before;
  try {
    before = await lstat(absPath);
  } catch (cause) {
    if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return { status: "missing" };
    return { status: "unknown", code: cause?.code ?? "unknown" };
  }
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) {
    return { status: "unsafe", mode: Number(before.mode & 0o777) };
  }
  let handle = null;
  try {
    handle = await open(absPath, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino) {
      return { status: "unsafe", mode: Number(opened.mode & 0o777) };
    }
    const bytes = await handle.readFile();
    return {
      status: "file",
      sha256: digest(bytes),
      size: bytes.length,
      mode: Number(opened.mode & 0o777),
      uid: opened.uid,
    };
  } catch (cause) {
    return { status: "unknown", code: cause?.code ?? "unknown" };
  } finally {
    await handle?.close();
  }
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

function stripBytes(operation, index, label) {
  if (!isPlainObject(operation)) fail("invalid-request", "input", `${label}[${index}] must be an object`);
  const projected = { ...operation };
  if (isPlainObject(projected.next)) {
    const next = { ...projected.next };
    delete next.bytes;
    projected.next = next;
  }
  return projected;
}

/**
 * Validates the frozen request projection and binds the runtime bytes. Fields
 * other than `bytes` survive into the projection so the closed-object
 * contract still rejects unknown fields; `bytes` never enters machine JSON.
 */
function parseApplyRequest(request) {
  if (!isPlainObject(request)) fail("invalid-request", "input", "request must be a closed object");
  if (!Array.isArray(request.operations) || request.operations.length === 0) {
    fail("invalid-request", "input", "operations must be a non-empty array");
  }
  const scheme = {
    ...request,
    operations: request.operations.map((operation, index) => stripBytes(operation, index, "operations")),
  };
  assertSchemaValid(scheme, APPLY_REQUEST_SCHEMA_ID, "apply request");
  validateEnvironment(request.environment);
  const operations = [];
  const entries = [];
  const seen = new Map();
  let totalBytes = 0;
  for (let index = 0; index < scheme.operations.length; index += 1) {
    const entry = scheme.operations[index];
    const raw = request.operations[index];
    assertPathShape(entry.path, `operations[${index}].path`);
    for (const [mode, label] of [
      [entry.expected.exists === true ? entry.expected.mode : null, `operations[${index}].expected.mode`],
      [entry.next === null ? null : entry.next.mode, `operations[${index}].next.mode`],
    ]) {
      if (mode !== null && mode !== undefined) modeIsUsable(mode, label);
    }
    if (entry.action === "replace" && entry.next.mode !== entry.expected.mode) {
      fail("invalid-request", "input", `operations[${index}] replacement must keep the frozen original mode`, entry.path);
    }
    if (entry.action === "replace" && entry.next.sha256 === entry.expected.sha256 &&
        entry.next.size === entry.expected.size && entry.next.mode === entry.expected.mode) {
      fail("precondition-mismatch", "preflight", `operations[${index}] replacement is byte-identical and carries no recovery meaning`, entry.path);
    }
    const identity = entry.path.normalize("NFC").toLowerCase();
    if (seen.has(identity)) {
      fail("unsafe-path", "preflight", `operations[${index}] aliases operations[${seen.get(identity)}] on a case-insensitive filesystem`, entry.path);
    }
    seen.set(identity, index);
    let bytes = null;
    if (entry.next !== null) {
      bytes = copyOperationBytes(raw.next?.bytes, `operations[${index}].next.bytes`);
      if (bytes.length !== entry.next.size) {
        fail("invalid-request", "input", `operations[${index}] actual byte length differs from the declared size`, entry.path);
      }
      if (digest(bytes) !== entry.next.sha256) {
        fail("invalid-request", "input", `operations[${index}] actual bytes differ from the declared digest`, entry.path);
      }
      totalBytes += bytes.length;
    }
    if (entry.expected.exists === true) totalBytes += entry.expected.size;
    if (totalBytes > MAX_TOTAL_BYTES) {
      fail("invalid-request", "input", `the group exceeds the ${MAX_TOTAL_BYTES} byte aggregate capacity limit (actual bytes counted)`);
    }
    operations.push({ path: entry.path, action: entry.action, expected: entry.expected, next: entry.next, bytes });
    entries.push({
      before: entry.expected.exists === true
        ? (windowsRuntime()
          ? { sha256: entry.expected.sha256, size: entry.expected.size, permissions: entry.expected.permissions }
          : { sha256: entry.expected.sha256, size: entry.expected.size, mode: entry.expected.mode })
        : null,
      after: entry.next === null
        ? null
        : (windowsRuntime()
          ? { sha256: entry.next.sha256, size: entry.next.size, permissions: entry.next.permissions }
          : { sha256: entry.next.sha256, size: entry.next.size, mode: entry.next.mode }),
    });
  }
  const ordered = [...seen.entries()].sort((left, right) => (left[0] < right[0] ? -1 : 1));
  for (let index = 0; index < ordered.length; index += 1) {
    for (let other = index + 1; other < ordered.length; other += 1) {
      if (ordered[other][0].startsWith(`${ordered[index][0]}/`)) {
        fail("unsafe-path", "preflight", "one request path is an ancestor of another request path",
          scheme.operations[ordered[other][1]].path);
      }
    }
  }
  return {
    operationId: request.operationId,
    root: request.root,
    rootBinding: request.rootBinding,
    environment: request.environment,
    validationTimeoutMs: request.validationTimeoutMs,
    operations,
    entries,
    projection: scheme,
    absolutePaths: new Array(operations.length).fill(null),
    parentDirectories: new Array(operations.length).fill(null),
    parentIdentities: new Array(operations.length).fill(null),
  };
}

const WINDOWS_PROMISED_ATTRIBUTE_MASK = 0x1 | 0x2 | 0x4 | 0x20;
const WINDOWS_REFUSED_ATTRIBUTE_MASK = 0x200 | 0x400 | 0x800 | 0x1000 | 0x4000;

function windowsRuntime() {
  return process.platform === "win32";
}

/**
 * Keeps only the four attributes this recovery contract promises to rebuild:
 * READONLY, HIDDEN, SYSTEM, and ARCHIVE. Other bits stay observable and are
 * not returned as restored attributes.
 */
export function windowsPromisedAttributes(attributes) {
  if (!Number.isInteger(attributes) || attributes < 0 || attributes > 0xFFFFFFFF) {
    throw new TypeError("Windows attributes must be an unsigned 32-bit integer");
  }
  return attributes & WINDOWS_PROMISED_ATTRIBUTE_MASK;
}

/**
 * Plans one saved owner/group/DACL restore. The descriptor bytes are kept
 * intact; only the promised attribute bits are selected. This does not write.
 */
export function planWindowsSecurityRestore(material) {
  if (material === null || typeof material !== "object" || Array.isArray(material)) {
    throw new TypeError("Windows security material must be an object");
  }
  if (typeof material.descriptorBase64 !== "string" || material.descriptorBase64.length === 0 ||
      Buffer.from(material.descriptorBase64, "base64").toString("base64") !== material.descriptorBase64) {
    throw new TypeError("Windows security material requires canonical descriptorBase64");
  }
  return Object.freeze({
    descriptorBase64: material.descriptorBase64,
    attributes: windowsPromisedAttributes(material.attributes),
  });
}

function validateEnvironment(environment) {
  if (environment?.filesystem === "ntfs") {
    if (!windowsRuntime()) {
      fail("unsupported-environment", "input", "Windows NTFS file-set recovery is not executed on this runtime and is not replaced by a POSIX mode");
    }
    if (environment.cooperativeWriters !== true) {
      fail("unsupported-environment", "input", "Windows NTFS file-set recovery requires cooperativeWriters");
    }
    return;
  }
  const expected = process.platform === "darwin" ? "apfs" : process.platform === "linux" ? "ext4" : null;
  if (expected === null) {
    fail("unsupported-environment", "input", "file-set recovery is unsupported on this runtime platform");
  }
  if (environment.filesystem !== expected) {
    fail("unsupported-environment", "input", `declared filesystem ${environment.filesystem} does not match this platform`);
  }
  if (FS_CONSTANTS.O_NOFOLLOW === undefined || FS_CONSTANTS.O_DIRECTORY === undefined) {
    fail("unsupported-environment", "input", "file-set recovery requires O_NOFOLLOW and O_DIRECTORY");
  }
}

function parseMaintenance(request, root) {
  const maintenance = request.maintenance;
  if (maintenance === undefined) return null;
  const journalRoot = path.join(root, RECOVERY_REL_PATH, JOURNAL_DIR_NAME);
  const observation = maintenance.observation;
  if (!isPlainObject(observation) || path.resolve(String(observation.root ?? "")) !== path.resolve(journalRoot)) {
    fail("invalid-request", "input", "maintenance observation must describe this business root's journal");
  }
  return {
    observation,
    confirmAllParticipantsStopped: true,
    confirmExclusiveMaintenance: true,
  };
}

function parseSharedRequest(request) {
  if (!isPlainObject(request)) fail("invalid-request", "input", "request must be a closed object");
  return {
    operationId: request.operationId,
    root: request.root,
    rootBinding: request.rootBinding,
    environment: request.environment,
  };
}

// ---------------------------------------------------------------------------
// Filesystem layout
// ---------------------------------------------------------------------------

function layoutOf(root, operationId) {
  const recoveryRoot = path.join(root, RECOVERY_REL_PATH);
  const operationsRoot = path.join(recoveryRoot, OPERATIONS_DIR_NAME);
  return {
    recoveryRoot,
    journalRoot: path.join(recoveryRoot, JOURNAL_DIR_NAME),
    operationsRoot,
    operationDir: path.join(operationsRoot, operationId),
    beforeDir: path.join(operationsRoot, operationId, BEFORE_DIR_NAME),
    afterDir: path.join(operationsRoot, operationId, AFTER_DIR_NAME),
  };
}

function materialFileName(index) {
  return String(index).padStart(6, "0");
}

function materialPath(layout, directoryName, index) {
  const directory = directoryName === BEFORE_DIR_NAME ? layout.beforeDir : layout.afterDir;
  return path.join(directory, materialFileName(index));
}

function identityOf(stats) {
  if (stats?.windowsIdentity) return stats.windowsIdentity;
  return {
    device: String(stats.dev),
    inode: String(stats.ino),
    mode: Number(stats.mode & 0o7777),
    type: stats.isDirectory() ? "directory" : "file",
  };
}

function sameIdentity(stats, identity) {
  if (identity && typeof identity.volumeSerial === "string") {
    return stats !== null && stats.windowsIdentity?.volumeSerial === identity.volumeSerial &&
      stats.windowsIdentity?.fileId === identity.fileId;
  }
  return stats !== null && identity !== undefined && identity !== null &&
    String(stats.dev) === identity.device && String(stats.ino) === identity.inode;
}

async function requireRealDirectory(target, label, { mode = null, kind = "unsafe-path", phase = "preflight", protectedMaterial = false } = {}) {
  let stats;
  try {
    stats = await lstat(target);
  } catch (cause) {
    if (cause?.code === "ENOENT") fail(kind, phase, `${label} does not exist`);
    fail(kind, phase, `${label} cannot be inspected (${cause?.code ?? "unknown"})`);
  }
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    fail(kind, phase, `${label} must be one real directory`);
  }
  if (!windowsRuntime() && mode !== null && Number(stats.mode & 0o7777) !== mode) {
    fail(kind, phase, `${label} must have mode 0${mode.toString(8)}`);
  }
  if (windowsRuntime()) {
    let loaded;
    try {
      loaded = await loadWindowsNativeAddon();
    } catch (cause) {
      fail(kind, phase, `${label} security descriptor cannot be captured (${cause?.message ?? "unknown"})`);
    }
    const captured = loaded.addon.captureSecurity(target);
    if (!captured?.ok || typeof captured.volumeSerial !== "string" || typeof captured.fileId !== "string" || !Buffer.isBuffer(captured.securityDescriptor)) {
      fail(kind, phase, `${label} security descriptor cannot be captured`);
    }
    const descriptor = Buffer.from(captured.securityDescriptor);
    if (protectedMaterial && (captured.currentUserOwner !== true || !acceptProtectedMaterialDirectory(windowsSecurityDisposition(descriptor)).accepted)) {
      fail(kind, phase, `${label} DACL is not a protected non-inheriting directory`);
    }
    stats.windowsIdentity = {
      volumeSerial: captured.volumeSerial,
      fileId: captured.fileId,
      permissionObservation: {
        kind: "windows-security-v1",
        attributes: windowsPromisedAttributes(captured.attributes),
        securityDigest: digest(descriptor),
      },
      type: stats.isDirectory() ? "directory" : "file",
    };
  }
  return stats;
}

async function assertRootBindingMatches(request) {
  let actual;
  try {
    actual = await createFilesystemRootBinding(request.root);
  } catch (cause) {
    fail("invalid-request", "input", `root cannot be bound as an authorized project root (${cause?.details?.kind ?? cause?.code ?? "unknown"})`);
  }
  if (actual.digest !== request.rootBinding?.digest) {
    fail("invalid-request", "input", "rootBinding does not match the current authorized project root");
  }
}

/**
 * The mechanism never creates `.foundation-file-apply` (that directory is
 * caller integration preparation) but it owns the journal and material
 * subdirectories inside it.
 */
async function requireRecoveryRoot(root) {
  await requireRealDirectory(path.join(root, RECOVERY_REL_PATH), "the .foundation-file-apply mechanism root", {
    mode: RECOVERY_ROOT_MODE,
    kind: "invalid-request",
    phase: "input",
    protectedMaterial: true,
  });
}

async function createProtectedMaterialDirectory(directory) {
  let loaded;
  try {
    loaded = await loadWindowsNativeAddon();
  } catch (cause) {
    fail("persistence-failed", "prepare", `win32-x64 native addon is not available (${cause?.message ?? "unknown"})`);
  }
  const created = loaded.addon.createProtectedDirectory(directory);
  if (!created?.ok) {
    const error = new Error(created?.failureReason ?? "native-io");
    error.code = created?.failureReason === "exists" ? "EEXIST" : "EIO";
    throw error;
  }
}

async function ensureMaterialLayout(state) {
  const layout = state.layout;
  for (const directory of [layout.operationsRoot, layout.operationDir, layout.beforeDir, layout.afterDir]) {
    let stats = await lstat(directory).catch((cause) => (cause?.code === "ENOENT" ? null : Promise.reject(cause)));
    if (stats === null) {
      try {
        if (windowsRuntime()) await createProtectedMaterialDirectory(directory);
        else await mkdir(directory, { mode: MATERIAL_DIR_MODE });
      } catch (cause) {
        if (cause?.code !== "EEXIST") fail("persistence-failed", "prepare", `a material directory cannot be created (${cause?.code ?? "unknown"})`);
      }
      stats = await lstat(directory);
    }
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      fail("recovery-corrupt", "prepare", "a material directory is not one real directory");
    }
    // A directory the mechanism creates during this call is re-verified against
    // the device the root was bound to before the `prepared` fact lands and
    // before any business write: a mount appearing between the topology
    // precheck and this point must not move the materials to another device.
    const device = await observedDeviceOf(directory, "a material directory");
    if (device !== null && state.rootDevice !== undefined && state.rootDevice !== null && device !== state.rootDevice) {
      refuseUnsupportedTopology(state,
        `the material directory ${directory} is on device ${device} while the authorized root is on device ${state.rootDevice}; ` +
        "one project root must stay on a single local filesystem");
    }
    if (windowsRuntime()) {
      await requireRealDirectory(directory, "a material directory", {
        kind: "recovery-corrupt",
        phase: "prepare",
        protectedMaterial: true,
      });
    }
    await syncDirectoryStrict(path.dirname(directory));
  }
}

async function writeMaterialFile(file, bytes) {
  if (windowsRuntime()) {
    let loaded;
    try {
      loaded = await loadWindowsNativeAddon();
    } catch (cause) {
      fail("persistence-failed", "prepare", `win32-x64 native addon is not available (${cause?.message ?? "unknown"})`);
    }
    const native = loaded.addon.publishProtectedFile(file, bytes, "windows-protected", false);
    if (!native?.ok || native.flushFailed === true) {
      fail("persistence-failed", "prepare", `a material file was not durably published (${native?.failureReason ?? "flush-failed"})`);
    }
    return;
  }
  const handle = await open(
    file,
    FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
    MATERIAL_FILE_MODE,
  );
  try {
    await handle.writeFile(bytes);
    await syncForDurability(file);
    const stats = await handle.stat();
    if (!stats.isFile() || stats.nlink !== 1) fail("persistence-failed", "prepare", "a material file is not one ordinary file");
  } finally {
    await handle.close();
  }
}

async function readMaterialFile(file, expected) {
  if (windowsRuntime()) {
    let loaded;
    try {
      loaded = await loadWindowsNativeAddon();
    } catch {
      return { status: "corrupt", code: "native-addon" };
    }
    const captured = loaded.addon.readCapturedFile(file);
    if (captured?.failureReason === "member-missing") return { status: "missing" };
    if (!captured?.ok || !Buffer.isBuffer(captured.bytes) || !Buffer.isBuffer(captured.securityDescriptor)) {
      return { status: "corrupt", code: captured?.failureReason ?? "security-unreadable" };
    }
    if (captured.currentUserOwner !== true || !acceptProtectedMaterialDirectory(windowsSecurityDisposition(Buffer.from(captured.securityDescriptor))).accepted) {
      return { status: "corrupt", code: "dacl-drift" };
    }
    const bytes = Buffer.from(captured.bytes);
    if (expected !== null && (digest(bytes) !== expected.sha256 || bytes.length !== expected.size)) {
      return { status: "corrupt", code: "digest-mismatch" };
    }
    return { status: "ok", bytes, observation: { volumeSerial: captured.volumeSerial, fileId: captured.fileId,
      attributes: windowsPromisedAttributes(captured.attributes), securityDigest: digest(captured.securityDescriptor) } };
  }
  let before;
  try {
    before = await lstat(file, { bigint: true });
  } catch (cause) {
    if (cause?.code === "ENOENT") return { status: "missing" };
    return { status: "corrupt", code: cause?.code };
  }
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1n) return { status: "corrupt", code: "unsafe-entry" };
  const handle = await open(file, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat({ bigint: true });
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1n) {
      return { status: "corrupt", code: "identity-drift" };
    }
    const bytes = await handle.readFile();
    if (!windowsRuntime() && Number(opened.mode & 0o7777n) !== MATERIAL_FILE_MODE) return { status: "corrupt", code: "mode-drift" };
    if (expected !== null && (digest(bytes) !== expected.sha256 || bytes.length !== expected.size)) {
      return { status: "corrupt", code: "digest-mismatch" };
    }
    return { status: "ok", bytes };
  } finally {
    await handle.close();
  }
}

/**
 * Material directories are as load-bearing as the material files: a registered
 * path inside a replaced or linked directory would address an unregistered
 * file. Both registered material directories (and the operation directory
 * whose removal ends a cleanup) must still be one real directory with the
 * recorded mode before anything inside them is read or removed.
 */
async function requireMaterialDirectory(directory, label, { kind, phase }) {
  if (windowsRuntime()) {
    return requireRealDirectory(directory, label, { kind, phase, protectedMaterial: true });
  }
  const stats = await lstat(directory).catch(() => null);
  if (stats === null || stats.isSymbolicLink() || !stats.isDirectory()) {
    fail(kind, phase, `${label} is not one real directory`);
  }
  if (Number(stats.mode & 0o7777) !== MATERIAL_DIR_MODE) {
    fail(kind, phase, `${label} must have mode 0${MATERIAL_DIR_MODE.toString(8)}`);
  }
  return stats;
}

/**
 * A material directory is only as trustworthy as the chain that leads to it:
 * a linked or replaced `operations/` level still spells the registered
 * `before/` and `after/` paths while addressing a directory the layout never
 * registered, and the end-of-chain checks cannot see it. Every level from the
 * authorized mechanism root down to the material directory must therefore be
 * one real directory with the recorded mode before anything inside it is read
 * or removed. The authorized root itself is already bound by the entry point.
 */
async function requireMaterialAncestry(layout, directory, label, { kind, phase }) {
  const chain = [
    [layout.recoveryRoot, "the .foundation-file-apply mechanism root"],
    [layout.operationsRoot, "the operation materials root"],
    [layout.operationDir, "the operation material directory"],
    [directory, label],
  ];
  const checked = new Set();
  for (const [level, levelLabel] of chain) {
    if (checked.has(level)) continue;
    checked.add(level);
    await requireMaterialDirectory(level, levelLabel, { kind, phase });
  }
}

async function scanAdjacentStaging(parentDirectories) {
  for (const directory of parentDirectories) {
    const entries = await readdir(directory, { withFileTypes: true }).catch(() => null);
    if (entries === null) return "possible-unknown";
    if (entries.some((entry) => ADJACENT_STAGING_PATTERN.test(entry.name))) return "possible-unknown";
  }
  return "none-observed";
}

/**
 * Materials are only reported from a trustworthy layout: every existing level
 * of the material chain must still be one real directory with the recorded
 * mode. Missing levels are not a drift signal here (a completed or interrupted
 * cleanup leaves exactly that), but a linked or replaced one is, and such
 * materials are never reported as a retained group.
 */
async function materialChainTrusted(state) {
  const layout = state.layout;
  for (const level of [
    layout.recoveryRoot,
    layout.operationsRoot,
    layout.operationDir,
    layout.beforeDir,
    layout.afterDir,
  ]) {
    const stats = await lstat(level).catch(() => null);
    if (stats === null) continue;
    if (stats.isSymbolicLink() || !stats.isDirectory()) return false;
    if (!windowsRuntime() && Number(stats.mode & 0o7777) !== MATERIAL_DIR_MODE) return false;
    if (windowsRuntime()) {
      try {
        await requireRealDirectory(level, "a material directory", {
          kind: "recovery-corrupt",
          phase: "prepare",
          protectedMaterial: true,
        });
      } catch {
        return false;
      }
    }
  }
  return true;
}

async function materialStatus(state) {
  const layout = state.layout;
  const ctx = state.ctx;
  if (!await materialChainTrusted(state)) return "partial";
  const beforeEntries = await readdir(layout.beforeDir, { withFileTypes: true }).catch(() => null);
  const afterEntries = await readdir(layout.afterDir, { withFileTypes: true }).catch(() => null);
  if (beforeEntries === null && afterEntries === null) return "none";
  if (beforeEntries === null || afterEntries === null) return "partial";
  if (ctx.entries === undefined) {
    // Materials exist but the frozen entry set is not available (the prepare
    // phase did not complete): report presence, never "none".
    return "partial";
  }
  let complete = true;
  for (let index = 0; index < ctx.operations.length; index += 1) {
    for (const [directoryName, expected] of [
      [BEFORE_DIR_NAME, ctx.entries[index].before],
      [AFTER_DIR_NAME, ctx.entries[index].after],
    ]) {
      if (expected === null || expected === undefined) continue;
      const read = await readMaterialFile(materialPath(layout, directoryName, index), expected);
      if (read.status !== "ok") complete = false;
    }
  }
  return complete ? "retained" : "partial";
}

async function finalMaterialStatus(state) {
  if (state.ctx === undefined || state.layout === undefined) return state.result.materials.status;
  if (state.result.materials.status === "pruned") return "pruned";
  try {
    return await materialStatus(state);
  } catch {
    return state.result.materials.status === "none" ? "none" : "partial";
  }
}

// ---------------------------------------------------------------------------
// Journal plumbing
// ---------------------------------------------------------------------------

function mapStoreFailure(cause, fallbackKind, phase) {
  if (cause instanceof FileSetFailure) return cause;
  const map = {
    "store-locked": "locked",
    "lock-recovery-refused": "recovery-corrupt",
    "lock-corrupt": "recovery-corrupt",
    "chain-broken": "recovery-corrupt",
    "unsafe-state-entry": "recovery-corrupt",
    "event-schema-invalid": "recovery-corrupt",
    "snapshot-mismatch": "recovery-corrupt",
    "idempotency-conflict": "recovery-corrupt",
    "duplicate-sequence": "recovery-corrupt",
    "invalid-root": "root-changed",
    "store-closed": "ownership-lost",
    "read-failed": "recovery-corrupt",
    "missing-resource": "recovery-corrupt",
  };
  const resolved = map[cause?.details?.kind] ?? fallbackKind;
  // After the group is frozen, losing the single writer means the exclusive
  // maintenance/ownership fact itself is gone: that blocks the affected
  // group instead of degrading into one more per-path failure.
  if (resolved === "locked" && phase !== "preflight") {
    return new FileSetFailure("ownership-lost", phase,
      `the journal writer lock was lost during ${phase}: ${cause?.message ?? "unknown"}`);
  }
  return new FileSetFailure(resolved, phase,
    `${cause?.message ?? "state store operation failed"} [${cause?.details?.kind ?? cause?.code ?? "unknown"}]`);
}

async function readAllEvents(state) {
  try {
    return await readEvents(state.store);
  } catch (cause) {
    throw mapStoreFailure(cause, "recovery-corrupt", "preflight");
  }
}

function attachStore(state) {
  state.knownKeys = new Set(state.events.map((record) => record.idempotencyKey));
}

/**
 * Appends one file-set fact through the state store's single writer and hash
 * chain. An append error never proves the event was not written: the ledger
 * is re-read before anything decides between fail-closed and rollback.
 */
async function appendFileSetEvent(state, payload, { unique = true, phase = "apply" } = {}) {
  // Event ids and idempotency keys stay inside the envelope pattern
  // (letters, digits, dot, colon, dash, underscore).
  const suffix = payload.index === undefined ? "" : `-${payload.index}`;
  const base = `${payload.operationId}.${payload.type}${suffix}`;
  const identity = unique
    ? { eventId: base, idempotencyKey: base }
    : { eventId: `${base}.${randomToken()}`, idempotencyKey: `${base}.${randomToken()}` };
  const schemaVersion = state?.ctx?.projection?.schemaVersion === 2 ? 2 : PAYLOAD_SCHEMA_VERSION;
  const body = {
    schemaVersion,
    kind: "skill-family.file-set-event-payload",
    operationId: payload.operationId,
    type: payload.type,
    ...payload,
  };
  const validator = PAYLOAD_VALIDATORS.get(body.type)?.[schemaVersion];
  if (typeof validator !== "function" || !validator(body)) {
    throw new FileSetFailure("recovery-corrupt", phase, `internal ${body.type} event payload violates its contract`);
  }
  if (state.knownKeys.has(identity.idempotencyKey)) return null;
  const event = {
    eventId: identity.eventId,
    eventType: `${EVENT_PREFIX}${body.type}`,
    payloadSchemaVersion: schemaVersion,
    producer: PRODUCER,
    idempotencyKey: identity.idempotencyKey,
    payload: body,
  };
  try {
    await runHook("beforeEventAppend", { type: body.type, index: body.index, event });
    const appended = await appendEvent(state.store, event);
    state.knownKeys.add(identity.idempotencyKey);
    return appended.record;
  } catch (cause) {
    let reread = null;
    try {
      reread = await readEvents(state.store);
    } catch {
      reread = null;
    }
    const found = reread?.find((record) => record.idempotencyKey === identity.idempotencyKey) ?? null;
    if (found !== null) {
      state.events = reread;
      state.knownKeys.add(identity.idempotencyKey);
      return found;
    }
    throw mapStoreFailure(cause, "persistence-failed", phase);
  }
}

/** Strict durability barrier the state store's tolerant directory sync does not provide. */
async function journalBarrier(state, phase, extraDirectories = []) {
  await syncDirectoriesStrict(
    [path.join(state.layout.journalRoot, "events"), state.layout.journalRoot, ...extraDirectories],
    phase,
  );
}

function summarizeOperation(events, operationId) {
  const summary = {
    mine: [],
    prepared: null,
    intents: new Set(),
    applied: new Map(),
    restoreIntents: new Set(),
    restored: new Map(),
    committed: null,
    rolledBack: null,
    recoveryRequired: null,
    pruneIntent: null,
    pruned: null,
    terminal: null,
  };
  for (const record of events) {
    if (record.payload?.operationId !== operationId) continue;
    summary.mine.push(record);
    const payload = record.payload;
    switch (payload.type) {
      case "prepared": if (summary.prepared === null) summary.prepared = record; break;
      case "apply-intent": summary.intents.add(payload.index); break;
      case "applied": summary.applied.set(payload.index, record); break;
      case "restore-intent": summary.restoreIntents.add(payload.index); break;
      case "restored": summary.restored.set(payload.index, record); break;
      case "committed": summary.committed = record; summary.terminal = "committed"; break;
      case "rolled-back": summary.rolledBack = record; if (summary.terminal !== "committed") summary.terminal = "rolled-back"; break;
      case "recovery-required": summary.recoveryRequired = record; if (summary.terminal !== "committed") summary.terminal = null; break;
      case "prune-intent": summary.pruneIntent = record; break;
      case "pruned": summary.pruned = record; break;
      default: break;
    }
  }
  return summary;
}

function journalOperationIds(events) {
  const ids = new Set();
  for (const record of events) {
    if (typeof record.payload?.operationId === "string") ids.add(record.payload.operationId);
  }
  return ids;
}

async function listOperationDirectories(layout) {
  return readdir(layout.operationsRoot, { withFileTypes: true }).catch((cause) => {
    if (cause?.code === "ENOENT") return [];
    throw cause;
  });
}

// ---------------------------------------------------------------------------
// Store lifecycle
// ---------------------------------------------------------------------------

function storeOwner(prefix, operationId) {
  return `${prefix}-${operationId.slice(0, 8)}-${randomToken(6)}`;
}

async function openJournalWriter(state, prefix) {
  try {
    return await openStateStore(state.layout.journalRoot, {
      owner: storeOwner(prefix, state.ctx.operationId),
      payloadSchemas: PAYLOAD_SCHEMAS,
    });
  } catch (cause) {
    throw mapStoreFailure(cause, "locked", "preflight");
  }
}

/**
 * Explicit maintenance takeover. Only maintenance-mode fields are ever
 * constructed; legacy takeover fields are never expanded with undefined
 * values, because an explicitly undefined legacy field still counts as mode
 * mixing and is rejected by the state store.
 */
async function openJournalMaintenance(state, prefix) {
  const maintenance = state.ctx.maintenance;
  try {
    return await recoverStateStoreLock(state.layout.journalRoot, {
      observation: maintenance.observation,
      confirmAllParticipantsStopped: maintenance.confirmAllParticipantsStopped,
      confirmExclusiveMaintenance: maintenance.confirmExclusiveMaintenance,
      newOwner: storeOwner(prefix, state.ctx.operationId),
      payloadSchemas: PAYLOAD_SCHEMAS,
    });
  } catch (cause) {
    throw mapStoreFailure(cause, "recovery-corrupt", "preflight");
  }
}

async function releaseStore(state) {
  if (state.store === null) return;
  const store = state.store;
  state.store = null;
  try {
    await closeStateStore(store);
  } catch (cause) {
    pushError(state.result, "lock-release-failed",
      `the exclusive project lock could not be released: ${cause?.message ?? "unknown"}`, "finalize");
  }
}

// ---------------------------------------------------------------------------
// Single-device topology
// ---------------------------------------------------------------------------

/**
 * Device fact of one existing site, or null when the site cannot be observed.
 *
 * The non-public test hook may substitute the observed device so a cross-device
 * topology is reachable on a host with only one writable filesystem; the hook
 * default is null, it is never re-exported from index.mjs and it changes no
 * public input, error kind or result field.
 */
async function observedDeviceOf(target, label) {
  const stats = await lstat(target).catch(() => null);
  if (stats === null) return null;
  const device = String(stats.dev);
  const substituted = await runHookValue("deviceFact", { path: target, device, label });
  return substituted === undefined || substituted === null ? device : String(substituted);
}

/**
 * The frozen shape of an environment-level refusal (PLAN section 0, D1): the
 * same `unsupported-environment` result as the platform check, reported before
 * any operation identity or per-path fact is claimed — no operationId, no
 * paths. API.md section 3 allows both when no verified identity exists, and a
 * cross-device topology is not attributable to one business path.
 */
function refuseUnsupportedTopology(state, message) {
  state.result.operationId = null;
  state.result.paths = [];
  state.result.preflight = "failed";
  fail("unsupported-environment", "preflight", message);
}

/**
 * Whole-group single-device topology.
 *
 * ARCHITECTURE section 3 supports one local filesystem per authorized root: the
 * root, every business target and its parent directory, the mechanism root, the
 * journal root and the operation materials must all live on the device the root
 * was bound to. A cross-device mount would only fail inside the primitives
 * (EXDEV) after the group was already frozen, so the topology is refused as an
 * unsupported environment before any business write, with the same refusal and
 * no automatic downgrade as an unsupported platform (VALIDATION V14).
 *
 * Sites that do not exist are skipped: the path preflight owns those refusals,
 * and the device question can only be asked of a site that exists.
 */
async function assertSingleDeviceTopology(state) {
  const ctx = state.ctx;
  const layout = state.layout;
  if (ctx === undefined || layout === undefined || ctx.root === undefined) return;
  const rootDevice = await observedDeviceOf(ctx.root, "the authorized business root");
  if (rootDevice === null) return;
  state.rootDevice = rootDevice;
  const sites = [];
  for (const [level, label] of [
    [layout.recoveryRoot, "the .foundation-file-apply mechanism root"],
    [layout.journalRoot, "the journal root"],
    [layout.operationsRoot, "the operation materials root"],
  ]) {
    if (await lstat(level).catch(() => null) !== null) sites.push([level, label]);
  }
  for (const operation of ctx.operations ?? []) {
    let absolute;
    try {
      absolute = await resolveContained(ctx.root, operation.path);
    } catch {
      continue; // the path preflight owns this refusal
    }
    sites.push([path.dirname(absolute), `the parent directory of ${operation.path}`]);
    sites.push([absolute, operation.path]);
  }
  for (const [target, label] of sites) {
    const device = await observedDeviceOf(target, label);
    if (device !== null && device !== rootDevice) {
      refuseUnsupportedTopology(state,
        `${label} is on device ${device} while the authorized root is on device ${rootDevice}; ` +
        "one project root must stay on a single local filesystem");
    }
  }
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

/**
 * Verifies every segment against the actual directory entries before the group
 * is frozen. On a case-insensitive filesystem a differently cased request
 * addresses the same entry, so `DIR/a` is the alias the contract forbids, and
 * this check is the only one that can see it. A segment that exists under no
 * spelling is not an alias: a create leaf may legitimately be absent and a
 * missing ancestor is reported by its own preflight failure.
 */
async function assertSegmentSpelling(state, index) {
  const relPath = state.ctx.operations[index].path;
  const segments = relPath.split("/");
  let directory = state.ctx.root;
  for (const segment of segments) {
    const entries = await readdir(directory, { withFileTypes: true }).catch(() => null);
    if (entries === null) {
      fail("unsafe-path", "preflight", `${relPath} cannot be listed to verify its path spelling`, relPath);
    }
    if (entries.some((entry) => entry.name === segment)) {
      directory = path.join(directory, segment);
      continue;
    }
    const identity = segment.normalize("NFC").toLowerCase();
    const alias = entries.find((entry) => entry.name.normalize("NFC").toLowerCase() === identity);
    if (alias !== undefined) {
      fail("unsafe-path", "preflight",
        `${relPath} addresses ${alias.name} through the differently cased segment ${segment}`, relPath);
    }
    return;
  }
}

async function preflightOperation(state, index) {
  const ctx = state.ctx;
  const operation = ctx.operations[index];
  const entry = ctx.entries[index];
  let absolute;
  let parent;
  let parentStats;
  let observed;
  let targetStats = null;
  try {
    absolute = await resolveContained(ctx.root, operation.path);
    parent = path.dirname(absolute);
    parentStats = await requireRealDirectory(parent, `the parent directory of ${operation.path}`, {
      kind: "unsafe-path",
      phase: "preflight",
    });
    await assertSegmentSpelling(state, index);
    observed = await readFileBound(ctx.root, operation.path, { rootBinding: ctx.rootBinding }).then(
      (bound) => ({
        status: "file",
        sha256: bound.sha256,
        size: bound.bytes,
        mode: bound.mode,
        attributes: bound.permissionObservation?.attributes,
        securityDigest: bound.permissionObservation?.securityDigest
          ?? (Buffer.isBuffer(bound.securityDescriptor) ? digest(bound.securityDescriptor) : undefined),
        securityDescriptor: bound.securityDescriptor,
      }),
      (cause) => {
        if (cause?.details?.kind === HARNESS_ERROR_KINDS.MISSING_RESOURCE) return { status: "missing" };
        throw cause;
      },
    );
    if (observed.status === "file" && !windowsRuntime()) {
      targetStats = await lstat(absolute);
      if (targetStats.isSymbolicLink() || !targetStats.isFile() || targetStats.nlink !== 1) {
        fail("unsafe-path", "preflight", `${operation.path} is not one ordinary file with a single link`, operation.path);
      }
    } else if (observed.status === "file") {
      targetStats = {
        windowsIdentity: {
          volumeSerial: observed.volumeSerial,
          fileId: observed.fileId,
          type: "file",
        },
      };
    }
  } catch (cause) {
    recordPathFailure(state, index, cause, "preflight");
    return false;
  }
  ctx.absolutePaths[index] = absolute;
  ctx.parentDirectories[index] = parent;
  ctx.parentIdentities[index] = identityOf(parentStats);
  state.distinctParents.add(parent);

  const problems = [];
  if (observed.status === "file" && !windowsRuntime()) {
    if (typeof process.getuid === "function" && targetStats.uid !== process.getuid()) {
      problems.push("the target is not owned by the executing user");
    }
    // The full site mode is read, not only the permission bits: a target that
    // already carries setuid, setgid or sticky bits is outside the frozen
    // mode contract, and replacing it would silently drop those bits.
    if ((targetStats.mode & 0o7000) !== 0) {
      problems.push("the target carries setuid, setgid or sticky bits");
    }
    if ((observed.mode & 0o400) !== 0o400) problems.push("the target has no owner-read bit");
    if ((observed.mode & currentUmask()) !== 0) problems.push("the target mode has bits masked by the process umask");
  }
  if (observed.status === "file" && windowsRuntime()) {
    const refused = (Number(observed.attributes) >>> 0) & WINDOWS_REFUSED_ATTRIBUTE_MASK;
    if (refused !== 0) problems.push("the target carries a Windows attribute this recovery contract does not rebuild");
    if (Buffer.isBuffer(observed.securityDescriptor)) {
      let loaded;
      try {
        loaded = await loadWindowsNativeAddon();
      } catch (cause) {
        problems.push(`the target security descriptor cannot be checked for ordinary-user restore (${cause?.message ?? "unknown"})`);
      }
      const capable = loaded?.addon.windowsRestoreCapable(observed.securityDescriptor, absolute, Number(observed.attributes) >>> 0);
      if (loaded && capable?.ok !== true) problems.push("the executing user cannot restore the target owner, group, and DACL");
    }
  }
  if (operation.expected.exists === true) {
    if (observed.status === "missing") {
      problems.push("expected an existing ordinary file but the target is missing");
    } else if (observed.sha256 !== operation.expected.sha256 || observed.size !== operation.expected.size) {
      problems.push("the existing target bytes do not match the frozen digest and size");
    } else if (windowsRuntime()) {
      if (observed.securityDigest !== operation.expected.permissions?.securityDigest) {
        problems.push("the existing target security digest does not match the frozen observation");
      } else if (windowsPromisedAttributes(observed.attributes ?? 0) !== windowsPromisedAttributes(operation.expected.permissions?.attributes ?? 0)) {
        problems.push("the existing target promised attributes do not match the frozen observation");
      }
    } else if (observed.mode !== operation.expected.mode) {
      problems.push("the existing target mode does not match the frozen mode");
    }
  } else if (observed.status === "file") {
    problems.push("create requires an absent target");
  }
  notePath(state, index, { current: classifyObserved(observed, entry) });
  if (problems.length > 0) {
    pushError(state.result, "precondition-mismatch",
      `preflight rejected ${operation.path}: ${problems.join("; ")}`, "preflight", operation.path);
    notePathError(state, index, "precondition-mismatch");
    return false;
  }
  return true;
}

function recordPathFailure(state, index, cause, phase) {
  const relPath = state.ctx.operations[index]?.path;
  if (cause instanceof FileSetFailure) {
    pushError(state.result, cause.kind, cause.message, cause.phase ?? phase, cause.relPath ?? relPath);
    notePathError(state, index, cause.kind);
    if (cause.kind === "invalid-request" || cause.kind === "unsupported-environment" || cause.kind === "root-changed") throw cause;
    return;
  }
  const mapped = {
    [HARNESS_ERROR_KINDS.MISSING_RESOURCE]: "unsafe-path",
    [HARNESS_ERROR_KINDS.INVALID_PATH]: "unsafe-path",
    [HARNESS_ERROR_KINDS.ABSOLUTE_PATH]: "unsafe-path",
    [HARNESS_ERROR_KINDS.PATH_TRAVERSAL]: "unsafe-path",
    [HARNESS_ERROR_KINDS.WINDOWS_DRIVE_PATH]: "unsafe-path",
    [HARNESS_ERROR_KINDS.WINDOWS_PATH]: "unsafe-path",
    [HARNESS_ERROR_KINDS.UNC_PATH]: "unsafe-path",
    [HARNESS_ERROR_KINDS.SYMLINK_ESCAPE]: "unsafe-path",
    [HARNESS_ERROR_KINDS.REALPATH_ESCAPE]: "unsafe-path",
    [HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY]: "unsafe-path",
    [HARNESS_ERROR_KINDS.READ_FAILED]: "unsafe-path",
    [HARNESS_ERROR_KINDS.CONTENT_GUARD_REJECTED]: "precondition-mismatch",
    [HARNESS_ERROR_KINDS.INVALID_ROOT]: "root-changed",
    [HARNESS_ERROR_KINDS.UNSUPPORTED_PLATFORM]: "unsupported-environment",
  }[cause?.details?.kind];
  const resolved = mapped ?? "unsafe-path";
  pushError(state.result, resolved, `preflight rejected ${relPath}: ${cause?.message ?? "unknown mechanism failure"}`, phase, relPath);
  notePathError(state, index, resolved);
}

async function runPreflight(state) {
  let passed = true;
  // Whole-group environment check inside the writer lock: the device topology
  // is re-verified against the live site before any per-path preflight work.
  await assertSingleDeviceTopology(state);
  for (let index = 0; index < state.ctx.operations.length; index += 1) {
    if (!await preflightOperation(state, index)) passed = false;
  }
  await runHook("afterPreflight", { passed });
  return passed;
}

// ---------------------------------------------------------------------------
// Prepared materials
// ---------------------------------------------------------------------------

async function prepareMaterials(state) {
  const ctx = state.ctx;
  const layout = state.layout;
  const entries = [];
  await ensureMaterialLayout(state);
  state.materialIdentity = identityOf(await requireRealDirectory(layout.operationDir, "operation material directory", { protectedMaterial: true }));
  for (let index = 0; index < ctx.operations.length; index += 1) {
    const entry = ctx.entries[index];
    let beforeRecord = entry.before;
    let afterRecord = entry.after;
    if (entry.before !== null) {
      await runHook("beforeMaterialWrite", { index, kind: "before" });
      const bound = await readFileBound(ctx.root, ctx.operations[index].path, {
        rootBinding: ctx.rootBinding,
        expectedSha256: entry.before.sha256,
      });
      if (windowsRuntime()) {
        if (!Buffer.isBuffer(bound.securityDescriptor)) {
          fail("precondition-mismatch", "prepare",
            `${ctx.operations[index].path} has no Windows security descriptor to retain`, ctx.operations[index].path);
        }
        const descriptor = Buffer.from(bound.securityDescriptor);
        const securityDigest = digest(descriptor);
        if (bound.bytes !== entry.before.size || securityDigest !== entry.before.permissions?.securityDigest) {
          fail("precondition-mismatch", "prepare",
            `${ctx.operations[index].path} changed between preflight and material write`, ctx.operations[index].path);
        }
        beforeRecord = {
          sha256: entry.before.sha256,
          size: entry.before.size,
          permissions: {
            kind: "windows-security-v1",
            attributes: windowsPromisedAttributes(bound.permissionObservation?.attributes ?? 0),
            securityDigest,
          },
          securityMaterial: {
            descriptorBase64: descriptor.toString("base64"),
            attributes: Number(bound.permissionObservation?.attributes ?? 0) >>> 0,
          },
        };
      } else if (bound.bytes !== entry.before.size || bound.mode !== entry.before.mode) {
        fail("precondition-mismatch", "prepare",
          `${ctx.operations[index].path} changed between preflight and material write`, ctx.operations[index].path);
      }
      await writeMaterialFile(materialPath(layout, BEFORE_DIR_NAME, index), bound.content);
    }
    if (entry.after !== null) {
      await runHook("beforeMaterialWrite", { index, kind: "after" });
      await writeMaterialFile(materialPath(layout, AFTER_DIR_NAME, index), ctx.operations[index].bytes);
      if (windowsRuntime()) {
        if (beforeRecord?.securityMaterial) {
          afterRecord = {
            sha256: entry.after.sha256,
            size: entry.after.size,
            permissions: beforeRecord.permissions,
            securityMaterial: beforeRecord.securityMaterial,
          };
        } else {
          let loaded;
          try {
            loaded = await loadWindowsNativeAddon();
          } catch (cause) {
            fail("persistence-failed", "prepare", `win32-x64 native addon is not available (${cause?.message ?? "unknown"})`);
          }
          const probe = path.join(ctx.parentDirectories[index], `.${path.basename(ctx.operations[index].path)}.${process.pid}.${randomBytes(12).toString("hex")}.publish-or-replace`);
          const captured = loaded.addon.publishProtectedFile(probe, Buffer.alloc(0), "windows-inherited", false);
          if (captured?.committed === true) {
            await unlink(probe);
            await syncDirectoryStrict(ctx.parentDirectories[index]);
          }
          if (!captured?.ok || !Buffer.isBuffer(captured.securityDescriptor)) {
            fail("persistence-failed", "prepare",
              `${ctx.operations[index].path} parent security descriptor cannot be captured before the first business byte`,
              ctx.operations[index].path);
          }
          const descriptor = Buffer.from(captured.securityDescriptor);
          const securityDigest = digest(descriptor);
          afterRecord = {
            sha256: entry.after.sha256,
            size: entry.after.size,
            permissions: {
              kind: "windows-security-v1",
              attributes: windowsPromisedAttributes(captured.attributes),
              securityDigest,
            },
            securityMaterial: {
              descriptorBase64: descriptor.toString("base64"),
              attributes: Number(captured.attributes) >>> 0,
            },
          };
        }
      }
    }
    entries.push({ before: beforeRecord, after: afterRecord, parentIdentity: ctx.parentIdentities[index] });
  }
  await syncDirectoriesStrict(
    [layout.beforeDir, layout.afterDir, layout.operationDir, layout.operationsRoot, layout.recoveryRoot],
    "prepare",
  );
  return entries;
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

async function recheckTarget(state, index) {
  const ctx = state.ctx;
  const operation = ctx.operations[index];
  const entry = ctx.entries[index];
  const parentStats = windowsRuntime()
    ? await requireRealDirectory(ctx.parentDirectories[index], `the parent directory of ${operation.path}`, {
      kind: "root-changed",
      phase: "apply",
    }).catch(() => null)
    : await lstat(ctx.parentDirectories[index]).catch(() => null);
  if (!sameIdentity(parentStats, ctx.parentIdentities[index])) {
    fail("root-changed", "apply", `the parent directory identity of ${operation.path} changed after preflight`, operation.path);
  }
  const observed = await observeTarget(ctx.absolutePaths[index]);
  if (operation.action === "create") {
    if (observed.status !== "missing") {
      fail("precondition-mismatch", "apply", `${operation.path} must still be absent before creation`, operation.path);
    }
    return;
  }
  if (observed.status === "missing") {
    fail("precondition-mismatch", "apply", `${operation.path} disappeared before its ${operation.action}`, operation.path);
  }
  if (observed.status !== "file" || observed.sha256 !== entry.before.sha256 ||
      observed.size !== entry.before.size ||
      (windowsRuntime()
        ? observed.securityDigest !== entry.before.permissions?.securityDigest
        : observed.mode !== entry.before.mode)) {
    fail("precondition-mismatch", "apply", `${operation.path} changed after preflight`, operation.path);
  }
}

async function applyOne(state, index, beforeMutation, context) {
  const ctx = state.ctx;
  const operation = ctx.operations[index];
  if (beforeMutation) {
    try { await beforeMutation(context); }
    catch (cause) { fail("apply-failed", "apply", `beforeMutation rejected ${operation.path}: ${cause?.message ?? "unknown"}`, operation.path); }
  }
  await recheckTarget(state, index);
  let failure = null;
  try {
    await runHook("beforeBusinessMutation", { index, path: operation.path });
    if (operation.action === "delete") {
      await unlink(ctx.absolutePaths[index]);
      await runHook("beforeDeleteDirectorySync", { index, path: operation.path });
      await syncDirectoryStrict(path.dirname(ctx.absolutePaths[index]));
    } else {
      if (windowsRuntime()) {
        const kind = operation.next.permissions?.kind === "windows-preserve" ? "windows-preserve" : "windows-inherited";
        await publishFileOrReplace(ctx.root, operation.path, operation.bytes, { permissions: { kind } });
      } else {
        await publishFileOrReplace(ctx.root, operation.path, operation.bytes, { mode: operation.next.mode });
      }
    }
  } catch (cause) {
    failure = cause;
  }
  await runHook("afterBusinessMutation", { index, path: operation.path, failure });
  if (failure !== null) {
    // A primitive failure never proves the site was left unwritten: the site
    // is observed before the per-path fact is fixed.
    const observed = await observeTarget(ctx.absolutePaths[index]);
    const indeterminate = failure?.details?.phase === "post-commit" ||
      failure?.details?.publicationState === "indeterminate" ||
      failure?.details?.publicationState === "published" ||
      classifyObserved(observed, ctx.entries[index]) === "expected-new";
    throw new FileSetFailure("apply-failed", "apply",
      `${operation.path} could not be applied (${failure?.message ?? "unknown"}, publicationState=${failure?.details?.publicationState ?? "unknown"}, observed=${classifyObserved(observed, ctx.entries[index])})`,
      operation.path, indeterminate);
  }
  if (classifyObserved(await observeTarget(ctx.absolutePaths[index]), ctx.entries[index]) !== "expected-new") {
    throw new FileSetFailure("apply-failed", "apply", `${operation.path} did not reach its frozen new state`, operation.path, true);
  }
}

async function runApplyLoop(state, options) {
  const ctx = state.ctx;
  for (let index = 0; index < ctx.operations.length; index += 1) {
    await runHook("beforeApplyIntent", { index });
    await appendFileSetEvent(state, { operationId: ctx.operationId, type: "apply-intent", index });
    await journalBarrier(state, "apply");
    notePath(state, index, { apply: "intent-recorded" });
    await runHook("afterApplyIntent", { index });
    const context = Object.freeze({ index, path: ctx.operations[index].path, action: ctx.operations[index].action });
    await applyOne(state, index, options.beforeMutation, context);
    await appendFileSetEvent(state, { operationId: ctx.operationId, type: "applied", index, current: "expected-new" });
    notePath(state, index, { apply: "applied", current: "expected-new" });
    if (options.afterMutation) {
      try { await options.afterMutation(context); }
      catch (cause) { fail("apply-failed", "apply", `afterMutation rejected ${context.path}: ${cause?.message ?? "unknown"}`, context.path); }
    }
  }
}

// ---------------------------------------------------------------------------
// Domain validation
// ---------------------------------------------------------------------------

async function runValidation(state, validate) {
  const ctx = state.ctx;
  const result = state.result;
  await appendFileSetEvent(state, { operationId: ctx.operationId, type: "validation-started" }, { phase: "validate" });
  await journalBarrier(state, "validate");
  const controller = new AbortController();
  const deadline = monotonicNow() + BigInt(ctx.validationTimeoutMs) * 1000000n;
  let timer = null;
  const timeoutPromise = new Promise((resolve) => {
    // The deadline timer is deliberately referenced: the guarantee is that a
    // caller who never settles still receives an auto-recovered result, so the
    // process must not be able to drain before the deadline fires.
    timer = setTimeout(() => {
      controller.abort();
      resolve({ kind: "timeout" });
    }, ctx.validationTimeoutMs);
  });
  let settled;
  try {
    settled = await Promise.race([
      Promise.resolve()
        .then(() => runHook("beforeValidation", {}))
        .then(() => validate({ root: ctx.root, operationId: ctx.operationId, signal: controller.signal }))
        .then(
          (value) => ({ kind: "returned", value }),
          (error) => ({ kind: "threw", error }),
        ),
      timeoutPromise,
    ]);
  } finally {
    clearTimeout(timer);
  }
  if (settled.kind === "threw" && controller.signal.aborted) settled = { kind: "timeout" };
  // A late completion never commits, even when it arrives after the deadline.
  if (settled.kind !== "timeout" && monotonicNow() >= deadline) settled = { kind: "timeout" };
  await runHook("afterValidation", { settled: settled.kind });

  let validation;
  if (settled.kind === "timeout") {
    validation = { status: "incomplete", reason: "timeout" };
  } else if (settled.kind === "threw") {
    const aborted = settled.error?.name === "AbortError" || settled.error?.code === "ABORT_ERR";
    validation = { status: "incomplete", reason: aborted ? "timeout" : "exception" };
  } else if (!isPlainObject(settled.value) || ownKeys(settled.value) !== "passed" || typeof settled.value.passed !== "boolean") {
    validation = { status: "incomplete", reason: "invalid-result" };
  } else if (settled.value.passed === false) {
    validation = { status: "failed", reason: "returned-false" };
  } else {
    validation = { status: "passed", reason: null };
  }
  result.validation = validation;
  await appendFileSetEvent(state, { operationId: ctx.operationId, type: "validation-finished", validation }, { phase: "validate" });
  await journalBarrier(state, "validate");
  return validation;
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/**
 * Re-proves the business ancestry of one frozen target from the authorized
 * root down to its parent directory and returns the parent's statistics.
 *
 * Containment alone is not enough: a link that points back inside the root
 * (`dir -> moved`) keeps every resolved path contained while addressing a
 * directory the plan never froze, and the end-of-chain parent identity check
 * cannot see it either, because the link sits above the parent. The contract
 * forbids symbolic-link traversal for the root, the parent directories and the
 * file alike, so every component is required to be one real directory.
 */
async function requireRealBusinessAncestry(state, index, phase) {
  const operation = state.ctx.operations[index];
  const segments = operation.path.split("/");
  let current = state.ctx.root;
  let stats = windowsRuntime()
    ? await requireRealDirectory(current, "the authorized business root", { phase }).catch(() => null)
    : await lstat(current).catch(() => null);
  if (stats === null || stats.isSymbolicLink() || !stats.isDirectory()) {
    fail("unsafe-path", phase, `the authorized root of ${operation.path} is not one real directory`, operation.path);
  }
  for (const segment of segments.slice(0, -1)) {
    current = path.join(current, segment);
    stats = windowsRuntime()
      ? await requireRealDirectory(current, "a business ancestor", { phase }).catch(() => null)
      : await lstat(current).catch(() => null);
    if (stats === null || stats.isSymbolicLink() || !stats.isDirectory()) {
      fail("unsafe-path", phase,
        `${operation.path} has a business ancestor that is not one real directory`, operation.path);
    }
  }
  // With a root-level target this is the authorized root itself, which is the
  // parent identity the prepared fact recorded.
  return stats;
}

/**
 * Re-proves one frozen business target immediately before this call reads or
 * writes it. Containment is checked again (an ancestor link that now escapes
 * the root is refused even though the recorded path never changed), every
 * ancestor must still be one real directory, and the parent must still be the
 * real directory whose identity the prepared fact saved. Drift stops the
 * affected write instead of acting on a site that is no longer the one the
 * plan froze. TOCTOU note: static drift is covered, a non-cooperating writer
 * racing this call is not.
 */
async function requireFrozenSite(state, index, phase) {
  const ctx = state.ctx;
  const operation = ctx.operations[index];
  let absolute;
  try {
    absolute = await resolveContained(ctx.root, operation.path);
  } catch (cause) {
    const kind = cause?.details?.kind === HARNESS_ERROR_KINDS.INVALID_ROOT ? "root-changed" : "unsafe-path";
    fail(kind, phase,
      `${operation.path} is no longer a contained business path (${cause?.details?.kind ?? cause?.code ?? "unknown"})`,
      operation.path);
  }
  const recorded = ctx.parentIdentities[index];
  if (recorded === undefined || recorded === null) {
    fail("recovery-corrupt", phase, `${operation.path} has no recorded parent directory identity`, operation.path);
  }
  const parentStats = await requireRealBusinessAncestry(state, index, phase);
  if (!sameIdentity(parentStats, recorded)) {
    fail("unsafe-path", phase,
      `the parent directory of ${operation.path} is no longer the directory the plan froze`, operation.path);
  }
  ctx.absolutePaths[index] = absolute;
  return absolute;
}

/** Guarded observation for path facts: an untrusted site is `unknown`. */
async function observeFrozenSite(state, index, phase) {
  try {
    const absolute = await requireFrozenSite(state, index, phase);
    return classifyObserved(await observeTarget(absolute), state.ctx.entries[index]);
  } catch {
    return "unknown";
  }
}

/**
 * The persisted terminal fact owns the write and restore history: a repeated
 * recovery reports the facts the operation already recorded instead of
 * re-deriving them from the current site. Only `current` describes this call.
 */
function recordedPathHistory(summary) {
  const terminal = summary.committed ?? summary.rolledBack ?? summary.recoveryRequired;
  return Array.isArray(terminal?.payload?.paths) ? terminal.payload.paths : null;
}

async function buildRecoveryPathFacts(state, summary) {
  const ctx = state.ctx;
  const recorded = recordedPathHistory(summary);
  state.recordedHistory = recorded;
  for (let index = 0; index < ctx.operations.length; index += 1) {
    const history = recorded?.[index] ?? null;
    if (history !== null) {
      notePath(state, index, {
        apply: history.apply,
        restore: history.restore,
        errorKinds: [...new Set([...state.result.paths[index].errorKinds, ...history.errorKinds])],
      });
    }
    if (!summary.intents.has(index)) {
      if (history === null) notePath(state, index, { apply: "not-started" });
      if (state.result.paths[index].current === "unknown") notePath(state, index, { current: "original" });
      continue;
    }
    const classification = await observeFrozenSite(state, index, "restore");
    notePath(state, index, { current: classification });
    if (history !== null) continue;
    notePath(state, index, { apply: recordedApplyHistory(summary, index, classification) });
    if (summary.restored.has(index)) {
      notePath(state, index, { restore: classification === "original" ? "already-original" : "restored" });
    }
  }
}

async function restoreOne(state, summary, index) {
  const ctx = state.ctx;
  const operation = ctx.operations[index];
  const entry = ctx.entries[index];
  let absolute;
  try {
    absolute = await requireFrozenSite(state, index, "restore");
  } catch (cause) {
    const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "recovery-corrupt", "restore");
    if (failure.kind === "root-changed" || failure.kind === "ownership-lost") throw failure;
    notePath(state, index, { restore: "failed" });
    notePathError(state, index, failure.kind);
    pushError(state.result, failure.kind, failure.message, failure.phase ?? "restore", operation.path);
    return { status: "failed" };
  }
  const classification = classifyObserved(await observeTarget(absolute), entry);
  notePath(state, index, { current: classification });
  const history = state.recordedHistory?.[index] ?? null;
  if (history !== null) notePath(state, index, { apply: history.apply });
  else notePath(state, index, { apply: recordedApplyHistory(summary, index, classification) });

  if (classification === "original") {
    if (!summary.restored.has(index)) {
      await appendFileSetEvent(state, { operationId: ctx.operationId, type: "restore-intent", index }, { unique: false, phase: "restore" });
      await journalBarrier(state, "restore");
      await appendFileSetEvent(state, { operationId: ctx.operationId, type: "restored", index, current: "original" }, { unique: false, phase: "restore" });
    }
    notePath(state, index, { restore: "already-original" });
    return { status: "already-original" };
  }
  if (classification === "unknown") {
    notePath(state, index, { restore: "unknown" });
    return { status: "unknown" };
  }
  if (classification !== "expected-new") {
    notePath(state, index, { restore: "conflict" });
    notePathError(state, index, "restore-conflict");
    pushError(state.result, "restore-conflict",
      `${operation.path} matches neither the original nor the frozen new state; the site is left untouched`,
      "restore", operation.path);
    return { status: "conflict" };
  }
  await appendFileSetEvent(state, { operationId: ctx.operationId, type: "restore-intent", index }, { unique: false, phase: "restore" });
  await journalBarrier(state, "restore");
  await runHook("afterRestoreIntent", { index });
  try {
    if (operation.action === "create") {
      // The inverse of a create is removing this call's own new file; the
      // site was just confirmed to hold exactly the frozen new bytes.
      await unlink(absolute);
      await runHook("beforeRestoreDirectorySync", { index, path: operation.path });
      await syncDirectoryStrict(path.dirname(absolute));
    } else {
      await requireMaterialAncestry(state.layout, state.layout.beforeDir, "the recorded original material directory", {
        kind: "recovery-corrupt",
        phase: "restore",
      });
      const material = await readMaterialFile(materialPath(state.layout, BEFORE_DIR_NAME, index), entry.before);
      if (material.status !== "ok") {
        fail("recovery-corrupt", "restore",
          `the recorded original bytes of ${operation.path} cannot be trusted (${material.code ?? material.status})`,
          operation.path);
      }
      await runHook("beforeRestoreMutation", { index, path: operation.path });
      if (windowsRuntime()) {
        if (!entry.before?.securityMaterial) {
          fail("recovery-corrupt", "restore", `${operation.path} has no Windows security material to restore`, operation.path);
        }
        const plan = planWindowsSecurityRestore(entry.before.securityMaterial);
        const descriptor = Buffer.from(plan.descriptorBase64, "base64");
        if (digest(descriptor) !== entry.before.permissions?.securityDigest) {
          fail("recovery-corrupt", "restore", `${operation.path} security material does not match its digest`, operation.path);
        }
        let loaded;
        try {
          loaded = await loadWindowsNativeAddon();
        } catch (cause) {
          fail("restore-failed", "restore", `win32-x64 native addon is not available (${cause?.message ?? "unknown"})`, operation.path);
        }
        const capable = loaded.addon.windowsRestoreCapable(descriptor, absolute, plan.attributes);
        if (capable?.ok !== true) {
          fail("restore-failed", "restore", `${operation.path} security material is not restorable by this user`, operation.path);
        }
        const native = loaded.addon.publishProtectedFile(
          absolute,
          material.bytes,
          "windows-restore",
          operation.action === "replace",
          descriptor,
          plan.attributes,
        );
        if (!native?.ok || native.flushFailed === true) {
          fail("restore-failed", "restore",
            `restoring ${operation.path} failed before a durable original-security write (${native?.failureReason ?? "flush-failed"})`,
            operation.path);
        }
        if (!Buffer.isBuffer(native.securityDescriptor) || digest(Buffer.from(native.securityDescriptor)) !== entry.before.permissions?.securityDigest) {
          fail("restore-failed", "restore", `${operation.path} did not keep its original security descriptor`, operation.path);
        }
      } else if (operation.action === "replace") {
        await replaceFileAtomic(ctx.root, operation.path, material.bytes, { mode: entry.before.mode });
      } else {
        await publishFileOrReplace(ctx.root, operation.path, material.bytes, { mode: entry.before.mode });
      }
    }
  } catch (cause) {
    if (cause instanceof FileSetFailure && cause.kind === "recovery-corrupt") {
      notePath(state, index, { restore: "failed" });
      notePathError(state, index, "recovery-corrupt");
      pushError(state.result, "recovery-corrupt", cause.message, "restore", operation.path);
      return { status: "corrupt" };
    }
    // The mutation may have failed after its commit point: the site is read
    // again so the reported observation is the latest safe one.
    notePath(state, index, { current: classifyObserved(await observeTarget(absolute), entry) });
    notePath(state, index, { restore: "failed" });
    notePathError(state, index, "restore-failed");
    pushError(state.result, "restore-failed", `restoring ${operation.path} failed: ${cause?.message ?? "unknown"}`, "restore", operation.path);
    return { status: "failed" };
  }
  await runHook("afterRestoreWrite", { index, path: operation.path });
  const restored = classifyObserved(await observeTarget(absolute), entry);
  notePath(state, index, { current: restored });
  if (restored !== "original") {
    notePath(state, index, { restore: "failed" });
    notePathError(state, index, "restore-failed");
    pushError(state.result, "restore-failed", `${operation.path} did not return to its original state`, "restore", operation.path);
    return { status: "failed" };
  }
  await appendFileSetEvent(state, { operationId: ctx.operationId, type: "restored", index, current: "original" }, { unique: false, phase: "restore" });
  notePath(state, index, { restore: "restored" });
  await runHook("afterRestoreMutation", { index });
  return { status: "restored" };
}

/**
 * Persists a business-terminal fact. A terminal append error never proves the
 * fact is absent: the ledger is re-read, and an unconfirmed strict barrier
 * keeps the operation out of the confirmed set.
 */
async function appendTerminalFact(state, payload) {
  let persisted = false;
  try {
    persisted = await appendFileSetEvent(state, payload, { unique: false, phase: "finalize" }) !== null;
  } catch (cause) {
    if (cause instanceof FileSetFailure && (cause.kind === "ownership-lost" || cause.kind === "root-changed")) throw cause;
    pushError(state.result, cause.kind ?? "persistence-failed", cause.message, "finalize");
    return false;
  }
  if (!persisted) {
    pushError(state.result, "persistence-failed", `${payload.type} event was not persisted`, "finalize");
    return false;
  }
  try {
    await journalBarrier(state, "finalize");
  } catch (cause) {
    pushError(state.result, "persistence-failed",
      `${payload.type} event is written but its strict sync barrier did not confirm: ${cause?.message ?? "unknown"}`, "finalize");
    return false;
  }
  return true;
}

async function runRecovery(state, summary) {
  const ctx = state.ctx;
  const result = state.result;
  result.recovery.attempted = true;
  const indices = [...summary.intents].sort((left, right) => right - left);
  const statuses = [];
  let blocked = false;
  try {
    const actual = await createFilesystemRootBinding(ctx.root);
    if (actual.digest !== ctx.rootBinding.digest) {
      throw new FileSetFailure("root-changed", "restore", "the authorized project root identity changed during recovery");
    }
  } catch (cause) {
    blocked = true;
    pushError(result, cause.kind ?? "root-changed", cause.message, "restore");
  }
  for (const index of indices) {
    if (blocked) break;
    let outcome;
    try {
      outcome = await restoreOne(state, summary, index);
    } catch (cause) {
      if (cause instanceof FileSetFailure && (cause.kind === "ownership-lost" || cause.kind === "root-changed")) {
        blocked = true;
        notePath(state, index, { restore: "unknown" });
        pushError(result, cause.kind, cause.message, "restore", ctx.operations[index].path);
        break;
      }
      const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "restore-failed", "restore");
      const kind = ["recovery-corrupt", "persistence-failed"].includes(failure.kind) ? failure.kind : "restore-failed";
      notePath(state, index, { restore: "failed" });
      notePathError(state, index, kind);
      pushError(result, kind, failure.message, "restore", ctx.operations[index].path);
      outcome = { status: "failed" };
    }
    statuses.push(outcome.status);
  }
  const safe = statuses.every((status) => status === "restored" || status === "already-original");
  const complete = !blocked && safe &&
    result.paths.every((entry) =>
      entry.restore === "restored" || entry.restore === "already-original" || entry.restore === "not-needed");
  const type = complete ? "rolled-back" : "recovery-required";
  await runHook("beforeTerminalEvent", { type });
  const confirmed = await appendTerminalFact(state, {
    operationId: ctx.operationId,
    type,
    paths: result.paths.map((entry) => ({ ...entry })),
    errorKinds: [...new Set(result.paths.flatMap((entry) => entry.errorKinds))],
  });
  result.outcome = complete && confirmed ? "rolled-back" : "recovery-required";
  result.recovery.status = !confirmed ? (blocked ? "blocked" : "partial")
    : complete ? "complete" : blocked ? "blocked" : "partial";
  return complete && confirmed;
}

async function recoverAfterFailure(state) {
  const result = state.result;
  try {
    state.events = await readAllEvents(state);
    attachStore(state);
    const summary = summarizeOperation(state.events, state.ctx.operationId);
    for (let index = 0; index < state.ctx.operations.length; index += 1) {
      state.ctx.absolutePaths[index] ??= path.resolve(state.ctx.root, state.ctx.operations[index].path);
      state.ctx.parentDirectories[index] ??= path.dirname(state.ctx.absolutePaths[index]);
      state.distinctParents.add(state.ctx.parentDirectories[index]);
    }
    await buildRecoveryPathFacts(state, summary);
    await runRecovery(state, summary);
  } catch (cause) {
    const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "recovery-corrupt", "restore");
    pushError(result, failure.kind, failure.message, "restore");
    result.recovery.attempted = true;
    result.recovery.status = failure.kind === "ownership-lost" || failure.kind === "root-changed" ? "blocked" : "partial";
    result.outcome = "recovery-required";
  }
}

/**
 * What the authoritative ledger says about the commit decision after an append
 * or strict-sync failure: `present` (a valid committed fact is durable),
 * `absent` (the ledger was read and holds no committed fact for this
 * operation) or `unknown` (the ledger itself cannot be read). An append error
 * alone never decides between those three.
 */
async function committedFactState(state) {
  try {
    const events = await readEvents(state.store);
    state.events = events;
    attachStore(state);
    return summarizeOperation(events, state.ctx.operationId).committed !== null ? "present" : "absent";
  } catch {
    return "unknown";
  }
}

async function commitOperation(state) {
  const ctx = state.ctx;
  const result = state.result;
  const problems = [];
  for (let index = 0; index < ctx.operations.length; index += 1) {
    const classification = classifyObserved(await observeTarget(ctx.absolutePaths[index]), ctx.entries[index]);
    notePath(state, index, { current: classification });
    if (classification !== "expected-new") problems.push(ctx.operations[index].path);
  }
  if (problems.length > 0) {
    // No committed fact exists yet: the group never reached its frozen new
    // state, so the pre-commit recovery path owns it. The drifted path keeps
    // its external content and is reported as a conflict; other paths return
    // to their original bytes.
    pushError(result, "apply-failed",
      `the frozen new state was not reached before the commit decision: ${problems.join(", ")}`, "finalize");
    await recoverAfterFailure(state);
    return;
  }
  await runHook("beforeTerminalEvent", { type: "committed" });
  let confirmed = false;
  let blocked = false;
  try {
    confirmed = await appendTerminalFact(state, {
      operationId: ctx.operationId,
      type: "committed",
      paths: result.paths.map((entry) => ({ ...entry })),
      errorKinds: [...new Set(result.paths.flatMap((entry) => entry.errorKinds))],
    });
  } catch (cause) {
    // The append proved that the exclusive right to write this journal (or the
    // authorized root) is gone, so no terminal fact can be persisted any more.
    // Success is never reported from the attempted status; the ledger is still
    // consulted so an already durable commit decision is not reversed.
    blocked = true;
    const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "persistence-failed", "finalize");
    pushError(result, failure.kind, failure.message, failure.phase ?? "finalize");
  }
  if (confirmed) {
    // Only a durable commit fact with its strict sync confirmation returns
    // committed.
    result.outcome = "committed";
    for (const entry of result.paths) entry.current = "expected-new";
    result.materials.durable = true;
    return;
  }
  const factState = await committedFactState(state);
  if (factState === "present") {
    // A valid commit decision is durable and is never rolled back; only its
    // strict sync confirmation is missing. Re-reading the ledger is the same
    // confirmation work the recovery entry reports, so the attempt is shown.
    result.outcome = "commit-unconfirmed";
    result.recovery.attempted = true;
    result.recovery.status = "blocked";
    return;
  }
  if (factState === "absent" && !blocked) {
    // The ledger was read and holds no committed fact: there is no commit
    // decision to confirm, so the group is rolled back instead of being
    // reported as an unconfirmed commit that a later recovery would reverse.
    await recoverAfterFailure(state);
    return;
  }
  // Either the ledger cannot be read, or the exclusive right is already gone:
  // no success is claimed, no further write is attempted and no automatic
  // rollback is started without a trustworthy journal. The recorded facts and
  // all materials are preserved for a later explicit recovery under the
  // maintenance conditions of the contract.
  result.outcome = "recovery-required";
  result.recovery.attempted = true;
  result.recovery.status = "blocked";
}

// ---------------------------------------------------------------------------
// Prepared-plan reconstruction
// ---------------------------------------------------------------------------

function rebuildContextFromPrepared(state, summary) {
  const ctx = state.ctx;
  const prepared = summary.prepared.payload;
  const operations = prepared.request.operations.map((operation) => ({
    path: operation.path,
    action: operation.action,
    expected: operation.expected,
    next: operation.next,
    bytes: null,
  }));
  ctx.operations = operations;
  ctx.entries = prepared.entries.map((entry) => ({ before: entry.before, after: entry.after }));
  ctx.parentIdentities = prepared.entries.map((entry) => entry.parentIdentity);
  ctx.absolutePaths = operations.map((operation) => path.resolve(ctx.root, operation.path));
  ctx.parentDirectories = ctx.absolutePaths.map((absolute) => path.dirname(absolute));
  ctx.validationTimeoutMs = prepared.request.validationTimeoutMs;
  ctx.projection = prepared.request;
  state.materialIdentity = prepared.materialIdentity;
  state.result.paths = operations.map((operation) => newPathResult(operation));
  for (const absolute of ctx.parentDirectories) state.distinctParents.add(absolute);
}

async function loadPreparedOperation(state, summary, { allowMissingMaterialRoot = false } = {}) {
  if (summary.mine.length === 0 || summary.prepared === null) {
    state.result.preflight = "failed";
    fail("operation-not-found", "preflight", `operation ${state.ctx.operationId} has no prepared fact in this journal`);
  }
  const prepared = summary.prepared.payload;
  rebuildContextFromPrepared(state, summary);
  if (path.resolve(prepared.request.root) !== path.resolve(state.ctx.root)) {
    state.result.preflight = "failed";
    fail("recovery-corrupt", "preflight", "the prepared plan was recorded for a different business root");
  }
  if (prepared.rootBinding.digest !== state.ctx.rootBinding.digest) {
    state.result.preflight = "failed";
    fail("root-changed", "preflight", "the authorized root binding changed since the plan was prepared");
  }
  const stats = await requireRealDirectory(state.layout.operationDir, "operation material directory", { protectedMaterial: true }).catch(() => null);
  // A durable cleanup intent of an exactly terminated operation explains a
  // missing material directory: that is the recorded intermediate state of a
  // cleanup whose removal finished before its terminal fact. Only the trusted
  // combination of valid terminal, valid intent and trusted path conditions
  // accepts it; every other absence stays corruption.
  const cleanupInterrupted = allowMissingMaterialRoot && summary.pruneIntent !== null && summary.terminal !== null;
  if (stats === null && cleanupInterrupted) {
    state.result.preflight = "passed";
    return;
  }
  if (stats === null || stats.isSymbolicLink() || !stats.isDirectory()) {
    state.result.preflight = "failed";
    fail("recovery-corrupt", "preflight", "the operation material directory cannot be read");
  }
  if (state.materialIdentity !== undefined && state.materialIdentity !== null && !sameIdentity(stats, state.materialIdentity)) {
    state.result.preflight = "failed";
    fail("recovery-corrupt", "preflight", "the operation material directory identity changed");
  }
  state.result.preflight = "passed";
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

export async function inspectFileSetRecovery(request) {
  let phase = "input";
  try {
    if (!isPlainObject(request) || ownKeys(request) !== "environment,recoveryRelPath,root,rootBinding" ||
        canonicalizeWindowsDriveAbsolute(request.root) !== request.root || request.recoveryRelPath !== RECOVERY_REL_PATH ||
        !["filesystem", "cooperativeWriters,filesystem"].includes(ownKeys(request.environment)) || request.environment.filesystem !== "ntfs" ||
        (Object.hasOwn(request.environment, "cooperativeWriters") && request.environment.cooperativeWriters !== true)) {
      fail("invalid-request", "input", "inspectFileSetRecovery requires the canonical Windows root, original binding and explicit NTFS read-only environment");
    }
    assertSchemaValid(request.rootBinding, findSchemaByObject("filesystem-root-binding").$id, "root binding");
    if (request.rootBinding.basis !== "canonical-finalpath-volume-fileid-type-security-v1") fail("invalid-request", "input", "inspection requires the Windows root binding");
    if (!windowsRuntime()) fail("unsupported-environment", "input", "Windows recovery inspection requires the Windows runtime");
    phase = "preflight";
    try { await assertRootBindingMatches(request); }
    catch (cause) { fail("root-changed", "preflight", cause.message); }
    const { addon } = await loadWindowsNativeAddon();
    const rootFact = addon.captureSecurity(request.root);
    if (!rootFact?.ok || rootFact.filesystem !== "NTFS") fail("unsupported-environment", "preflight", "recovery inspection requires an actually observed NTFS root");
    const recoveryRoot = path.join(request.root, RECOVERY_REL_PATH);
    const stats = await lstat(recoveryRoot).catch(cause => { if (cause?.code === "ENOENT") return null; throw cause; });
    if (stats === null) {
      await assertRootBindingMatches(request);
      if (await lstat(recoveryRoot).catch(cause => { if (cause?.code === "ENOENT") return null; throw cause; })) fail("recovery-corrupt", "preflight", "recovery root appeared during inspection");
      return { status: "absent", error: null };
    }
    const directories = new Map();
    const materials = new Map();
    const inspectDirectory = async (directory) => {
      const identity = await requireRealDirectory(directory, "inspected file-set directory", { protectedMaterial: true, kind: "recovery-corrupt", phase: "preflight" });
      const members = await readdir(directory, { withFileTypes: true });
      const current = await requireRealDirectory(directory, "inspected file-set directory", { protectedMaterial: true, kind: "recovery-corrupt", phase: "preflight" });
      const fact = value => ({ identity: identityOf(value), mtimeMs: value.mtimeMs, ctimeMs: value.ctimeMs });
      if (digestDocument(fact(identity)) !== digestDocument(fact(current))) fail("recovery-corrupt", "preflight", "file-set directory changed while enumerating");
      const observed = { identity: fact(identity), members: members.map(entry => [entry.name, entry.isDirectory() ? "directory" : entry.isFile() ? "file" : "unsafe"]).sort((left, right) => left[0].localeCompare(right[0])) };
      if (directories.has(directory) && digestDocument(directories.get(directory)) !== digestDocument(observed)) fail("recovery-corrupt", "preflight", "file-set directory or member set changed during inspection");
      directories.set(directory, observed);
      return members;
    };
    await requireRecoveryRoot(request.root);
    for (const { name } of await inspectDirectory(recoveryRoot)) {
      if (name !== JOURNAL_DIR_NAME && name !== OPERATIONS_DIR_NAME) fail("recovery-corrupt", "preflight", "unregistered entry in file-set recovery root");
    }
    const journalRoot = path.join(recoveryRoot, JOURNAL_DIR_NAME);
    const journal = await lstat(journalRoot).catch(cause => { if (cause?.code === "ENOENT") return null; throw cause; });
    if (journal) await requireMaterialDirectory(journalRoot, "file-set journal root", { kind: "recovery-corrupt", phase: "preflight" });
    const journalObservation = journal ? await readStateStoreEventsReadOnly(journalRoot, { payloadSchemas: PAYLOAD_SCHEMAS }) : null;
    const events = journalObservation?.records ?? [];
    const ids = journalOperationIds(events);
    const operationsRoot = path.join(recoveryRoot, OPERATIONS_DIR_NAME);
    const operations = await lstat(operationsRoot).catch(cause => { if (cause?.code === "ENOENT") return null; throw cause; });
    if (operations) await requireMaterialDirectory(operationsRoot, "file-set operations root", { kind: "recovery-corrupt", phase: "preflight" });
    for (const entry of operations ? await inspectDirectory(operationsRoot) : []) {
      if (!entry.isDirectory() || entry.isSymbolicLink() || !ids.has(entry.name)) fail("recovery-corrupt", "preflight", "unknown or unsafe file-set operation material");
    }
    for (const operationId of ids) {
      const summary = summarizeOperation(events, operationId);
      if (!summary.prepared || summary.terminal === null) fail("unfinished-operation", "preflight", "a file-set operation is not terminated");
      const prepared = summary.prepared.payload;
      if (digestDocument(prepared.request) !== prepared.requestDigest || prepared.request.operationId !== operationId ||
          prepared.request.schemaVersion !== 2 || prepared.entries.length !== prepared.request.operations.length) {
        fail("recovery-corrupt", "preflight", "prepared file-set facts do not bind their original request");
      }
      assertSchemaValid(prepared.request, APPLY_REQUEST_SCHEMA_ID, "recorded apply request");
      const state = newState("recover");
      state.ctx = { root: request.root, rootBinding: request.rootBinding, operationId, environment: request.environment };
      state.layout = layoutOf(request.root, operationId);
      await loadPreparedOperation(state, summary, { allowMissingMaterialRoot: summary.pruneIntent !== null });
      if (summary.pruned !== null) {
        if (await lstat(state.layout.operationDir).catch(cause => { if (cause?.code === "ENOENT") return null; throw cause; })) {
          fail("recovery-corrupt", "preflight", "pruned file-set operation unexpectedly has material");
        }
        continue;
      }
      // A durable cleanup intent explains only missing known materials. It
      // never authorizes an unknown entry or a changed surviving byte.
      const cleanup = summary.pruneIntent !== null;
      for (const { name } of await (cleanup && !await lstat(state.layout.operationDir).catch(cause => { if (cause?.code === "ENOENT") return null; throw cause; }) ? [] : inspectDirectory(state.layout.operationDir))) {
        if (name !== BEFORE_DIR_NAME && name !== AFTER_DIR_NAME) fail("recovery-corrupt", "preflight", "unknown file-set material directory");
      }
      for (const [directoryName, key] of [[BEFORE_DIR_NAME, "before"], [AFTER_DIR_NAME, "after"]]) {
        const directory = path.join(state.layout.operationDir, directoryName);
        const exists = await lstat(directory).catch(cause => { if (cause?.code === "ENOENT") return null; throw cause; });
        if (!exists && !cleanup) fail("recovery-corrupt", "preflight", "required file-set material directory is missing");
        if (exists) await requireMaterialAncestry(state.layout, directory, "file-set historical material", { kind: "recovery-corrupt", phase: "preflight" });
        const expected = new Map(prepared.entries.flatMap((entry, index) => entry[key] === null ? [] : [[path.basename(materialPath(state.layout, directoryName, index)), entry[key]]]));
        for (const entry of exists ? await inspectDirectory(directory) : []) {
          if (!entry.isFile() || !expected.has(entry.name)) fail("recovery-corrupt", "preflight", "unregistered historical material entry");
        }
        for (const [name, frozen] of expected) {
          if (key === "before") {
            const restore = planWindowsSecurityRestore(frozen.securityMaterial);
            if (digest(Buffer.from(restore.descriptorBase64, "base64")) !== frozen.permissions.securityDigest) fail("recovery-corrupt", "preflight", "historical security material digest mismatch");
          }
          const file = path.join(directory, name);
          const read = await readMaterialFile(file, frozen);
          materials.set(file, { frozen, status: read.status, observation: read.observation });
          if (!(read.status === "ok" || (cleanup && read.status === "missing"))) fail("recovery-corrupt", "preflight", "historical file-set material is missing or corrupt");
        }
      }
    }
    if (journalObservation) await journalObservation.revalidate();
    for (const [file, expected] of materials) {
      const current = await readMaterialFile(file, expected.frozen);
      if (current.status !== expected.status || digestDocument(current.observation ?? null) !== digestDocument(expected.observation ?? null)) fail("recovery-corrupt", "preflight", "historical material changed during inspection");
    }
    for (const directory of [...directories.keys()]) await inspectDirectory(directory);
    if (!journal && await lstat(journalRoot).catch(cause => { if (cause?.code === "ENOENT") return null; throw cause; })) fail("recovery-corrupt", "preflight", "journal appeared during inspection");
    if (!operations && await lstat(operationsRoot).catch(cause => { if (cause?.code === "ENOENT") return null; throw cause; })) fail("recovery-corrupt", "preflight", "operation materials appeared during inspection");
    await assertRootBindingMatches(request);
    return { status: "admitted", error: null };
  } catch (cause) {
    const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "recovery-corrupt", phase);
    return { status: "refused", error: { code: "SFC2004", message: failure.message,
      details: { kind: failure.kind, phase, ...(failure.relPath === undefined ? {} : { path: failure.relPath }) } } };
  }
}

export async function applyFileSet(request, options = {}) {
  const state = newState("apply");
  const result = state.result;
  try {
    if (typeof options?.validate !== "function") {
      fail("invalid-request", "input", "applyFileSet requires a trusted validate function; a missing one never auto-passes");
    }
    for (const name of ["beforeMutation", "afterMutation"]) {
      if (options[name] !== undefined && typeof options[name] !== "function") {
        fail("invalid-request", "input", `${name} must be a trusted function when supplied`);
      }
    }
    const ctx = parseApplyRequest(request);
    state.ctx = ctx;
    state.layout = layoutOf(ctx.root, ctx.operationId);
    result.operationId = ctx.operationId;
    result.paths = ctx.operations.map((operation) => newPathResult(operation));

    await assertRootBindingMatches(ctx);
    await requireRecoveryRoot(ctx.root);
    // Environment gate before the journal is opened: a cross-device topology is
    // refused before any mechanism write, so no journal or material is created
    // on a device the request may not use.
    await assertSingleDeviceTopology(state);
    await runHook("beforeJournalOpen", {});
    state.store = await openJournalWriter(state, "file-set");
    state.events = await readAllEvents(state);
    attachStore(state);
    await assertOperationIdReusable(state);
    assertNoUnfinishedOperation(state);

    if (!await runPreflight(state)) {
      result.preflight = "failed";
      result.outcome = "rejected";
      return result;
    }
    result.preflight = "passed";

    // The whole group is frozen: every original byte, every new byte and the
    // exact request copy become durable before the first business write.
    ctx.entries = await prepareMaterials(state).catch((cause) => {
      if (cause instanceof FileSetFailure) throw cause;
      const kind = cause?.details?.kind;
      if (kind === HARNESS_ERROR_KINDS.MISSING_RESOURCE || kind === HARNESS_ERROR_KINDS.CONTENT_GUARD_REJECTED) {
        throw new FileSetFailure("precondition-mismatch", "prepare", cause.message, cause?.details?.path);
      }
      throw mapStoreFailure(cause, "persistence-failed", "prepare");
    });
    result.materials.status = "retained";
    await runHook("afterMaterialWrite", {});
    await appendFileSetEvent(state, {
      operationId: ctx.operationId,
      type: "prepared",
      request: ctx.projection,
      requestDigest: digestDocument(ctx.projection),
      rootBinding: ctx.rootBinding,
      materialIdentity: state.materialIdentity,
      entries: ctx.entries,
    }, { unique: true, phase: "prepare" });
    await journalBarrier(state, "prepare", [state.layout.operationsRoot, state.layout.recoveryRoot]);
    result.materials.durable = true;
    await runHook("afterPreparedEvent", {});

    try {
      await runApplyLoop(state, options);
    } catch (cause) {
      markApplyFailure(state, cause);
      await recoverAfterFailure(state);
      return result;
    }

    let validation;
    try {
      validation = await runValidation(state, options.validate);
    } catch (cause) {
      // A validation-phase log append or strict-sync failure happens before any
      // commit decision: it belongs to the same pre-commit auto-recovery path
      // as every other pre-commit failure, and the original reason is kept
      // instead of escaping to the outer catch, which recovers nothing.
      const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "persistence-failed", "validate");
      pushError(result, failure.kind, failure.message, failure.phase ?? "validate");
      await recoverAfterFailure(state);
      return result;
    }
    if (validation.status !== "passed") {
      const kind = validation.status === "failed" ? "validation-failed" : "validation-incomplete";
      pushError(result, kind, `domain validation did not pass (${validation.reason})`, "validate");
      for (const entry of result.paths) if (!entry.errorKinds.includes(kind)) entry.errorKinds.push(kind);
      await recoverAfterFailure(state);
      return result;
    }
    await commitOperation(state);
    return result;
  } catch (cause) {
    absorbFailure(state, cause);
    return result;
  } finally {
    result.materials.status = await finalMaterialStatus(state);
    result.materials.adjacentStaging = await scanAdjacentStaging([...state.distinctParents]).catch(() => "possible-unknown");
    await releaseStore(state);
    finalizeBusinessWrite(state);
  }
}

function newState(operation) {
  return {
    result: baseResult(operation, null),
    store: null,
    events: null,
    knownKeys: new Set(),
    distinctParents: new Set(),
    materialIdentity: null,
  };
}

async function assertOperationIdReusable(state) {
  const ctx = state.ctx;
  if (journalOperationIds(state.events).has(ctx.operationId)) {
    fail("operation-id-reused", "preflight", `operationId ${ctx.operationId} already exists in this project journal`);
  }
  const entries = await listOperationDirectories(state.layout);
  if (entries.some((entry) => entry.name === ctx.operationId)) {
    // Orphan materials without a prepared fact are never deleted and their
    // id is never reused; manual handling is required.
    fail("operation-id-reused", "preflight",
      `materials for ${ctx.operationId} exist without a prepared fact; manual handling is required`);
  }
}

function assertNoUnfinishedOperation(state) {
  for (const id of journalOperationIds(state.events)) {
    const summary = summarizeOperation(state.events, id);
    if (summary.terminal === null && summary.pruned === null) {
      fail("unfinished-operation", "preflight", `operation ${id} is not terminated; recover it before a new apply`);
    }
  }
}

function markApplyFailure(state, cause) {
  const ctx = state.ctx;
  const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "apply-failed", "apply");
  const index = failure.relPath === undefined
    ? -1
    : ctx.operations.findIndex((operation) => operation.path === failure.relPath);
  pushError(state.result, failure.kind, failure.message, failure.phase, failure.relPath);
  if (index >= 0) {
    if (!state.result.paths[index].errorKinds.includes(failure.kind)) state.result.paths[index].errorKinds.push(failure.kind);
    if (failure.indeterminate || (failure.kind === "apply-failed" && state.result.paths[index].apply !== "applied")) state.result.paths[index].apply = "unknown";
  }
}

function absorbFailure(state, cause) {
  const result = state.result;
  const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "invalid-request", "input");
  pushError(result, failure.kind, failure.message, failure.phase, failure.relPath);
  if (result.preflight === "not-run" && failure.phase !== "input") result.preflight = "failed";
}

export async function recoverFileSet(request) {
  const state = newState("recover");
  const result = state.result;
  try {
    assertSchemaValid(request, RECOVERY_REQUEST_SCHEMA_ID, "recovery request");
    validateEnvironment(request.environment);
    const shared = parseSharedRequest(request);
    state.ctx = { ...shared, maintenance: parseMaintenance(request, shared.root) };
    state.layout = layoutOf(shared.root, shared.operationId);
    result.operationId = shared.operationId;
    await assertRootBindingMatches(shared);
    await requireRecoveryRoot(shared.root);
    await assertSingleDeviceTopology(state);
    state.store = await openJournalMaintenance(state, "file-set-recovery");
    state.events = await readAllEvents(state);
    attachStore(state);
    const summary = summarizeOperation(state.events, shared.operationId);
    await loadPreparedOperation(state, summary);
    // The frozen plan's targets are only known once it is loaded, so the device
    // topology is re-checked over the recovered plan before any restore write.
    await assertSingleDeviceTopology(state);
    return await runRecoverFlow(state, summary);
  } catch (cause) {
    absorbFailure(state, cause);
    return result;
  } finally {
    result.materials.status = await finalMaterialStatus(state);
    result.materials.adjacentStaging = await scanAdjacentStaging([...state.distinctParents]).catch(() => "possible-unknown");
    await releaseStore(state);
    finalizeBusinessWrite(state);
  }
}

async function runRecoverFlow(state, summary) {
  const ctx = state.ctx;
  const result = state.result;
  await buildRecoveryPathFacts(state, summary);

  if (summary.pruned !== null) {
    result.outcome = "already-pruned";
    result.materials.status = "pruned";
    return result;
  }
  if (summary.committed !== null) {
    // An existing valid commit decision is never rolled back; recovery only
    // confirms it. The confirmation work is the recovery attempt itself.
    result.recovery.attempted = true;
    const problems = [];
    for (let index = 0; index < ctx.operations.length; index += 1) {
      // The confirmation reuses the frozen-site observation: a target whose
      // ancestry or parent directory is no longer the one the plan froze is
      // `unknown`, never a silently re-read leaf that overrides the drift.
      const classification = await observeFrozenSite(state, index, "finalize");
      notePath(state, index, { current: classification });
      if (classification !== "expected-new") problems.push(ctx.operations[index].path);
    }
    if (problems.length > 0) {
      pushError(result, "commit-unconfirmed",
        `committed targets no longer match the frozen new state: ${problems.join(", ")}`, "finalize");
      result.outcome = "commit-unconfirmed";
      result.recovery.status = "blocked";
      return result;
    }
    for (const entry of result.paths) entry.current = "expected-new";
    try {
      await journalBarrier(state, "finalize");
    } catch (cause) {
      pushError(result, "commit-unconfirmed",
        `the commit decision is persisted but its strict sync barrier did not confirm: ${cause?.message ?? "unknown"}`, "finalize");
      result.outcome = "commit-unconfirmed";
      result.recovery.status = "blocked";
      return result;
    }
    result.outcome = "already-committed";
    result.recovery.status = "complete";
    result.materials.durable = true;
    return result;
  }
  if (summary.terminal === "rolled-back") {
    result.outcome = "already-rolled-back";
    result.recovery.attempted = true;
    result.recovery.status = "complete";
    result.materials.durable = true;
    return result;
  }
  if (summary.pruneIntent !== null && summary.pruned === null) {
    // An interrupted cleanup of an exactly terminated operation is resumed by
    // the same entry point instead of being restarted as a business recovery.
    await resumePrune(state, summary);
    return result;
  }
  if (summary.intents.size === 0) {
    // Prepared with no business intent: no business write ever happened.
    result.recovery.attempted = true;
    await runHook("beforeTerminalEvent", { type: "rolled-back" });
    const confirmed = await appendTerminalFact(state, {
      operationId: ctx.operationId,
      type: "rolled-back",
      paths: result.paths.map((entry) => ({ ...entry })),
      errorKinds: [],
    });
    result.outcome = confirmed ? "rolled-back" : "recovery-required";
    result.recovery.status = confirmed ? "complete" : "partial";
    result.materials.durable = confirmed;
    return result;
  }
  await runRecovery(state, summary);
  result.materials.durable = true;
  return result;
}

// ---------------------------------------------------------------------------
// Prune
// ---------------------------------------------------------------------------

export async function pruneFileSetRecovery(request) {
  const state = newState("prune");
  const result = state.result;
  try {
    assertSchemaValid(request, PRUNE_REQUEST_SCHEMA_ID, "prune request");
    validateEnvironment(request.environment);
    const shared = parseSharedRequest(request);
    state.ctx = { ...shared, maintenance: parseMaintenance(request, shared.root) };
    state.layout = layoutOf(shared.root, shared.operationId);
    result.operationId = shared.operationId;
    await assertRootBindingMatches(shared);
    await requireRecoveryRoot(shared.root);
    await assertSingleDeviceTopology(state);
    // Prune takes the normal writer when nothing is left over, and only uses
    // the explicit maintenance takeover the caller provided.
    state.store = state.ctx.maintenance === null
      ? await openJournalWriter(state, "file-set-prune")
      : await openJournalMaintenance(state, "file-set-prune");
    state.events = await readAllEvents(state);
    attachStore(state);
    const summary = summarizeOperation(state.events, shared.operationId);
    if (summary.pruned !== null) {
      // A repeated prune of a cleaned operation is answered before any
      // material is expected: the cleaned materials are gone by design.
      rebuildRecordedPaths(state, summary);
      result.preflight = "passed";
      result.outcome = "already-pruned";
      result.materials.status = "pruned";
      return result;
    }
    await loadPreparedOperation(state, summary, {
      allowMissingMaterialRoot: summary.pruneIntent !== null && summary.pruned === null,
    });
    // Same re-check as recovery: the cleaned operation's recorded targets are
    // known here, and a cross-device site keeps the whole group refused.
    await assertSingleDeviceTopology(state);
    rebuildRecordedPaths(state, summary);
    if (summary.terminal === null) {
      fail("prune-refused", "preflight",
        `operation ${shared.operationId} is not terminated and cannot be cleaned`);
    }
    await appendFileSetEvent(state, { operationId: shared.operationId, type: "prune-intent" }, { unique: true, phase: "prune" });
    await journalBarrier(state, "prune");
    await runHook("afterPruneIntent", {});
    try {
      await resumePrune(state, summary);
    } catch (cause) {
      // A cleanup that stops half way never reports success: the refusal and
      // the material facts stay truthful and a retry resumes the same plan.
      const failure = cause instanceof FileSetFailure ? cause
        : new FileSetFailure("prune-refused", "prune", `material cleanup did not finish (${cause?.message ?? "unknown"})`);
      pushError(result, failure.kind, failure.message, failure.phase ?? "prune");
      return result;
    }
    return result;
  } catch (cause) {
    absorbFailure(state, cause);
    return result;
  } finally {
    result.materials.status = await finalMaterialStatus(state);
    result.materials.adjacentStaging = await scanAdjacentStaging([...state.distinctParents]).catch(() => "possible-unknown");
    await releaseStore(state);
    if (result.outcome === "already-pruned" || result.outcome === "pruned") result.materials.status = "pruned";
    finalizeBusinessWrite(state);
  }
}

/** Prune reports the recorded per-path facts and never touches business targets. */
function rebuildRecordedPaths(state, summary) {
  const terminal = summary.committed ?? summary.rolledBack ?? summary.recoveryRequired;
  if (terminal) {
    state.result.paths = terminal.payload.paths.map((entry) => ({ ...entry, errorKinds: [...entry.errorKinds] }));
    return;
  }
  state.result.paths = state.ctx.operations.map((operation) => newPathResult(operation));
}

async function resumePrune(state, summary) {
  const ctx = state.ctx;
  const result = state.result;
  try {
    await pruneMaterials(state, summary);
  } catch (cause) {
    const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "prune-refused", "prune");
    pushError(result, failure.kind, failure.message, "prune");
    result.outcome = "recovery-required";
    result.recovery.attempted = true;
    result.recovery.status = "partial";
    return result;
  }
  try {
    await appendFileSetEvent(state, { operationId: ctx.operationId, type: "pruned" }, { unique: true, phase: "prune" });
    await journalBarrier(state, "prune");
  } catch (cause) {
    // The materials are already removed and the intent is durable: the cleanup
    // is unfinished, not successful, and a retry explains the same recorded
    // intermediate state and completes the terminal fact.
    const failure = cause instanceof FileSetFailure ? cause : mapStoreFailure(cause, "persistence-failed", "prune");
    pushError(result, failure.kind, failure.message, failure.phase ?? "prune");
    result.outcome = "recovery-required";
    result.recovery.attempted = true;
    result.recovery.status = "partial";
    return result;
  }
  result.outcome = "pruned";
  result.materials.status = "pruned";
  result.materials.durable = true;
  result.recovery.attempted = true;
  result.recovery.status = "complete";
  return result;
}

/**
 * Removes exactly the registered material files of one terminated operation.
 * Unknown entries are never removed — not even when their name looks like a
 * primitive staging name — and the journal is never touched.
 */
async function pruneMaterials(state) {
  const ctx = state.ctx;
  const layout = state.layout;
  // A cleanup only proceeds inside the registered material layout. A missing
  // directory is the recorded intermediate state of an interrupted cleanup; a
  // linked or replaced one anywhere between the mechanism root and the
  // material directory is refused before anything inside it is removed, so a
  // linked `operations/` level can never redirect the removal out of the
  // authorized root.
  for (const [directory, label] of [
    [layout.beforeDir, "the recorded original material directory"],
    [layout.afterDir, "the recorded new material directory"],
    [layout.operationDir, "the operation material directory"],
  ]) {
    if (await lstat(directory).catch(() => null) === null) continue;
    await requireMaterialAncestry(layout, directory, label, { kind: "prune-refused", phase: "prune" });
  }
  const registered = new Map();
  for (let index = 0; index < ctx.operations.length; index += 1) {
    if (ctx.entries[index].before !== null) {
      registered.set(materialPath(layout, BEFORE_DIR_NAME, index), ctx.entries[index].before);
    }
    if (ctx.entries[index].after !== null) {
      registered.set(materialPath(layout, AFTER_DIR_NAME, index), ctx.entries[index].after);
    }
  }
  for (const directory of [layout.beforeDir, layout.afterDir]) {
    const entries = await readdir(directory, { withFileTypes: true }).catch((cause) => {
      if (cause?.code === "ENOENT") return null;
      throw cause;
    });
    if (entries === null) continue;
    for (const entry of entries) {
      const file = path.join(directory, entry.name);
      if (!registered.has(file) || !entry.isFile()) {
        fail("prune-refused", "prune",
          `unregistered material entry ${path.relative(layout.operationDir, file)} is never removed`);
      }
    }
    for (const entry of entries) {
      const file = path.join(directory, entry.name);
      const read = await readMaterialFile(file, registered.get(file));
      if (read.status === "missing") continue;
      if (read.status !== "ok") {
        fail("prune-refused", "prune",
          `material entry ${path.relative(layout.operationDir, file)} is not the registered material`);
      }
      await runHook("beforePruneUnlink", { path: file });
      const current = await lstat(file).catch(() => null);
      if (current === null || !current.isFile() || current.nlink !== 1) {
        fail("prune-refused", "prune", "a material entry changed before removal");
      }
      await unlink(file);
      await syncDirectoryStrict(directory);
    }
  }
  for (const directory of [layout.beforeDir, layout.afterDir, layout.operationDir]) {
    // rmdir removes only an empty directory: any unregistered leftover keeps
    // the refusal and the directory instead of being swept away.
    try {
      await rmdir(directory);
    } catch (cause) {
      if (cause?.code === "ENOENT") continue;
      fail("prune-refused", "prune", `material directory ${path.basename(directory)} is not empty or cannot be removed`);
    }
    await syncDirectoryStrict(path.dirname(directory));
  }
}