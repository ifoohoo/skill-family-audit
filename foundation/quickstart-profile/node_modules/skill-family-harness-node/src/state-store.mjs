import { constants as FS_CONSTANTS } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import { randomBytes } from "node:crypto";
import path from "node:path";
import process from "node:process";
import {
  canonicalJson,
  compileSchema,
  detectDialect,
  digestDocument,
  findSchemaByObject,
} from "skill-family-contracts";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { validateContractDocument } from "./validation.mjs";

export const STATE_GENESIS_DIGEST = "0".repeat(64);

const EVENT_SCHEMA_ID = findSchemaByObject("state-event-envelope").$id;
const SNAPSHOT_SCHEMA_ID = findSchemaByObject("state-snapshot-metadata").$id;
const EVENT_KIND = "skill-family.state-event-envelope";
const SNAPSHOT_KIND = "skill-family.state-snapshot-metadata";
const EVENTS_DIR = "events";
const SNAPSHOTS_DIR = "snapshots";
const LOCK_FILE = "writer.lock";
const RECOVERY_FILE = "writer-recovery.lock";
const MUTATION_FILE = "writer-mutation.lock";
const FENCING_FILE = "fencing-counter.json";
const HEAD_FILE = "chain-head.json";
const EVENT_NAME = /^(\d{6})\.json$/;
const SNAPSHOT_NAME = /^(\d{6})\.json$/;
const TEMP_NAME = /^\.(event|snapshot|control)-[0-9a-f]+\.tmp$/;
const ROOT_NAMES = new Set([
  EVENTS_DIR,
  SNAPSHOTS_DIR,
  LOCK_FILE,
  RECOVERY_FILE,
  MUTATION_FILE,
  FENCING_FILE,
  HEAD_FILE,
]);

const TEST_HOOKS = new WeakMap();

function failure(kind, message, details) {
  return mechanismError(kind, message, details);
}

function randomId() {
  return randomBytes(12).toString("hex");
}

function clockMillis(clock) {
  const raw = clock?.now?.() ?? Date.now();
  const value = raw instanceof Date ? raw.getTime() : raw;
  if (!Number.isFinite(value)) throw new TypeError("state store clock must return a finite time");
  return value;
}

function assertJsonValue(value, seen = new Set(), location = "value") {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`${location} contains a non-finite number`);
    return;
  }
  if (typeof value !== "object") throw new TypeError(`${location} is not JSON data`);
  if (seen.has(value)) throw new TypeError(`${location} contains a cycle`);
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw new TypeError(`${location} contains a sparse array`);
        assertJsonValue(value[index], seen, `${location}[${index}]`);
      }
      return;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${location} must contain only plain JSON objects`);
    }
    for (const [key, child] of Object.entries(value)) {
      assertJsonValue(child, seen, `${location}.${key}`);
    }
  } finally {
    seen.delete(value);
  }
}

function assertSafeRegular(stats, label) {
  if (stats.isSymbolicLink() || !stats.isFile() || stats.nlink !== 1) {
    throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `${label} must be one ordinary, unlinked file`);
  }
}

function assertSafeDirectory(stats, label) {
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `${label} must be one real directory`);
  }
}

function sameIdentity(actual, expected) {
  return actual.dev === expected.dev && actual.ino === expected.ino;
}

async function assertNoSymlinkAncestors(absolute, { allowMissingLeaf = false } = {}) {
  const parsed = path.parse(absolute);
  const parts = absolute.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    let stats;
    try {
      stats = await lstat(current);
    } catch (cause) {
      if (allowMissingLeaf && cause?.code === "ENOENT" && index === parts.length - 1) return;
      throw failure(HARNESS_ERROR_KINDS.INVALID_ROOT, "state store path ancestry cannot be inspected", {
        path: current,
        code: cause?.code,
      });
    }
    if (stats.isSymbolicLink()) {
      throw failure(HARNESS_ERROR_KINDS.INVALID_ROOT, "state store root cannot have a symbolic-link ancestor", {
        path: current,
      });
    }
    if (index < parts.length - 1 && !stats.isDirectory()) {
      throw failure(HARNESS_ERROR_KINDS.INVALID_ROOT, "state store ancestor must be a directory", { path: current });
    }
  }
}

async function readSafeFile(file, { optional = false, label = "state entry" } = {}) {
  let before;
  try {
    before = await lstat(file);
  } catch (cause) {
    if (optional && cause?.code === "ENOENT") return null;
    throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `${label} cannot be inspected`, { code: cause?.code });
  }
  assertSafeRegular(before, label);
  const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  let handle;
  try {
    handle = await open(file, FS_CONSTANTS.O_RDONLY | noFollow);
    const opened = await handle.stat();
    assertSafeRegular(opened, label);
    if (opened.dev !== before.dev || opened.ino !== before.ino) {
      throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `${label} changed during inspection`);
    }
    return { text: await handle.readFile("utf8"), stats: opened };
  } finally {
    await handle?.close();
  }
}

async function readSafeJson(file, options) {
  const result = await readSafeFile(file, options);
  if (result === null) return null;
  try {
    return { value: JSON.parse(result.text), stats: result.stats };
  } catch {
    throw failure(HARNESS_ERROR_KINDS.CHAIN_BROKEN, `${options?.label ?? "state entry"} is not valid JSON`);
  }
}

async function syncDirectory(dir) {
  try {
    const handle = await open(dir, FS_CONSTANTS.O_RDONLY);
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch {
    // Some platforms do not support directory fsync. File fsync and atomic
    // namespace operations remain the portable contract.
  }
}

async function writeExclusive(file, bytes, mode = 0o600) {
  const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  let handle;
  try {
    handle = await open(
      file,
      FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | noFollow,
      mode,
    );
    await handle.writeFile(bytes);
    await handle.sync();
    const stats = await handle.stat();
    assertSafeRegular(stats, path.basename(file));
    return stats;
  } finally {
    await handle?.close();
  }
}

async function atomicReplace(file, bytes, prefix = "control") {
  const dir = path.dirname(file);
  const existing = await readSafeFile(file, { optional: true, label: path.basename(file) });
  void existing;
  const temp = path.join(dir, `.${prefix}-${randomId()}.tmp`);
  try {
    await writeExclusive(temp, bytes);
    await rename(temp, file);
    await syncDirectory(dir);
  } catch (cause) {
    await unlink(temp).catch(() => {});
    throw cause;
  }
}

async function appendExclusiveEvent(dir, file, bytes) {
  const temp = path.join(dir, `.event-${randomId()}.tmp`);
  let linked = false;
  try {
    await writeExclusive(temp, bytes);
    await link(temp, file); // atomic create-if-absent; never replaces history
    linked = true;
    await unlink(temp);
    await syncDirectory(dir);
  } catch (cause) {
    if (!linked) await unlink(temp).catch(() => {});
    if (cause?.code === "EEXIST") {
      throw failure(HARNESS_ERROR_KINDS.DUPLICATE_SEQUENCE, "event sequence already exists");
    }
    throw cause;
  }
}

async function prepareRoot(root, { create }) {
  if (typeof root !== "string" || root.length === 0) {
    throw new TypeError("state store root must be a non-empty path");
  }
  const absolute = path.resolve(root);
  await assertNoSymlinkAncestors(absolute, { allowMissingLeaf: create });
  let stats;
  try {
    stats = await lstat(absolute);
  } catch (cause) {
    if (!create || cause?.code !== "ENOENT") {
      throw failure(HARNESS_ERROR_KINDS.INVALID_ROOT, "state store root does not exist");
    }
    try {
      await mkdir(absolute);
      stats = await lstat(absolute);
    } catch (mkdirCause) {
      throw failure(HARNESS_ERROR_KINDS.INVALID_ROOT, "state store root cannot be created", { code: mkdirCause?.code });
    }
  }
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw failure(HARNESS_ERROR_KINDS.INVALID_ROOT, "state store root must be a real directory, not a link or special entry");
  }
  const resolved = await realpath(absolute);
  if (resolved !== absolute) {
    throw failure(HARNESS_ERROR_KINDS.INVALID_ROOT, "state store root must use its canonical symlink-free path");
  }
  return absolute;
}

async function ensureDirectory(root, name) {
  const target = path.join(root, name);
  let stats;
  try {
    stats = await lstat(target);
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
    await mkdir(target);
    stats = await lstat(target);
  }
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `${name} must be a real directory`);
  }
  return { path: target, stats };
}

async function ensureLayout(root) {
  const rootStats = await lstat(root);
  assertSafeDirectory(rootStats, "state root");
  const events = await ensureDirectory(root, EVENTS_DIR);
  const snapshots = await ensureDirectory(root, SNAPSHOTS_DIR);
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (ROOT_NAMES.has(entry.name) || TEMP_NAME.test(entry.name)) continue;
    throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `unexpected entry in state root: ${entry.name}`);
  }
  return {
    eventsDir: events.path,
    snapshotsDir: snapshots.path,
    identities: {
      root: { dev: rootStats.dev, ino: rootStats.ino },
      events: { dev: events.stats.dev, ino: events.stats.ino },
      snapshots: { dev: snapshots.stats.dev, ino: snapshots.stats.ino },
    },
  };
}

async function assertLayoutIdentity(store) {
  assertStore(store);
  await assertNoSymlinkAncestors(store.root);
  const entries = [
    [store.root, store.identities.root, "state root"],
    [path.join(store.root, EVENTS_DIR), store.identities.events, EVENTS_DIR],
    [path.join(store.root, SNAPSHOTS_DIR), store.identities.snapshots, SNAPSHOTS_DIR],
  ];
  for (const [target, expected, label] of entries) {
    let stats;
    try {
      stats = await lstat(target);
    } catch (cause) {
      throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `${label} cannot be revalidated`, { code: cause?.code });
    }
    assertSafeDirectory(stats, label);
    if (!sameIdentity(stats, expected)) {
      throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `${label} was replaced after the state store opened`);
    }
  }
  for (const entry of await readdir(store.root, { withFileTypes: true })) {
    if (ROOT_NAMES.has(entry.name) || TEMP_NAME.test(entry.name)) continue;
    throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `unexpected entry in state root: ${entry.name}`);
  }
}

async function inspectLayoutReadOnly(root) {
  await assertNoSymlinkAncestors(root);
  for (const name of [EVENTS_DIR, SNAPSHOTS_DIR]) {
    const target = path.join(root, name);
    const stats = await lstat(target).catch((cause) => {
      if (cause?.code === "ENOENT") return null;
      throw cause;
    });
    if (stats && (stats.isSymbolicLink() || !stats.isDirectory())) {
      throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `${name} must be a real directory`);
    }
  }
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (ROOT_NAMES.has(entry.name) || TEMP_NAME.test(entry.name)) continue;
    throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, `unexpected entry in state root: ${entry.name}`);
  }
}

function normalizePayloadSchemas(payloadSchemas) {
  if (!payloadSchemas || typeof payloadSchemas !== "object" || Array.isArray(payloadSchemas)) {
    throw new TypeError("payloadSchemas must map eventType to a version-to-schema map");
  }
  const validators = new Map();
  for (const [eventType, versions] of Object.entries(payloadSchemas)) {
    if (!versions || typeof versions !== "object" || Array.isArray(versions)) {
      throw new TypeError(`payloadSchemas.${eventType} must be a version map`);
    }
    for (const [versionText, schema] of Object.entries(versions)) {
      if (!/^[1-9]\d*$/.test(versionText) || !schema || typeof schema !== "object" || Array.isArray(schema)) {
        throw new TypeError(`payloadSchemas.${eventType}.${versionText} is not a frozen JSON Schema pair`);
      }
      const dialect = detectDialect(schema) ?? "2020-12";
      validators.set(`${eventType}\u0000${Number(versionText)}`, compileSchema({ schema }, { dialect, policy: "strict" }));
    }
  }
  if (validators.size === 0) throw new TypeError("payloadSchemas must register at least one eventType/version pair");
  return validators;
}

function validatePayload(validators, eventType, version, payload, position) {
  const validator = validators.get(`${eventType}\u0000${version}`);
  if (!validator || !validator(payload)) {
    throw failure(HARNESS_ERROR_KINDS.EVENT_SCHEMA_INVALID, "eventType/payloadSchemaVersion is unknown or payload validation failed", {
      position,
      eventType,
      payloadSchemaVersion: version,
      errors: validator?.errors?.map((entry) => entry.message) ?? [],
    });
  }
}

function recordDigest(record) {
  const { recordDigest: _ignored, ...unsigned } = record;
  return digestDocument(unsigned);
}

async function readEvent(file, sequence, validators) {
  let parsed;
  try {
    parsed = await readSafeJson(file, { label: `event ${sequence}` });
  } catch (cause) {
    if (cause?.details?.kind === HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY) throw cause;
    throw failure(HARNESS_ERROR_KINDS.CHAIN_BROKEN, `event ${sequence} is unreadable`, { position: sequence });
  }
  const record = parsed.value;
  const checked = validateContractDocument(record, { schemaId: EVENT_SCHEMA_ID });
  if (!checked.valid) {
    throw failure(HARNESS_ERROR_KINDS.CHAIN_BROKEN, `event ${sequence} violates its envelope`, { position: sequence });
  }
  validatePayload(validators, record.eventType, record.payloadSchemaVersion, record.payload, sequence);
  return record;
}

async function scanEvents(store) {
  await assertLayoutIdentity(store);
  const entries = await readdir(store.eventsDir, { withFileTypes: true });
  const sequences = [];
  for (const entry of entries) {
    if (TEMP_NAME.test(entry.name)) {
      await readSafeFile(path.join(store.eventsDir, entry.name), { label: "event staging file" });
      continue;
    }
    const match = EVENT_NAME.exec(entry.name);
    if (!match) throw failure(HARNESS_ERROR_KINDS.CHAIN_BROKEN, `unexpected event entry: ${entry.name}`, { position: 0 });
    sequences.push(Number(match[1]));
  }
  sequences.sort((a, b) => a - b);
  let previousDigest = STATE_GENESIS_DIGEST;
  let previousFencing = 0;
  const eventIds = new Set();
  const idempotencyKeys = new Set();
  const fencingOwners = new Map();
  const records = [];
  for (let index = 0; index < sequences.length; index += 1) {
    const expected = index + 1;
    if (sequences[index] !== expected) {
      throw failure(HARNESS_ERROR_KINDS.CHAIN_BROKEN, `event sequence gap at ${expected}`, { position: expected });
    }
    const record = await readEvent(path.join(store.eventsDir, `${String(expected).padStart(6, "0")}.json`), expected, store.validators);
    if (record.sequence !== expected || record.prevDigest !== previousDigest || record.recordDigest !== recordDigest(record)) {
      throw failure(HARNESS_ERROR_KINDS.CHAIN_BROKEN, `event chain breaks at ${expected}`, { position: expected });
    }
    if (record.writerFencing < previousFencing) {
      throw failure(HARNESS_ERROR_KINDS.CHAIN_BROKEN, `writer fencing regresses at ${expected}`, { position: expected });
    }
    const knownOwner = fencingOwners.get(record.writerFencing);
    if (knownOwner && knownOwner !== record.writerOwner) {
      throw failure(HARNESS_ERROR_KINDS.CHAIN_BROKEN, `one fencing token has multiple owners at ${expected}`, { position: expected });
    }
    if (eventIds.has(record.eventId) || idempotencyKeys.has(record.idempotencyKey)) {
      throw failure(HARNESS_ERROR_KINDS.CHAIN_BROKEN, `duplicate event identity at ${expected}`, { position: expected });
    }
    fencingOwners.set(record.writerFencing, record.writerOwner);
    eventIds.add(record.eventId);
    idempotencyKeys.add(record.idempotencyKey);
    records.push(record);
    previousDigest = record.recordDigest;
    previousFencing = record.writerFencing;
  }
  return { records, eventCount: records.length, headDigest: previousDigest, maxFencing: previousFencing };
}

function lockRecord({ owner, fencing, acquisitionId, acquiredAt }) {
  return { schemaVersion: 1, owner, fencing, acquisitionId, acquiredAt };
}

function validateLock(record) {
  if (
    !record || record.schemaVersion !== 1 || typeof record.owner !== "string" || record.owner.length === 0 ||
    !Number.isSafeInteger(record.fencing) || record.fencing < 0 ||
    typeof record.acquisitionId !== "string" || !/^[0-9a-f]{24}$/.test(record.acquisitionId) ||
    !Number.isFinite(Date.parse(record.acquiredAt))
  ) {
    throw failure(HARNESS_ERROR_KINDS.LOCK_CORRUPT, "writer lock is malformed");
  }
  return record;
}

async function readLock(root, { optional = false } = {}) {
  const parsed = await readSafeJson(path.join(root, LOCK_FILE), { optional, label: LOCK_FILE });
  return parsed === null ? null : { record: validateLock(parsed.value), stats: parsed.stats };
}

async function removeSameFile(file, expectedStats) {
  const current = await lstat(file).catch(() => null);
  if (current && current.dev === expectedStats.dev && current.ino === expectedStats.ino) await unlink(file);
}

async function allocateFencing(store, lowerBound = 0) {
  const counterPath = path.join(store.root, FENCING_FILE);
  const parsed = await readSafeJson(counterPath, { optional: true, label: FENCING_FILE });
  let previous = 0;
  if (parsed !== null) {
    const value = parsed.value;
    if (value?.schemaVersion !== 1 || !Number.isSafeInteger(value.lastFencing) || value.lastFencing < 0) {
      throw failure(HARNESS_ERROR_KINDS.LOCK_CORRUPT, "fencing counter is malformed");
    }
    previous = value.lastFencing;
  }
  const fencing = Math.max(previous, lowerBound) + 1;
  await atomicReplace(counterPath, `${canonicalJson({ schemaVersion: 1, lastFencing: fencing })}\n`);
  return fencing;
}

function assertStore(store) {
  if (!store || store.__stateStore !== true) throw new TypeError("expected a state store handle");
  if (store.closed) throw failure(HARNESS_ERROR_KINDS.STORE_CLOSED, "state store is closed");
}

async function assertWriter(store) {
  assertStore(store);
  await assertLayoutIdentity(store);
  const lock = await readLock(store.root);
  if (
    lock.record.owner !== store.owner || lock.record.fencing !== store.fencing ||
    lock.record.acquisitionId !== store.acquisitionId
  ) {
    throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "writer fencing no longer matches the active lock", {
      owner: store.owner,
      fencing: store.fencing,
    });
  }
}

async function buildStore(root, owner, fencing, acquisitionId, validators, clock) {
  const { eventsDir, snapshotsDir, identities } = await ensureLayout(root);
  return {
    __stateStore: true,
    root,
    owner,
    fencing,
    acquisitionId,
    validators,
    clock,
    eventsDir,
    snapshotsDir,
    identities,
    closed: false,
  };
}

function mutationRecord(store, operation) {
  return {
    schemaVersion: 1,
    owner: store.owner,
    fencing: store.fencing,
    acquisitionId: store.acquisitionId,
    operation,
    mutationId: randomId(),
  };
}

async function acquireMutation(root, record) {
  const file = path.join(root, MUTATION_FILE);
  let stats;
  try {
    stats = await writeExclusive(file, `${canonicalJson(record)}\n`);
  } catch (cause) {
    if (cause?.code === "EEXIST") {
      throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "another state-store mutation is in progress", {
        operation: record.operation,
      });
    }
    throw cause;
  }
  return { file, stats };
}

async function reclaimMutationForConfirmedRecovery(root, expectedOwner, expectedFencing) {
  const file = path.join(root, MUTATION_FILE);
  const parsed = await readSafeJson(file, { label: MUTATION_FILE });
  if (
    parsed.value?.schemaVersion !== 1 || parsed.value.owner !== expectedOwner ||
    parsed.value.fencing !== expectedFencing || typeof parsed.value.mutationId !== "string"
  ) {
    throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "active mutation does not match the explicitly confirmed writer");
  }
  await removeSameFile(file, parsed.stats);
  const remaining = await readSafeFile(file, { optional: true, label: MUTATION_FILE });
  if (remaining !== null) {
    throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "active mutation changed during explicit recovery");
  }
}

async function acquireRecoveryMutation(root, record) {
  try {
    return await acquireMutation(root, record);
  } catch (cause) {
    if (cause?.details?.kind !== HARNESS_ERROR_KINDS.STORE_LOCKED) throw cause;
    // `confirmOwnerTerminated` was checked before this function is reached.
    // Reclaiming a matching guard therefore does not add a second recovery
    // boundary or infer liveness from time/PID. A falsely confirmed live
    // writer is still fenced by guard + writer-lock revalidation before write.
    await reclaimMutationForConfirmedRecovery(root, record.owner, record.fencing);
    return acquireMutation(root, record);
  }
}

async function releaseMutation(guard) {
  const current = await lstat(guard.file).catch((cause) => {
    throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "state-store mutation guard disappeared before release", {
      code: cause?.code,
    });
  });
  assertSafeRegular(current, MUTATION_FILE);
  if (!sameIdentity(current, guard.stats)) {
    throw failure(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, "state-store mutation guard was replaced before release");
  }
  await unlink(guard.file);
  await syncDirectory(path.dirname(guard.file));
}

async function assertMutationGuard(guard) {
  const current = await lstat(guard.file).catch((cause) => {
    throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "state-store mutation ownership was lost", { code: cause?.code });
  });
  assertSafeRegular(current, MUTATION_FILE);
  if (!sameIdentity(current, guard.stats)) {
    throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "state-store mutation ownership was replaced");
  }
}

async function withWriterMutation(store, operation, action) {
  await assertWriter(store);
  const guard = await acquireMutation(store.root, mutationRecord(store, operation));
  let actionFailed = false;
  try {
    await assertWriter(store);
    const recovery = await readSafeFile(path.join(store.root, RECOVERY_FILE), {
      optional: true,
      label: RECOVERY_FILE,
    });
    if (recovery !== null) {
      throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "explicit lock recovery is in progress");
    }
    return await action(guard);
  } catch (cause) {
    actionFailed = true;
    throw cause;
  } finally {
    try {
      await releaseMutation(guard);
    } catch (releaseCause) {
      if (!actionFailed) throw releaseCause;
    }
  }
}

/** Test-only hook registry. It is deliberately not re-exported by index.mjs. */
export function __setStateStoreTestHooks(store, hooks) {
  assertStore(store);
  if (hooks === null) {
    TEST_HOOKS.delete(store);
    return;
  }
  if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) {
    throw new TypeError("state-store test hooks must be an object or null");
  }
  TEST_HOOKS.set(store, hooks);
}

async function runTestHook(store, name) {
  const hook = TEST_HOOKS.get(store)?.[name];
  if (hook !== undefined) await hook();
}

export async function inspectStateStoreLock(root, { clock } = {}) {
  if (typeof root !== "string" || root.length === 0) {
    throw new TypeError("state store root must be a non-empty path");
  }
  const rootStats = await lstat(path.resolve(root)).catch((cause) => {
    if (cause?.code === "ENOENT") return null;
    throw cause;
  });
  if (rootStats === null) return { locked: false, rootExists: false, recoveryInProgress: false };
  const safeRoot = await prepareRoot(root, { create: false });
  await inspectLayoutReadOnly(safeRoot);
  const recovery = await readSafeFile(path.join(safeRoot, RECOVERY_FILE), { optional: true, label: RECOVERY_FILE });
  const lock = await readLock(safeRoot, { optional: true });
  if (lock === null) return { locked: false, rootExists: true, recoveryInProgress: recovery !== null };
  const acquiredAt = Date.parse(lock.record.acquiredAt);
  return {
    locked: true,
    rootExists: true,
    owner: lock.record.owner,
    fencing: lock.record.fencing,
    acquiredAt: lock.record.acquiredAt,
    ageMs: Math.max(0, clockMillis(clock) - acquiredAt),
    recoveryInProgress: recovery !== null,
  };
}

export async function openStateStore(root, { owner, payloadSchemas, clock } = {}) {
  const safeRoot = await prepareRoot(root, { create: true });
  const validators = normalizePayloadSchemas(payloadSchemas);
  const writerOwner = typeof owner === "string" && owner.length > 0 ? owner : `writer-${process.pid}-${randomId()}`;
  const acquisitionId = randomId();
  await ensureLayout(safeRoot);
  if (await readSafeFile(path.join(safeRoot, RECOVERY_FILE), { optional: true, label: RECOVERY_FILE })) {
    throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "explicit lock recovery is in progress");
  }
  if (await readSafeFile(path.join(safeRoot, MUTATION_FILE), { optional: true, label: MUTATION_FILE })) {
    throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "an unfinished state-store mutation requires explicit recovery");
  }
  const placeholder = lockRecord({ owner: writerOwner, fencing: 0, acquisitionId, acquiredAt: new Date(clockMillis(clock)).toISOString() });
  let lockStats;
  try {
    lockStats = await writeExclusive(path.join(safeRoot, LOCK_FILE), `${canonicalJson(placeholder)}\n`);
  } catch (cause) {
    if (cause?.code === "EEXIST") throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "state store already has a writer");
    throw cause;
  }
  try {
    const store = await buildStore(safeRoot, writerOwner, 0, acquisitionId, validators, clock);
    const scan = await scanEvents(store);
    const fencing = await allocateFencing(store, scan.maxFencing);
    const active = lockRecord({ ...placeholder, fencing });
    await atomicReplace(path.join(safeRoot, HEAD_FILE), `${canonicalJson({ lastSequence: scan.eventCount, headDigest: scan.headDigest })}\n`);
    // Publish the active fencing token last. Every prior initialization
    // failure still owns the original exclusive-create inode and can release
    // it without risking another writer's lock.
    await atomicReplace(path.join(safeRoot, LOCK_FILE), `${canonicalJson(active)}\n`);
    store.fencing = fencing;
    return store;
  } catch (cause) {
    await removeSameFile(path.join(safeRoot, LOCK_FILE), lockStats).catch(() => {});
    throw cause;
  }
}

export async function recoverStateStoreLock(root, {
  expectedOwner,
  expectedFencing,
  confirmOwnerTerminated,
  newOwner,
  payloadSchemas,
  clock,
} = {}) {
  if (confirmOwnerTerminated !== true) {
    throw failure(HARNESS_ERROR_KINDS.LOCK_RECOVERY_REFUSED, "lock recovery requires explicit confirmation that the observed writer has terminated");
  }
  const safeRoot = await prepareRoot(root, { create: false });
  const validators = normalizePayloadSchemas(payloadSchemas);
  await ensureLayout(safeRoot);
  const mutationGuard = await acquireRecoveryMutation(safeRoot, {
    schemaVersion: 1,
    owner: expectedOwner,
    fencing: expectedFencing,
    acquisitionId: "recovery-claim",
    operation: "recover",
    mutationId: randomId(),
  });
  const guardPath = path.join(safeRoot, RECOVERY_FILE);
  let guardStats;
  try {
    guardStats = await writeExclusive(guardPath, `${canonicalJson({ schemaVersion: 1, recoveryId: randomId() })}\n`);
  } catch (cause) {
    await releaseMutation(mutationGuard).catch(() => {});
    if (cause?.code === "EEXIST") throw failure(HARNESS_ERROR_KINDS.STORE_LOCKED, "another explicit recovery is in progress");
    throw cause;
  }
  let recoveryFailed = false;
  try {
    const observed = await readLock(safeRoot);
    if (observed.record.owner !== expectedOwner || observed.record.fencing !== expectedFencing) {
      throw failure(HARNESS_ERROR_KINDS.LOCK_RECOVERY_REFUSED, "observed owner/fencing no longer matches the recovery request", {
        observedOwner: observed.record.owner,
        observedFencing: observed.record.fencing,
      });
    }
    const owner = typeof newOwner === "string" && newOwner.length > 0 ? newOwner : `recovery-${process.pid}-${randomId()}`;
    const acquisitionId = randomId();
    const store = await buildStore(safeRoot, owner, 0, acquisitionId, validators, clock);
    const scan = await scanEvents(store);
    const fencing = await allocateFencing(store, Math.max(expectedFencing, scan.maxFencing));
    const active = lockRecord({ owner, fencing, acquisitionId, acquiredAt: new Date(clockMillis(clock)).toISOString() });
    await atomicReplace(path.join(safeRoot, LOCK_FILE), `${canonicalJson(active)}\n`);
    store.fencing = fencing;
    await removeSameFile(guardPath, guardStats);
    return store;
  } catch (cause) {
    recoveryFailed = true;
    await removeSameFile(guardPath, guardStats).catch(() => {});
    throw cause;
  } finally {
    try {
      await releaseMutation(mutationGuard);
    } catch (releaseCause) {
      if (!recoveryFailed) throw releaseCause;
    }
  }
}

export async function appendEvent(store, event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) throw new TypeError("event must be a plain object");
  assertJsonValue(event, new Set(), "event");
  return withWriterMutation(store, "append-event", async (guard) => {
    const scan = await scanEvents(store);
    const prior = scan.records.find((record) => record.idempotencyKey === event.idempotencyKey);
    if (prior) {
      const same = canonicalJson({
        eventId: prior.eventId,
        eventType: prior.eventType,
        payloadSchemaVersion: prior.payloadSchemaVersion,
        producer: prior.producer,
        payload: prior.payload,
      }) === canonicalJson({
        eventId: event.eventId,
        eventType: event.eventType,
        payloadSchemaVersion: event.payloadSchemaVersion,
        producer: event.producer,
        payload: event.payload,
      });
      if (same) return { appended: false, record: prior };
      throw failure(HARNESS_ERROR_KINDS.IDEMPOTENCY_CONFLICT, "idempotency key was reused with different event content");
    }
    if (scan.records.some((record) => record.eventId === event.eventId)) {
      throw failure(HARNESS_ERROR_KINDS.IDEMPOTENCY_CONFLICT, "eventId was reused with a different idempotency key", {
        eventId: event.eventId,
        identity: "eventId",
      });
    }
    const sequence = scan.eventCount + 1;
    validatePayload(store.validators, event.eventType, event.payloadSchemaVersion, event.payload, sequence);
    const record = {
      schemaVersion: 1,
      kind: EVENT_KIND,
      eventId: event.eventId,
      eventType: event.eventType,
      payloadSchemaVersion: event.payloadSchemaVersion,
      producer: event.producer,
      idempotencyKey: event.idempotencyKey,
      writerOwner: store.owner,
      writerFencing: store.fencing,
      sequence,
      prevDigest: scan.headDigest,
      payload: event.payload,
    };
    record.recordDigest = recordDigest(record);
    const checked = validateContractDocument(record, { schemaId: EVENT_SCHEMA_ID });
    if (!checked.valid) throw failure(HARNESS_ERROR_KINDS.EVENT_SCHEMA_INVALID, "event envelope is invalid", { errors: checked.errors });
    await runTestHook(store, "beforeAuthoritativeEventWrite");
    await assertMutationGuard(guard);
    await assertWriter(store);
    await appendExclusiveEvent(store.eventsDir, path.join(store.eventsDir, `${String(sequence).padStart(6, "0")}.json`), `${canonicalJson(record)}\n`);
    await assertWriter(store);
    await atomicReplace(path.join(store.root, HEAD_FILE), `${canonicalJson({ lastSequence: sequence, headDigest: record.recordDigest })}\n`);
    return { appended: true, record };
  });
}

export async function readEvents(store, { afterSequence = 0 } = {}) {
  assertStore(store);
  if (!Number.isSafeInteger(afterSequence) || afterSequence < 0) throw new TypeError("afterSequence must be a non-negative integer");
  const scan = await scanEvents(store);
  return scan.records.filter((record) => record.sequence > afterSequence);
}

async function cacheStatus(store, scan) {
  let parsed;
  try {
    parsed = await readSafeJson(path.join(store.root, HEAD_FILE), { optional: true, label: HEAD_FILE });
  } catch (cause) {
    if (cause?.details?.kind === HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY) throw cause;
    return "corrupt";
  }
  if (parsed === null) return "missing";
  return parsed.value?.lastSequence === scan.eventCount && parsed.value?.headDigest === scan.headDigest ? "current" : "stale";
}

export async function verifyStateStore(store, { reducer, initial = null } = {}) {
  assertStore(store);
  const scan = await scanEvents(store);
  const result = {
    valid: true,
    eventCount: scan.eventCount,
    headDigest: scan.headDigest,
    chainHeadCache: await cacheStatus(store, scan),
    snapshotStatus: "missing",
  };
  let snapshot;
  try {
    snapshot = await newestSnapshot(store, scan);
  } catch (cause) {
    if (cause?.details?.kind !== HARNESS_ERROR_KINDS.SNAPSHOT_MISMATCH) throw cause;
    return { ...result, valid: false, snapshotStatus: "corrupt", snapshotError: cause.message };
  }
  if (snapshot === null) return result;
  if (reducer === undefined) {
    return { ...result, valid: false, snapshotStatus: "unverified" };
  }
  if (typeof reducer !== "function") throw new TypeError("reducer must be a function");
  assertJsonValue(initial, new Set(), "initial state");
  const prefix = reduceEventPrefix(scan.records, reducer, initial, snapshot.lastSequence);
  if (digestDocument(prefix) !== snapshot.stateDigest) {
    return { ...result, valid: false, snapshotStatus: "semantic-mismatch" };
  }
  return { ...result, snapshotStatus: "verified" };
}

async function newestSnapshot(store, scan) {
  await assertLayoutIdentity(store);
  const entries = await readdir(store.snapshotsDir, { withFileTypes: true });
  const sequences = [];
  for (const entry of entries) {
    if (TEMP_NAME.test(entry.name)) {
      await readSafeFile(path.join(store.snapshotsDir, entry.name), { label: "snapshot staging file" });
      continue;
    }
    const match = SNAPSHOT_NAME.exec(entry.name);
    if (!match) throw failure(HARNESS_ERROR_KINDS.SNAPSHOT_MISMATCH, `unexpected snapshot entry: ${entry.name}`);
    sequences.push(Number(match[1]));
  }
  if (sequences.length === 0) return null;
  sequences.sort((left, right) => left - right);
  let newest = null;
  for (const sequence of sequences) {
    let parsed;
    try {
      parsed = await readSafeJson(path.join(store.snapshotsDir, `${String(sequence).padStart(6, "0")}.json`), { label: `snapshot ${sequence}` });
    } catch (cause) {
      if (cause?.details?.kind === HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY) throw cause;
      throw failure(HARNESS_ERROR_KINDS.SNAPSHOT_MISMATCH, `snapshot ${sequence} is unreadable`, { position: sequence });
    }
    const snapshot = parsed.value;
    const checked = validateContractDocument(snapshot, { schemaId: SNAPSHOT_SCHEMA_ID });
    const expectedDigest = sequence === 0 ? STATE_GENESIS_DIGEST : scan.records[sequence - 1]?.recordDigest;
    if (!checked.valid || snapshot.lastSequence !== sequence || snapshot.chainHeadDigest !== expectedDigest || snapshot.stateDigest !== digestDocument(snapshot.state)) {
      throw failure(HARNESS_ERROR_KINDS.SNAPSHOT_MISMATCH, `snapshot ${sequence} does not bind to the authoritative event prefix`, { position: sequence });
    }
    newest = snapshot;
  }
  return newest;
}

export async function readSnapshot(store, { reducer, initial = null } = {}) {
  assertStore(store);
  const scan = await scanEvents(store); // bad events always win over old snapshots
  const snapshot = await newestSnapshot(store, scan);
  if (snapshot === null) return null;
  if (typeof reducer !== "function") {
    throw new TypeError("readSnapshot requires the consumer reducer used to verify the authoritative event prefix");
  }
  assertJsonValue(initial, new Set(), "initial state");
  const prefix = reduceEventPrefix(scan.records, reducer, initial, snapshot.lastSequence);
  if (digestDocument(prefix) !== snapshot.stateDigest) {
    throw failure(HARNESS_ERROR_KINDS.SNAPSHOT_MISMATCH, "snapshot state does not equal the reducer result for the authoritative event prefix", {
      position: snapshot.lastSequence,
    });
  }
  return snapshot;
}

export async function writeSnapshot(store, state, { hostSessionRef, reducer, initial = null } = {}) {
  if (typeof reducer !== "function") {
    throw new TypeError("writeSnapshot requires the consumer reducer used to derive state from authoritative events");
  }
  assertJsonValue(state, new Set(), "snapshot state");
  assertJsonValue(initial, new Set(), "initial state");
  return withWriterMutation(store, "write-snapshot", async () => {
    const scan = await scanEvents(store);
    const authoritativeState = reduceEventPrefix(scan.records, reducer, initial, scan.eventCount);
    if (digestDocument(authoritativeState) !== digestDocument(state)) {
      throw failure(HARNESS_ERROR_KINDS.SNAPSHOT_MISMATCH, "snapshot state does not equal the reducer result for the authoritative event prefix", {
        position: scan.eventCount,
      });
    }
    const snapshot = {
      schemaVersion: 1,
      kind: SNAPSHOT_KIND,
      lastSequence: scan.eventCount,
      chainHeadDigest: scan.headDigest,
      stateDigest: digestDocument(authoritativeState),
      state: authoritativeState,
    };
    if (hostSessionRef !== undefined) snapshot.hostSessionRef = hostSessionRef;
    const checked = validateContractDocument(snapshot, { schemaId: SNAPSHOT_SCHEMA_ID });
    if (!checked.valid) throw failure(HARNESS_ERROR_KINDS.SNAPSHOT_MISMATCH, "snapshot metadata is invalid", { errors: checked.errors });
    await assertWriter(store);
    await atomicReplace(path.join(store.snapshotsDir, `${String(scan.eventCount).padStart(6, "0")}.json`), `${canonicalJson(snapshot)}\n`, "snapshot");
    return snapshot;
  });
}

function reduceEventPrefix(records, reducer, initial, length) {
  let state = structuredClone(initial);
  for (const record of records.slice(0, length)) {
    state = reducer(state, structuredClone(record));
    assertJsonValue(state, new Set(), "reducer result");
  }
  return state;
}

export async function rebuildSnapshot(store, reducer, { initial = null } = {}) {
  assertStore(store);
  if (typeof reducer !== "function") throw new TypeError("reducer must be a function");
  assertJsonValue(initial, new Set(), "initial state");
  const scan = await scanEvents(store); // full authority check before snapshot use
  let snapshot = null;
  let snapshotStatus = "missing";
  try {
    snapshot = await newestSnapshot(store, scan);
    snapshotStatus = snapshot === null ? "missing" : "structurally-valid";
  } catch (cause) {
    if (cause?.details?.kind !== HARNESS_ERROR_KINDS.SNAPSHOT_MISMATCH) throw cause;
    snapshotStatus = "ignored-corrupt";
  }
  const state = reduceEventPrefix(scan.records, reducer, initial, scan.eventCount);
  if (snapshot !== null) {
    const prefix = reduceEventPrefix(scan.records, reducer, initial, snapshot.lastSequence);
    if (digestDocument(prefix) !== snapshot.stateDigest) {
      snapshotStatus = "ignored-semantic-mismatch";
    } else {
      snapshotStatus = "verified";
    }
  }
  return {
    state,
    lastSequence: scan.eventCount,
    chainHeadDigest: scan.headDigest,
    replayed: scan.eventCount,
    snapshotSequence: snapshot?.lastSequence ?? 0,
    snapshotStatus,
  };
}

export async function closeStateStore(store) {
  if (!store || store.__stateStore !== true) throw new TypeError("expected a state store handle");
  if (store.closed) return;
  await assertLayoutIdentity(store);
  const lock = await readLock(store.root, { optional: true }).catch(() => null);
  const ownsLock = lock && lock.record.owner === store.owner && lock.record.fencing === store.fencing &&
    lock.record.acquisitionId === store.acquisitionId;
  if (!ownsLock) {
    store.closed = true;
    TEST_HOOKS.delete(store);
    return;
  }
  const guard = await acquireMutation(store.root, mutationRecord(store, "close"));
  let closeFailed = false;
  try {
    await assertWriter(store);
    store.closed = true;
    TEST_HOOKS.delete(store);
    await removeSameFile(path.join(store.root, LOCK_FILE), lock.stats);
    await syncDirectory(store.root);
  } catch (cause) {
    closeFailed = true;
    throw cause;
  } finally {
    try {
      await releaseMutation(guard);
    } catch (releaseCause) {
      if (!closeFailed) throw releaseCause;
    }
  }
}

export const close = closeStateStore;
