/**
 * supervise-process: bounded subprocess lifecycle supervision (FND-ADR-012).
 *
 * The mechanism supervises ONE consumer-supplied command through a bounded
 * lifecycle: spawn, liveness, parameterized timeouts, SIGTERM -> grace ->
 * SIGKILL escalation against the process group, terminal-progress
 * observation, and closed-enum termination evidence. It produces exactly one
 * watchdog-termination-envelope per call (single writer) and never restarts
 * the supervised process (workflow-orchestration exclusion: retry/restart
 * policy stays with the upper orchestration layer).
 *
 * Mechanism vs consumer policy split:
 *  - mechanism: spawn/exit monitoring, process-group termination, timeout
 *    enforcement (values supplied by the consumer), fail-closed evidence
 *    convergence, residual process-group cleanup after leader exit;
 *  - consumer: the command itself, host profile vocabulary, concrete timeout
 *    numbers, budget thresholds, restart strategy.
 *
 * Fail-closed directions (also declared in the envelope schema `guarantees`):
 *  - natural completion with exit 0 and a satisfied terminal requirement is
 *    ok=true; every other end is reported as failure;
 *  - timeout terminations always carry their closed-enum reason;
 *  - a process that vanishes without an exit event after having been
 *    confirmed live (external kill) is reported as a failure envelope
 *    (no_terminal_result / TERMINATED / 124) — the mechanism never hangs
 *    waiting for a terminal state it cannot confirm;
 *  - internal mechanism failure (evidence persistence failure, un-finalizable
 *    termination, consumer callback throwing) terminates the process and
 *    REJECTS with SFC2004 + details.kind supervise-process-failed; the
 *    rejection details carry the assembled termination evidence;
 *  - liveness is confirmed only by explicit events (exit, signal,
 *    process-group probe). ps/process-table observation, if ever added by a
 *    consumer, is restricted to residual-descendant tracking and is NEVER
 *    used for liveness guessing (FND-ADR-012 section 7).
 *
 * Dependency injection (deps, all optional): spawn/signal/liveness/timers
 * and the clock can be replaced so every code path is deterministic in tests.
 */

import { spawn as nodeSpawn } from "node:child_process";
import { constants as FS_CONSTANTS, existsSync, readFileSync, statSync, writeFileSync, renameSync } from "node:fs";
import { open as openFile, readdir, realpath, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { mechanismError } from "./errors.mjs";

// ---------------------------------------------------------------------------
// Closed vocabulary (FND-ADR-012 section 7, finalized per O-2). The same
// enums are frozen in the contracts schema watchdog-termination-envelope;
// any change requires a contracts ADR.
// ---------------------------------------------------------------------------

/** Watchdog reason: why the supervision layer closed the process (9 values). */
export const WATCHDOG_REASONS = Object.freeze([
  "max_seconds",
  "startup_stale_progress",
  "stale_progress",
  "tool_lease_expired",
  "runtime_error",
  "terminal_progress",
  "no_terminal_result",
  "residual_process_group",
  "context_budget_exhausted",
  "output_limit_exceeded",
]);

/** Termination reason: the deterministic mapping consumers consume (8 values). */
export const TERMINATION_REASONS = Object.freeze([
  "hard_ceiling",
  "startup_idle",
  "stream_idle",
  "tool_lease_expired",
  "failed_to_start",
  "completed",
  "child_exit",
  "context_budget_exhausted",
  "output_limit_exceeded",
]);

/** Process status of the supervised process (7 values). */
export const PROCESS_STATUSES = Object.freeze([
  "PLANNED",
  "STARTING",
  "RUNNING",
  "EXITED",
  "FAILED_TO_START",
  "TIMED_OUT",
  "TERMINATED",
]);

/** Closed guarantee vocabulary carried in the envelope (see schema). */
export const ENVELOPE_GUARANTEES = Object.freeze([
  "closed-enum-evidence",
  "fail-closed",
  "no-auto-restart",
  "no-liveness-guessing",
  "process-group-termination",
  "mechanism-holds-no-timeout-values",
]);

const ENVELOPE_KIND = "skill-family.watchdog-termination-envelope";
const TRACE_KIND = "skill-family.watchdog-supervision-trace";

const TIMEOUT_POLICY_FIELDS = Object.freeze([
  "startupStaleSeconds",
  "startupIdleSeconds",
  "streamIdleSeconds",
  "maxSeconds",
  "toolLeaseSeconds",
  "killGraceSeconds",
]);

const TIMEOUT_WATCHDOG_REASONS = new Set([
  "max_seconds",
  "startup_stale_progress",
  "stale_progress",
  "tool_lease_expired",
]);

const OUTPUT_LIMIT_FIELDS = Object.freeze(["stdout", "stderr"]);
const MAX_SAFE_OUTPUT_BYTES = Number.MAX_SAFE_INTEGER;

function validateOutputByteLimits(limits) {
  if (limits === undefined) return null;
  if (!isPlainObject(limits)) return "outputByteLimits must be a plain object";
  const fields = Object.keys(limits);
  if (fields.length === 0 || fields.some((field) => !OUTPUT_LIMIT_FIELDS.includes(field))) {
    return "outputByteLimits must contain stdout and/or stderr only";
  }
  for (const field of fields) {
    const value = limits[field];
    if (!Number.isInteger(value) || value < 0 || value > MAX_SAFE_OUTPUT_BYTES) {
      return `outputByteLimits.${field} must be an integer from 0 to Number.MAX_SAFE_INTEGER`;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Option and policy validation
// ---------------------------------------------------------------------------

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validatePositiveNumber(value, field) {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? null
    : `${field} must be a positive finite number, got ${String(value)}`;
}

/**
 * Validates the consumer-supplied timeout policy. Shape violations are
 * coded as SFC2004 with details.kind "timeout-policy-invalid" (the ADR-fixed
 * kind); the mechanism never substitutes hidden default values.
 */
export function validateTimeoutPolicy(policy) {
  if (!isPlainObject(policy)) {
    return "timeoutPolicy must be a plain object";
  }
  for (const field of Object.keys(policy)) {
    if (!TIMEOUT_POLICY_FIELDS.includes(field)) {
      return `timeoutPolicy: unknown field ${field} (closed field set: ${TIMEOUT_POLICY_FIELDS.join(", ")})`;
    }
  }
  if (policy.maxSeconds === undefined) {
    return "timeoutPolicy: maxSeconds is required (the mechanism holds no default ceiling)";
  }
  if (policy.killGraceSeconds === undefined) {
    return "timeoutPolicy: killGraceSeconds is required (the mechanism holds no default grace)";
  }
  for (const field of TIMEOUT_POLICY_FIELDS) {
    if (policy[field] === undefined) continue;
    const problem = validatePositiveNumber(policy[field], `timeoutPolicy.${field}`);
    if (problem) return problem;
  }
  return null;
}

function validateOptions(options) {
  if (!isPlainObject(options)) {
    throw new TypeError("superviseProcess: options must be a plain object");
  }
  const {
    command, args, cwd, env,
    timeoutPolicy, progressPaths, terminalProgressPaths, terminalGraceSeconds,
    checkIntervalSeconds, longToolActive, budgetExhausted, evidencePath, rawSink, rawStreamSink, outputByteLimits,
  } = options;
  if (typeof command !== "string" || command.length === 0) {
    throw new TypeError("superviseProcess: command must be a non-empty string");
  }
  if (!Array.isArray(args) || args.some((a) => typeof a !== "string")) {
    throw new TypeError("superviseProcess: args must be an array of strings");
  }
  if (typeof cwd !== "string" || cwd.length === 0) {
    throw new TypeError("superviseProcess: cwd must be a non-empty string");
  }
  if (env !== undefined && !isPlainObject(env)) {
    throw new TypeError("superviseProcess: env must be a plain object when provided");
  }
  if (progressPaths !== undefined && !Array.isArray(progressPaths)) {
    throw new TypeError("superviseProcess: progressPaths must be an array when provided");
  }
  if (terminalProgressPaths !== undefined && !Array.isArray(terminalProgressPaths)) {
    throw new TypeError("superviseProcess: terminalProgressPaths must be an array when provided");
  }
  if (terminalGraceSeconds !== undefined) {
    const problem = validatePositiveNumber(terminalGraceSeconds, "terminalGraceSeconds");
    if (problem) throw new TypeError(`superviseProcess: ${problem}`);
  }
  if ((terminalProgressPaths?.length ?? 0) > 0 && terminalGraceSeconds === undefined) {
    throw new TypeError(
      "superviseProcess: terminalGraceSeconds is required when terminalProgressPaths is provided",
    );
  }
  if (checkIntervalSeconds !== undefined) {
    const problem = validatePositiveNumber(checkIntervalSeconds, "checkIntervalSeconds");
    if (problem) throw new TypeError(`superviseProcess: ${problem}`);
  }
  if (longToolActive !== undefined && typeof longToolActive !== "function") {
    throw new TypeError("superviseProcess: longToolActive must be a function when provided");
  }
  if (longToolActive !== undefined && options.timeoutPolicy?.toolLeaseSeconds === undefined) {
    throw new TypeError(
      "superviseProcess: toolLeaseSeconds is required in timeoutPolicy when longToolActive is provided",
    );
  }
  if (budgetExhausted !== undefined && typeof budgetExhausted !== "function") {
    throw new TypeError("superviseProcess: budgetExhausted must be a function when provided");
  }
  if (evidencePath !== undefined && typeof evidencePath !== "string") {
    throw new TypeError("superviseProcess: evidencePath must be a string when provided");
  }
  if (rawStreamSink !== undefined) {
    throw new TypeError(
      "superviseProcess: rawStreamSink is not supported (rawSink requires a fresh canonical root and two relative file names)",
    );
  }
  if (rawSink !== undefined) {
    const problem = validateRawSink(rawSink);
    if (problem) throw new TypeError(`superviseProcess: ${problem}`);
  }
  const outputLimitProblem = validateOutputByteLimits(outputByteLimits);
  if (outputLimitProblem) throw new TypeError(`superviseProcess: ${outputLimitProblem}`);
  const policyProblem = validateTimeoutPolicy(timeoutPolicy);
  if (policyProblem) {
    throw mechanismError("timeout-policy-invalid", policyProblem);
  }
}

const RAW_SINK_FIELDS = Object.freeze(["root", "stdoutFile", "stderrFile", "onClosed"]);

function validateSingleSegmentName(value, field) {
  if (typeof value !== "string" || value.length === 0) return `${field} must be a non-empty string`;
  if (value.includes("\0") || value.includes("/") || value.includes("\\")) {
    return `${field} must be a single-segment relative name`;
  }
  if (value === "." || value === "..") return `${field} must be a safe relative name`;
  if (/^[A-Za-z]:/u.test(value)) return `${field} must be a safe relative name`;
  return null;
}

/**
 * The sink shape is closed: one fresh canonical root plus two distinct
 * single-segment relative file names. Absolute or nested paths are rejected
 * here (shape violation); canonicality and freshness of the root are state
 * checks performed at open time.
 */
function validateRawSink(sink) {
  if (!isPlainObject(sink)) return "rawSink must be a plain object";
  for (const field of Object.keys(sink)) {
    if (!RAW_SINK_FIELDS.includes(field)) {
      return `rawSink unknown field ${field} (closed field set: ${RAW_SINK_FIELDS.join(", ")})`;
    }
  }
  if (typeof sink.root !== "string" || sink.root.length === 0 || !path.isAbsolute(sink.root) || sink.root.includes("\0") || path.normalize(sink.root) !== sink.root) {
    return "rawSink root must be a normalized absolute path";
  }
  for (const field of ["stdoutFile", "stderrFile"]) {
    const problem = validateSingleSegmentName(sink[field], `rawSink ${field}`);
    if (problem) return problem;
  }
  if (sink.stdoutFile === sink.stderrFile) {
    return "rawSink stdoutFile and stderrFile must be different names";
  }
  if (sink.onClosed !== undefined && typeof sink.onClosed !== "function") {
    return "rawSink onClosed must be a function when provided";
  }
  return null;
}

/**
 * Prepares the sink root: it must already be its canonical realpath, a real
 * directory, and fresh (empty). The captured identity (device/inode/mode) is
 * re-verified after every sink open, mirroring the root-binding containment
 * the harness applies to bound reads and exclusive publications.
 */
async function captureRawSinkRoot(root) {
  let canonical;
  try {
    canonical = await realpath(root);
  } catch (cause) {
    throw new Error(`raw sink root must exist and be canonical: ${cause?.code ?? cause?.message ?? "unknown"}`);
  }
  if (canonical !== root) throw new Error("raw sink root must already be its canonical realpath");
  let info;
  try {
    info = await stat(root);
  } catch (cause) {
    throw new Error(`raw sink root cannot be inspected: ${cause?.code ?? cause?.message ?? "unknown"}`);
  }
  if (!info.isDirectory()) throw new Error("raw sink root must be a directory");
  if ((await readdir(root)).length !== 0) throw new Error("raw sink root must be fresh (empty)");
  return { canonical, identity: { dev: info.dev, ino: info.ino, mode: info.mode } };
}

async function openRawSinkFile(captured, filename) {
  const flags = FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL |
    (FS_CONSTANTS.O_NOFOLLOW ?? 0) | (FS_CONSTANTS.O_CLOEXEC ?? 0);
  const handle = await openFile(path.join(captured.canonical, filename), flags, 0o600);
  try {
    const info = await stat(captured.canonical);
    if (info.dev !== captured.identity.dev || info.ino !== captured.identity.ino || info.mode !== captured.identity.mode) {
      throw new Error("raw sink root changed while opening sink files");
    }
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
  return handle;
}

function makeRawStreamState(handle, limit) {
  return { handle, hash: createHash("sha256"), bytes: 0, limit, queue: Promise.resolve(), closed: false };
}

function enqueueRawChunk(state, chunk) {
  const bytes = Buffer.from(chunk);
  state.hash.update(bytes);
  state.bytes += bytes.length;
  state.queue = state.queue.then(() => state.handle.write(bytes));
  return state.queue;
}

async function closeRawStreamState(state) {
  if (state.closed) return;
  state.closed = true;
  // A failed write or fsync must not skip the close attempt.  Preserve the
  // first failure for the caller, but make every later durability/close step
  // best-effort so a FileHandle never becomes a GC-cleanup leak.
  let primary = null;
  try {
    await state.queue;
  } catch (error) {
    primary = error;
  }
  try {
    await state.handle.sync();
  } catch (error) {
    primary ??= error;
  }
  try {
    await state.handle.close();
  } catch (error) {
    primary ??= error;
  }
  if (primary !== null) throw primary;
}

function rawStreamSummary(state) {
  return { sha256: state.hash.digest("hex"), bytes: state.bytes, sensitivity: "private" };
}

// ---------------------------------------------------------------------------
// Default dependency implementations (all injectable for deterministic tests)
// ---------------------------------------------------------------------------

const defaultDeps = Object.freeze({
  spawn: nodeSpawn,
  platform: process.platform,
  killSignal(pid, signal) {
    process.kill(pid, signal);
  },
  nowMs: () => Date.now(),
  isoNow(ms) {
    return new Date(ms ?? Date.now()).toISOString();
  },
  setInterval: (fn, ms) => setInterval(fn, ms),
  clearInterval: (id) => clearInterval(id),
  statMtimeMs(filePath) {
    try {
      return statSync(filePath).mtimeMs;
    } catch {
      return 0;
    }
  },
  readFileUtf8(filePath) {
    return readFileSync(filePath, "utf8");
  },
  fileExists(filePath) {
    return existsSync(filePath);
  },
  writeFileBytes(filePath, bytes) {
    // Atomic replace via same-directory temp file + rename (single writer:
    // the final envelope replaces the startup trace exactly once).
    const dir = path.dirname(filePath);
    const tmp = path.join(
      dir,
      `.watchdog-evidence-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.tmp`,
    );
    writeFileSync(tmp, bytes);
    renameSync(tmp, filePath);
  },
});

// ---------------------------------------------------------------------------
// Process-group signalling (mirrors loop-agent signalProcess semantics)
// ---------------------------------------------------------------------------

function sendSignal(deps, child, processGroupId, signal, sequence) {
  const requestedMode = deps.platform === "win32" ? "child_process" : "process_group";
  const attempt = { signal, requestedMode };
  if (requestedMode === "process_group") {
    try {
      deps.killSignal(-processGroupId, signal);
      attempt.successfulMode = "process_group";
      sequence.push(attempt);
      return true;
    } catch (error) {
      if (error.code !== "ESRCH") {
        sequence.push(attempt);
        return false;
      }
    }
  }
  try {
    if (child.kill(signal)) {
      attempt.successfulMode = "child_process";
      sequence.push(attempt);
      return true;
    }
  } catch {
    // fall through to failure
  }
  sequence.push(attempt);
  return false;
}

function isTargetLive(deps, child, processGroupId) {
  if (deps.platform !== "win32" && processGroupId !== undefined) {
    try {
      deps.killSignal(-processGroupId, 0);
      return true;
    } catch (error) {
      if (error.code !== "ESRCH") return true;
    }
  }
  if (child.exitCode !== null && child.exitCode !== undefined) return false;
  if (child.signalCode !== null && child.signalCode !== undefined) return false;
  try {
    return child.kill(0);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Progress observation (files only; no stream semantics are interpreted)
// ---------------------------------------------------------------------------

/**
 * A terminal record is a JSON file with a non-empty string `identity` and an
 * optional string `status`. The mechanism requires the record to be newer
 * than supervision start and carries the identity/status as facts without
 * interpreting them (business interpretation stays consumer-owned).
 */
function readTerminalRecord(deps, filePath, startedAtMs) {
  if (!deps.fileExists(filePath)) return null;
  let mtimeMs;
  try {
    mtimeMs = deps.statMtimeMs(filePath);
  } catch {
    return null;
  }
  if (mtimeMs < startedAtMs) return null;
  let value;
  try {
    value = JSON.parse(deps.readFileUtf8(filePath));
  } catch {
    return null;
  }
  if (!isPlainObject(value)) return null;
  if (typeof value.identity !== "string" || value.identity.length === 0) return null;
  if (value.status !== undefined && typeof value.status !== "string") return null;
  return {
    file: filePath,
    identity: value.identity,
    ...(value.status !== undefined ? { status: value.status } : {}),
  };
}

function sameTerminalObservation(left, right) {
  return left?.identity === right?.identity;
}

/** Startup progress exists when any progress path has a non-empty file newer than start. */
function hasStartupProgress(deps, progressPaths, startedAtMs) {
  return progressPaths.some((rel) => {
    const mtimeMs = deps.statMtimeMs(rel);
    return mtimeMs > 0 && mtimeMs >= startedAtMs;
  });
}

// ---------------------------------------------------------------------------
// Envelope assembly
// ---------------------------------------------------------------------------

const WATCHDOG_TO_TERMINATION = Object.freeze({
  max_seconds: "hard_ceiling",
  startup_stale_progress: "startup_idle",
  stale_progress: "stream_idle",
  tool_lease_expired: "tool_lease_expired",
  runtime_error: "failed_to_start",
  terminal_progress: "completed",
  no_terminal_result: "completed",
  residual_process_group: "child_exit",
  context_budget_exhausted: "context_budget_exhausted",
  output_limit_exceeded: "output_limit_exceeded",
});

function mapWatchdogToTermination(watchdogReason) {
  if (watchdogReason === null) return null;
  return WATCHDOG_TO_TERMINATION[watchdogReason] ?? null;
}

function processStatusFor(watchdogReason, terminationReason, spawnError, sawLeaderExit) {
  if (spawnError) return "FAILED_TO_START";
  if (watchdogReason !== null && TIMEOUT_WATCHDOG_REASONS.has(watchdogReason)) return "TIMED_OUT";
  if (watchdogReason === "terminal_progress") return "EXITED";
  if (watchdogReason === "no_terminal_result") {
    if (terminationReason === "terminal_progress") return "TERMINATED";
    // Natural self-exit without the required terminal record keeps EXITED;
    // a vanished process (external kill, no exit event) is TERMINATED
    // because the terminal state was never confirmed — fail-closed.
    return sawLeaderExit ? "EXITED" : "TERMINATED";
  }
  if (watchdogReason !== null) return "TERMINATED";
  return "EXITED";
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

function buildEnvelope({
  startedAtMs,
  finishedAtMs,
  command,
  args,
  cwd,
  child,
  processGroupId,
  spawnError,
  exitStatus,
  termination,
  watchdogReason,
  signalSequence,
  forcedKill,
  timeoutPolicy,
  outputByteLimits,
  outputLimitExceeded,
  progressPaths,
  terminalProgressPaths,
  terminalSeen,
  residualGroupCleanupCompleted,
  checkIntervalSeconds,
  isoNow,
}) {
  const terminationReason = mapWatchdogToTermination(watchdogReason);
  const sawLeaderExit = (child?.exitCode !== null && child?.exitCode !== undefined)
    || (child?.signalCode !== null && child?.signalCode !== undefined);
  const processStatus = processStatusFor(
    watchdogReason,
    termination?.reason ?? null,
    spawnError ?? null,
    sawLeaderExit,
  );
  const ok = watchdogReason === "terminal_progress"
    ? outputLimitExceeded === null
    : watchdogReason === null
      ? exitStatus === 0 && outputLimitExceeded === null
      : false;
  const evidence = {
    command,
    args,
    cwd,
    startedAt: isoNow(startedAtMs),
    finishedAt: isoNow(finishedAtMs),
    checkIntervalSeconds,
    ...(child?.pid !== undefined ? { pid: child.pid } : {}),
    ...(processGroupId !== undefined ? { processGroupId } : {}),
    ...(child?.exitCode !== null && child?.exitCode !== undefined
      ? { childExitCode: child.exitCode }
      : {}),
    ...(child?.signalCode != null ? { childSignal: child.signalCode } : {}),
    ...(spawnError ? { spawnError: spawnError.message } : {}),
    signalSequence,
    forcedKill,
    startupProgressPaths: progressPaths,
    terminalProgressPaths,
    timeoutPolicy,
    ...(outputByteLimits !== undefined ? { outputByteLimits, outputLimitExceeded } : {}),
    ...(terminalSeen ? { terminalIdentity: terminalSeen.identity } : {}),
    ...(terminalSeen?.status !== undefined ? { terminalStatus: terminalSeen.status } : {}),
    ...(residualGroupCleanupCompleted !== undefined
      ? { residualGroupCleanupCompleted }
      : {}),
    guarantees: [...ENVELOPE_GUARANTEES],
  };
  // The envelope is the single writer's only output: deep-frozen so no
  // caller can mutate the evidence after publication.
  return deepFreeze({
    schemaVersion: 1,
    kind: ENVELOPE_KIND,
    ok,
    exitStatus,
    processStatus,
    terminationReason,
    watchdogReason,
    evidence,
  });
}

// ---------------------------------------------------------------------------
// Main supervision
// ---------------------------------------------------------------------------

/**
 * Supervise one bounded subprocess through its lifecycle.
 *
 * @param {object} options
 * @param {string} options.command - command to spawn (consumer-supplied).
 * @param {string[]} options.args - argument vector (may be empty).
 * @param {string} options.cwd - working directory of the supervised process.
 * @param {object} [options.env] - child environment; defaults to process.env.
 * @param {object} options.timeoutPolicy - { maxSeconds, killGraceSeconds,
 *   startupStaleSeconds?, startupIdleSeconds?, streamIdleSeconds?,
 *   toolLeaseSeconds? }; all values consumer-supplied, closed field set,
 *   `additionalProperties: false` equivalent enforced by
 *   validateTimeoutPolicy (timeout-policy-invalid otherwise).
 * @param {string[]} [options.progressPaths] - startup-progress marker files
 *   (relative to cwd); their appearance completes the startup phase.
 * @param {string[]} [options.terminalProgressPaths] - terminal-record JSON
 *   files ({ identity: string, status?: string }); requires
 *   terminalGraceSeconds.
 * @param {number} [options.terminalGraceSeconds] - stability window a
 *   terminal record must persist before the mechanism closes the process
 *   with watchdog_reason terminal_progress.
 * @param {number} [options.checkIntervalSeconds=1] - supervision cadence.
 * @param {{stdout?: number, stderr?: number}} [options.outputByteLimits] -
 *   optional independent raw-byte caps; equal is allowed, first excess
 *   immediately enters the existing process-group termination path.
 * @param {() => boolean} [options.longToolActive] - consumer-owned long-tool
 *   activity probe; enables the tool-lease dimension (requires
 *   toolLeaseSeconds). Stream-idle is suspended while the probe is true.
 * @param {() => boolean|Promise<boolean>} [options.budgetExhausted] -
 *   consumer-owned context-budget observation hook; true terminates with
 *   watchdog_reason context_budget_exhausted (thresholds stay consumer-side).
 * @param {string} [options.evidencePath] - optional persistence of the
 *   supervision trace (started_at + cadence at spawn, per forensics) and the
 *   final envelope (atomic replace; write failure fails closed).
 * @param {object} [options.rawSink] - optional raw-byte sink
 *   (FND-DES-012 section 6): { root, stdoutFile, stderrFile, onClosed? }
 *   where root must be a fresh (empty) directory that already is its
 *   canonical realpath, and the two file names must be distinct
 *   single-segment relative names. Both files are opened
 *   exclusive/no-follow with mode 0600 before spawn, and closed only after
 *   child close, both stream closes, every queued write, fsync and handle
 *   close. onClosed receives the frozen { stdout, stderr } summaries.
 * @param {object} [deps] - injected dependencies for deterministic tests.
 * @returns {Promise<object>} exactly one watchdog-termination-envelope.
 * @throws {TypeError} on option shape violations (programming errors).
 * @throws {HarnessError} SFC2004 + kind timeout-policy-invalid on policy
 *   shape violations; SFC2004 + kind supervise-process-failed when the
 *   supervision mechanism itself fails (evidence persistence failure,
 *   un-finalizable termination, consumer callback throwing); the rejection
 *   details carry the assembled termination evidence.
 */
export async function superviseProcess(options, deps = {}) {
  validateOptions(options);
  const d = { ...defaultDeps, ...deps };

  const {
    command,
    args,
    cwd,
    env,
    timeoutPolicy,
    progressPaths = [],
    terminalProgressPaths = [],
    terminalGraceSeconds,
    checkIntervalSeconds = 1,
    longToolActive,
    budgetExhausted,
    evidencePath,
  } = options;
  const sink = options.rawSink ?? null;
  const outputByteLimits = options.outputByteLimits;
  let rawStreams = null;
  if (sink !== null) {
    try {
      const captured = await captureRawSinkRoot(sink.root);
      const stdoutHandle = await openRawSinkFile(captured, sink.stdoutFile);
      let stderrHandle;
      try {
        stderrHandle = await openRawSinkFile(captured, sink.stderrFile);
      } catch (error) {
        await stdoutHandle.close().catch(() => {});
        throw error;
      }
      rawStreams = {
        stdout: makeRawStreamState(stdoutHandle, outputByteLimits?.stdout),
        stderr: makeRawStreamState(stderrHandle, outputByteLimits?.stderr),
      };
    } catch (error) {
      if (rawStreams?.stdout) await closeRawStreamState(rawStreams.stdout).catch(() => {});
      if (rawStreams?.stderr) await closeRawStreamState(rawStreams.stderr).catch(() => {});
      throw mechanismError("supervise-process-failed", "failed to open raw stream sink", { causeMessage: error.message });
    }
  }

  const startedAtMs = d.nowMs();
  const intervalMs = Math.max(1, checkIntervalSeconds * 1000);
  const startupIdleSeconds = timeoutPolicy.startupIdleSeconds ?? timeoutPolicy.startupStaleSeconds;
  const leaseMs = timeoutPolicy.toolLeaseSeconds !== undefined
    ? timeoutPolicy.toolLeaseSeconds * 1000
    : null;

  // Startup trace persistence (forensics: start time + deterministic cadence
  // survive an external kill of the whole supervision tree). Failure fails
  // closed before any process is spawned.
  if (evidencePath !== undefined) {
    try {
      d.writeFileBytes(
        evidencePath,
        JSON.stringify(
          {
            schemaVersion: 1,
            kind: TRACE_KIND,
            phase: "supervising",
            startedAt: d.isoNow(startedAtMs),
            checkIntervalSeconds,
            command,
            args,
            cwd,
          },
          null,
          2,
        ),
      );
    } catch (error) {
      // Trace persistence happens after both exclusive sink handles opened
      // but before spawn.  The trace error is primary; all opened handles
      // still have to be closed before this fail-closed rejection escapes.
      if (rawStreams !== null) {
        await Promise.allSettled([
          closeRawStreamState(rawStreams.stdout),
          closeRawStreamState(rawStreams.stderr),
        ]);
      }
      throw mechanismError(
        "supervise-process-failed",
        `failed to persist the supervision trace at ${evidencePath}`,
        { causeMessage: error.message },
      );
    }
  }

  const lifecycle = {
    phase: "running", // running | terminating | finished
    termination: null, // { reason, requestedAt, killRequestedAt, forcedKill, terminalIdentity? }
    leaderResult: null, // child 'exit' event payload { code, signalCode }
    runtimeError: null,
    vanish: false,
    everSeenLive: false,
    residualGroupCleanupCompleted: undefined,
    watchdogSignalSucceeded: false,
    finalizing: false,
    outputLimitExceeded: null,
    outputBytes: { stdout: 0, stderr: 0 },
  };
  const signalSequence = [];
  let interval = null;
  let terminalSeen = null;
  let terminalSeenAtMs = null;
  let leaseUntilMs = null;
  let lastStreamActivityAtMs = null;
  let startupProgressSeen = false;
  let tickInFlight = false;
  let resolveLifecycle;
  let rejectLifecycle;
  const lifecyclePromise = new Promise((resolve, reject) => {
    resolveLifecycle = resolve;
    rejectLifecycle = reject;
  });

  // Close-state tracking is initialized before spawn so a synchronous spawn
  // failure can still complete the sink close path deterministically (no
  // child or streams ever exist in that path).
  let resolveChildClosed;
  let resolveStdoutClosed;
  let resolveStderrClosed;
  const childClosed = new Promise((resolve) => { resolveChildClosed = resolve; });
  const stdoutClosed = new Promise((resolve) => { resolveStdoutClosed = resolve; });
  const stderrClosed = new Promise((resolve) => { resolveStderrClosed = resolve; });

  let child;
  try {
    child = d.spawn(command, args, {
      cwd,
      env: env ?? process.env,
      detached: d.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (spawnError) {
    return finalizeSpawnFailure(spawnError, { noChild: true });
  }
  const processGroupId = d.platform !== "win32" ? child.pid : undefined;
  if (rawStreams) {
    child.on("close", () => resolveChildClosed());
    if (child.stdout) child.stdout.on("close", () => resolveStdoutClosed());
    else resolveStdoutClosed();
    if (child.stderr) child.stderr.on("close", () => resolveStderrClosed());
    else resolveStderrClosed();
  }

  function finishLifecycle(result) {
    if (lifecycle.phase === "finished") return;
    lifecycle.phase = "finished";
    if (interval !== null) {
      d.clearInterval(interval);
      interval = null;
    }
    if (result instanceof Error) {
      rejectLifecycle(result);
    } else {
      resolveLifecycle(result);
    }
  }

  async function closeRawStreams() {
    if (!rawStreams) return;
    // Ordered durability: the child must be fully closed (which implies both
    // stdio streams closed), then each sink's queued writes must complete,
    // then each sink is fsynced and closed before the consumer callback.
    await Promise.all([childClosed, stdoutClosed, stderrClosed]);
    // Do not let a first sink error return before the other already-open
    // handle has reached its own close attempt.  The stdout result remains
    // the deterministic primary when both paths fail.
    const closed = await Promise.allSettled([
      closeRawStreamState(rawStreams.stdout),
      closeRawStreamState(rawStreams.stderr),
    ]);
    const primary = closed.find((outcome) => outcome.status === "rejected");
    if (primary) throw primary.reason;
    if (typeof sink.onClosed === "function") {
      await sink.onClosed(Object.freeze({
        stdout: rawStreamSummary(rawStreams.stdout),
        stderr: rawStreamSummary(rawStreams.stderr),
      }));
    }
  }

  async function persistFinalEnvelope(envelope) {
    if (evidencePath === undefined) return envelope;
    try {
      d.writeFileBytes(evidencePath, JSON.stringify(envelope, null, 2));
    } catch (error) {
      throw mechanismError(
        "supervise-process-failed",
        `failed to persist the termination envelope at ${evidencePath}`,
        {
          watchdogReason: envelope.watchdogReason,
          terminationReason: envelope.terminationReason,
          exitStatus: envelope.exitStatus,
          processStatus: envelope.processStatus,
          evidence: envelope.evidence,
        },
      );
    }
    return envelope;
  }

  function assembleEnvelope() {
    const termination = lifecycle.termination;
    let watchdogReason = lifecycle.vanish
      ? "no_terminal_result"
      : (termination?.reason ?? null);
    if (watchdogReason === null && lifecycle.outputLimitExceeded !== null) {
      watchdogReason = "output_limit_exceeded";
    }

    // Terminal requirement reconciliation (R9-equivalent): when terminal
    // progress paths are configured and the close was authoritative
    // (no termination, or a terminal_progress close), the terminal record
    // must still be present at publication; otherwise fail closed with
    // no_terminal_result.
    if (terminalProgressPaths.length > 0) {
      const terminalCanBeAuthoritative = termination === null || termination.reason === "terminal_progress";
      if (terminalCanBeAuthoritative) {
        const expectedIdentity = termination?.reason === "terminal_progress"
          ? termination.terminalIdentity
          : termination === null
            ? terminalSeen?.identity
            : null;
        const finalTerminal = readTerminalRecord(d, path.resolve(cwd, terminalProgressPaths[0]), startedAtMs);
        terminalSeen = expectedIdentity
          ? (finalTerminal?.identity === expectedIdentity ? finalTerminal : null)
          : termination === null
            ? finalTerminal
            : null;
      } else {
        terminalSeen = null;
      }
      if (!terminalSeen && (termination === null || termination.reason === "terminal_progress")) {
        watchdogReason = "no_terminal_result";
      }
    }

    const exitStatus = watchdogReason === "terminal_progress"
      ? 0
      : termination !== null || watchdogReason === "no_terminal_result"
        ? 124
        : (lifecycle.leaderResult?.code ?? 128);

    return buildEnvelope({
      startedAtMs,
      finishedAtMs: d.nowMs(),
      command,
      args,
      cwd,
      child,
      processGroupId,
      spawnError: null,
      exitStatus,
      termination,
      watchdogReason,
      signalSequence,
      forcedKill: termination?.forcedKill === true,
      timeoutPolicy,
      outputByteLimits,
      outputLimitExceeded: lifecycle.outputLimitExceeded,
      progressPaths,
      terminalProgressPaths,
      terminalSeen,
      residualGroupCleanupCompleted: lifecycle.residualGroupCleanupCompleted,
      checkIntervalSeconds,
      isoNow: d.isoNow,
    });
  }

  function finalizeFailure(error) {
    let envelope;
    try {
      envelope = assembleEnvelope();
    } catch (assembleError) {
      finishLifecycle(mechanismError("supervise-process-failed", error.message, {
        causeMessage: assembleError.message,
      }));
      return;
    }
    finishLifecycle(mechanismError("supervise-process-failed", error.message, {
      watchdogReason: envelope.watchdogReason,
      terminationReason: envelope.terminationReason,
      exitStatus: envelope.exitStatus,
      processStatus: envelope.processStatus,
      evidence: envelope.evidence,
    }));
  }

  async function finalize() {
    if (lifecycle.finalizing) return;
    lifecycle.finalizing = true;
    try {
      await closeRawStreams();
    } catch (error) {
      lifecycle.runtimeError = error;
    }
    const envelope = assembleEnvelope();
    if (lifecycle.runtimeError !== null) {
      // Internal mechanism failure: persist the evidence when possible,
      // then REJECT with SFC2004 (the envelope is not delivered as a
      // resolved value — the consumer reads it from details/evidencePath).
      try {
        await persistFinalEnvelope(envelope);
      } catch (persistError) {
        finishLifecycle(persistError);
        return;
      }
      finishLifecycle(mechanismError("supervise-process-failed", lifecycle.runtimeError.message, {
        watchdogReason: envelope.watchdogReason,
        terminationReason: envelope.terminationReason,
        exitStatus: envelope.exitStatus,
        processStatus: envelope.processStatus,
        evidence: envelope.evidence,
      }));
      return;
    }
    try {
      await persistFinalEnvelope(envelope);
    } catch (error) {
      finalizeFailure(error);
      return;
    }
    finishLifecycle(envelope);
  }

  async function finalizeSpawnFailure(spawnError, { noChild = false } = {}) {
    if (noChild) {
      // No child object exists (synchronous spawn failure): close-state
      // tracking resolves immediately so the sink close path completes
      // deterministically and the caller still receives the envelope.
      resolveChildClosed();
      resolveStdoutClosed();
      resolveStderrClosed();
    }
    const envelope = buildEnvelope({
      startedAtMs,
      finishedAtMs: d.nowMs(),
      command,
      args,
      cwd,
      child: { pid: undefined, exitCode: null, signalCode: null },
      processGroupId: undefined,
      spawnError,
      exitStatus: 128,
      termination: null,
      watchdogReason: null,
      signalSequence: [],
      forcedKill: false,
      timeoutPolicy,
      outputByteLimits,
      outputLimitExceeded: null,
      progressPaths,
      terminalProgressPaths,
      terminalSeen: null,
      residualGroupCleanupCompleted: undefined,
      checkIntervalSeconds,
      isoNow: d.isoNow,
    });
    try {
      await closeRawStreams();
    } catch (error) {
      throw mechanismError("supervise-process-failed", "failed to close the raw stream sink after spawn failure", {
        causeMessage: error.message,
        watchdogReason: envelope.watchdogReason,
        terminationReason: envelope.terminationReason,
        exitStatus: envelope.exitStatus,
        processStatus: envelope.processStatus,
        evidence: envelope.evidence,
      });
    }
    return persistFinalEnvelope(envelope);
  }

  function elapsedAtLeast(fromMs, nowMs, seconds) {
    return fromMs !== null && fromMs !== undefined && (nowMs - fromMs) / 1000 >= seconds;
  }

  function beginTermination(reason, nowMsValue) {
    if (lifecycle.phase !== "running" || lifecycle.leaderResult !== null) return false;
    if (!isTargetLive(d, child, processGroupId)) return false;
    lifecycle.phase = "terminating";
    lifecycle.termination = {
      reason,
      requestedAt: nowMsValue,
      killRequestedAt: null,
      forcedKill: false,
      ...(reason === "terminal_progress" && terminalSeen ? { terminalIdentity: terminalSeen.identity } : {}),
    };
    const signalSucceeded = sendSignal(d, child, processGroupId, "SIGTERM", signalSequence);
    if (signalSucceeded) lifecycle.watchdogSignalSucceeded = true;
    return true;
  }

  function beginResidualGroupFinalizer(nowMsValue) {
    if (lifecycle.phase !== "running" || lifecycle.leaderResult === null) return false;
    if (processGroupId === undefined) return false;
    if (!isTargetLive(d, child, processGroupId)) return false;
    lifecycle.phase = "terminating";
    lifecycle.termination = {
      reason: "residual_process_group",
      requestedAt: nowMsValue,
      killRequestedAt: null,
      forcedKill: false,
    };
    const signalSucceeded = sendSignal(d, child, processGroupId, "SIGTERM", signalSequence);
    if (signalSucceeded) lifecycle.watchdogSignalSucceeded = true;
    return true;
  }

  function superviseLifecycle(nowMsValue) {
    if (lifecycle.phase === "running") {
      if (lifecycle.leaderResult !== null) {
        if (processGroupId !== undefined && isTargetLive(d, child, processGroupId)) {
          beginResidualGroupFinalizer(nowMsValue);
        } else {
          finalize();
        }
      }
      return;
    }
    if (lifecycle.phase !== "terminating") return;

    const targetWasLive = isTargetLive(d, child, processGroupId);
    if (!targetWasLive) {
      if (lifecycle.termination?.reason === "residual_process_group") {
        lifecycle.residualGroupCleanupCompleted = true;
      }
      if (lifecycle.leaderResult !== null) {
        if (
          lifecycle.termination?.reason !== "residual_process_group"
          && !lifecycle.watchdogSignalSucceeded
          && lifecycle.runtimeError === null
        ) {
          // The leader exited before any watchdog signal landed; the
          // natural completion wins over the unexecuted termination.
          lifecycle.termination = null;
        }
      }
      // The target is gone: the termination completed (or was never needed).
      // This holds even when the exit event was lost — never hang.
      finalize();
      return;
    }

    if (lifecycle.termination === null) return;
    const termination = lifecycle.termination;
    if (
      termination.killRequestedAt !== null
      && elapsedAtLeast(termination.killRequestedAt, nowMsValue, timeoutPolicy.killGraceSeconds)
    ) {
      // The target survived SIGTERM + grace + SIGKILL; one best-effort
      // SIGKILL retry before failing closed (the process group may outlive
      // the mechanism — documented, consumer-owned cleanup). finalize()
      // persists the evidence envelope and rejects with SFC2004.
      sendSignal(d, child, processGroupId, "SIGKILL", signalSequence);
      lifecycle.runtimeError = new Error(
        termination.reason === "residual_process_group"
          ? "residual process group remained live after SIGKILL finalization"
          : `termination target remained live after SIGKILL finalization (${termination.reason})`,
      );
      void finalize();
      return;
    }
    if (
      termination.killRequestedAt === null
      && elapsedAtLeast(termination.requestedAt, nowMsValue, timeoutPolicy.killGraceSeconds)
    ) {
      const signalSucceeded = sendSignal(d, child, processGroupId, "SIGKILL", signalSequence);
      if (signalSucceeded) {
        termination.forcedKill = true;
        lifecycle.watchdogSignalSucceeded = true;
      }
      termination.killRequestedAt = nowMsValue;
    }
  }

  async function tick(nowMsValue) {
    if (tickInFlight) return;
    tickInFlight = true;
    try {
      if (lifecycle.phase === "terminating") {
        superviseLifecycle(nowMsValue);
        return;
      }
      if (lifecycle.phase !== "running") return;

      const live = isTargetLive(d, child, processGroupId);
      if (live) lifecycle.everSeenLive = true;

      // Fail-closed liveness: a process that was confirmed live and then
      // vanished without an exit event (external kill) must not hang the
      // supervisor; report the failure envelope. A never-live child is a
      // spawn-side failure and waits for the 'error' event.
      if (
        lifecycle.leaderResult === null
        && (child.exitCode ?? null) === null
        && (child.signalCode ?? null) === null
        && !live
        && lifecycle.everSeenLive
      ) {
        lifecycle.vanish = true;
        await finalize();
        return;
      }

      if (lifecycle.runtimeError !== null) {
        if (beginTermination("runtime_error", nowMsValue)) superviseLifecycle(nowMsValue);
        return;
      }

      const elapsedMs = nowMsValue - startedAtMs;

      // Step 1: consumer-owned context-budget observation hook. The
      // mechanism holds no thresholds; the consumer decides what "exhausted"
      // means. Budget exhaustion takes priority over every timeout dimension.
      if (budgetExhausted !== undefined) {
        const exhausted = await budgetExhausted();
        if (exhausted === true) {
          if (beginTermination("context_budget_exhausted", nowMsValue)) superviseLifecycle(nowMsValue);
          return;
        }
      }

      // Step 2: terminal progress. A stable terminal record closes the
      // process as a success (terminal_progress) after terminalGraceSeconds.
      if (terminalProgressPaths.length > 0) {
        const terminal = readTerminalRecord(d, path.resolve(cwd, terminalProgressPaths[0]), startedAtMs);
        if (!sameTerminalObservation(terminal, terminalSeen)) {
          terminalSeenAtMs = terminal !== null ? nowMsValue : null;
          terminalSeen = terminal;
        }
        if (
          terminalSeenAtMs !== null
          && terminalGraceSeconds !== undefined
          && (nowMsValue - terminalSeenAtMs) / 1000 >= terminalGraceSeconds
        ) {
          if (beginTermination("terminal_progress", nowMsValue)) superviseLifecycle(nowMsValue);
          return;
        }
      }

      // Step 3: stream activity observation (any stdout/stderr line renews
      // activity; business interpretation stays consumer-owned). With
      // progress paths configured, their appearance completes the startup
      // phase; without them the startup phase ends on first stream activity.
      const streamActive = lastStreamActivityAtMs !== null;
      if (progressPaths.length > 0) {
        const startupProgress = hasStartupProgress(d, progressPaths.map((rel) => path.resolve(cwd, rel)), startedAtMs);
        if (startupProgress && !startupProgressSeen) startupProgressSeen = true;
      }
      const startupComplete = streamActive || (progressPaths.length > 0 && startupProgressSeen);

      // Long-tool lease dimension (consumer-owned activity probe). The
      // lease is established when the probe first reports true and renewed
      // only by stream activity; it expires on its own otherwise.
      const longTool = longToolActive !== undefined && longToolActive() === true;
      if (longTool) {
        if (leaseMs !== null) {
          if (leaseUntilMs === null) leaseUntilMs = nowMsValue + leaseMs;
          if (streamActive) leaseUntilMs = nowMsValue + leaseMs;
        }
      } else {
        leaseUntilMs = null;
      }

      // Step 4: deterministic timeout priority
      // (hard_ceiling > startup_idle > stream_idle > tool_lease_expired).
      if (timeoutPolicy.maxSeconds !== undefined && elapsedMs / 1000 >= timeoutPolicy.maxSeconds) {
        if (beginTermination("max_seconds", nowMsValue)) superviseLifecycle(nowMsValue);
        return;
      }
      if (
        startupIdleSeconds !== undefined
        && !startupComplete
        && elapsedMs / 1000 >= startupIdleSeconds
      ) {
        if (beginTermination("startup_stale_progress", nowMsValue)) superviseLifecycle(nowMsValue);
        return;
      }
      if (leaseMs !== null && longTool && leaseUntilMs !== null && nowMsValue >= leaseUntilMs) {
        if (beginTermination("tool_lease_expired", nowMsValue)) superviseLifecycle(nowMsValue);
        return;
      }
      if (timeoutPolicy.streamIdleSeconds !== undefined && !longTool) {
        const sinceActivity = lastStreamActivityAtMs !== null
          ? nowMsValue - lastStreamActivityAtMs
          : elapsedMs;
        if (sinceActivity / 1000 >= timeoutPolicy.streamIdleSeconds) {
          if (beginTermination("stale_progress", nowMsValue)) superviseLifecycle(nowMsValue);
          return;
        }
      }
    } catch (error) {
      lifecycle.runtimeError = error;
      if (beginTermination("runtime_error", nowMsValue)) {
        superviseLifecycle(nowMsValue);
      } else {
        // The termination target is already gone (or un-terminatable):
        // close immediately instead of hanging.
        await finalize();
      }
    } finally {
      tickInFlight = false;
    }
  }

  function handleOutputChunk(stream, chunk) {
    const bytes = Buffer.from(chunk);
    lifecycle.outputBytes[stream] += bytes.length;
    const limit = outputByteLimits?.[stream];
    let saved = bytes;
    if (limit !== undefined) {
      const allowed = Math.max(0, limit - (lifecycle.outputBytes[stream] - bytes.length));
      saved = bytes.subarray(0, allowed);
      if (lifecycle.outputBytes[stream] > limit) {
        lifecycle.outputLimitExceeded ??= stream;
        if (beginTermination("output_limit_exceeded", d.nowMs())) superviseLifecycle(d.nowMs());
      }
    }
    if (rawStreams && saved.length > 0) {
      void enqueueRawChunk(rawStreams[stream], saved).catch((error) => { lifecycle.runtimeError = error; });
    }
  }

  // Wire the child events.
  child.stdout?.on("data", () => {
    lastStreamActivityAtMs = d.nowMs();
  });
  child.stderr?.on("data", () => {
    lastStreamActivityAtMs = d.nowMs();
  });
  child.stdout?.on("data", (chunk) => handleOutputChunk("stdout", chunk));
  child.stderr?.on("data", (chunk) => handleOutputChunk("stderr", chunk));
  child.on("exit", (code, signalCode) => {
    lifecycle.leaderResult = { code, signalCode };
    superviseLifecycle(d.nowMs());
  });
  child.on("error", (error) => {
    // Spawn error delivered asynchronously (e.g. ENOENT). The child was
    // never confirmed live, so the vanish path cannot have claimed it.
    if (lifecycle.phase === "running" && lifecycle.leaderResult === null) {
      finalizeSpawnFailure(error)
        .then((envelope) => finishLifecycle(envelope))
        .catch((persistError) => finishLifecycle(persistError));
    }
  });

  interval = d.setInterval(() => {
    void tick(d.nowMs());
  }, intervalMs);
  superviseLifecycle(d.nowMs());

  try {
    return await lifecyclePromise;
  } finally {
    if (interval !== null) {
      d.clearInterval(interval);
      interval = null;
    }
  }
}
