/**
 * skill-family-harness-node: the default Node mechanism runtime for Skill
 * Family engineering contracts.
 *
 * The harness is a thin runtime: it consumes skill-family-contracts (envelopes,
 * schemas, dialect routing, kernel protocol, stable error codes, fixtures)
 * and implements mechanism only — validator caching, contained filesystem
 * access, atomic writes, temporary workspaces, resource closure, and the
 * operation-request -> operation-result pipeline. It owns no business
 * semantics, no orchestration, no git, no network, and no second language.
 */

export const HARNESS_CAPABILITIES = Object.freeze([
  "schema-validation",
  "atomic-write",
  "strict-file-publication",
  "nonblocking-filesystem-lock",
  "path-containment",
  "temporary-workspace",
  "resource-closure",
  "operation-envelope",
  "host-adapter-mechanism",
  "report-rendering",
  "durable-state-store",
  "baseline-materialization",
  "read-chokepoint",
  "surface-scan",
  "declared-read-surface",
  "structured-scan",
  "token-estimation",
  "upper-bound-guard",
  "supervise-process",
  // Foundation capability completion (FG-1/FG-2): strict authority reads and
  // pre-persistence URL credential redaction.
  "strict-read",
  "url-credential-redaction",
]);

export const HARNESS_EXCLUSIONS = Object.freeze([
  "business-semantics",
  "workflow-orchestration",
  "git-writes",
  "model-calls",
  "release-state",
  "remote-network-access",
]);

export { HarnessError, HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";

export { classifyPathInput, resolveContained, readFileContained } from "./paths.mjs";

// Strict contained read (FG-1): no-follow, regular-file identity assertion,
// and a post-read sha256 digest receipt for existing authority files.
export { readFileStrict } from "./strict-read.mjs";

// Generic URL credential redaction (FG-2): strip userinfo before any value
// reaches disk or logs; unparseable input degrades to an opaque placeholder.
export { redactUrlCredentials, REDACTED_URL_PLACEHOLDER } from "./url-redaction.mjs";

export { writeFileAtomic, publishFileExclusive, publishFileOrReplace, replaceFileAtomic } from "./atomic.mjs";

export {
  acquireFilesystemLock,
  inspectFilesystemLock,
  releaseFilesystemLock,
  recoverFilesystemLock,
} from "./token-lock.mjs";

export {
  TemporaryWorkspace,
  createTemporaryWorkspace,
  withTemporaryWorkspace,
} from "./workspace.mjs";

// Finite-closed-semantics tools (FND-ADR-009). Mechanism only: baseline
// byte fidelity, read admission, strategy-driven surface scanning,
// deterministic estimation, and the consumer-injected usage upper bound.
export { computeDirectoryDigest, materializeBaseline } from "./baseline.mjs";

export { createReadChokepoint } from "./chokepoint.mjs";

export { scanSurface } from "./surface-scan.mjs";

export { assertDeclaredReadSurface } from "./declared-read-surface.mjs";

export { scanSurfaceStructured, STRUCTURED_SCAN_RULES, isIpv6ShapedRun, extractIpCandidates, normalizeIpToken, classifyIpToken, collectLockfileCommentRegions } from "./structured-scan.mjs";

export {
  estimateTokenUpperBound,
  estimateTokens,
  isCjkCodePoint,
  CJK_CODE_POINT_RANGES,
  TOKEN_ESTIMATOR_ID,
  TOKEN_ESTIMATOR_VERSION,
  TOKEN_ESTIMATION_ALGORITHM,
} from "./token-estimate.mjs";

// Minimal consumption contract of the token estimate record (SG-33): the
// contracts-owned consumption functions are re-exported next to the estimator
// so mechanism consumers keep one import surface. Pure functions only.
export {
  TOKEN_ESTIMATE_CONSUMPTION,
  TOKEN_ESTIMATE_CONSUMPTION_REASONS,
  TOKEN_ESTIMATE_CONSUMPTION_ERROR_KIND,
  consumeTokenEstimate,
  consumeTokenEstimateStrict,
} from "skill-family-contracts";

export {
  openUsageGuard,
  appendUsageEvent,
  readUsage,
  closeUsageGuard,
} from "./budget-guard.mjs";

// Bounded subprocess supervision (FND-ADR-012). Mechanism only: one bounded
// spawn, liveness by explicit events, consumer-supplied timeout policy,
// SIGTERM -> grace -> SIGKILL against the process group, terminal-progress
// observation, and a single closed-enum termination envelope. The mechanism
// never restarts the supervised process and never holds timeout values;
// retry/restart policy and budget thresholds stay consumer-owned.
export {
  superviseProcess,
  validateTimeoutPolicy,
  WATCHDOG_REASONS,
  TERMINATION_REASONS,
  PROCESS_STATUSES,
  ENVELOPE_GUARANTEES,
} from "./supervise-process.mjs";

export { digestBytes, computeResourceClosure, closureContains } from "./closure.mjs";

export {
  resolveSchemaContext,
  getValidator,
  validatorCacheSize,
  validateContractDocument,
} from "./validation.mjs";

export { parseRequest, processRequest } from "./request.mjs";

// Generic host mechanism. Concrete host profiles and audited driver vectors
// are injected by downstream orchestration; the harness never imports them.
export {
  normalizeAdapterSource,
  buildAdapterClosure,
  verifyAdapterBuildManifest,
  materializeAdapterBuild,
  probeVersionVector,
} from "./host.mjs";

// Deterministic report layer (FND-ADR-005): validate -> render -> bind -> check.
// Pure functions only: no clock, no environment, no network, no model calls.
export {
  REPORT_RENDERER_NAME,
  REPORT_RENDERER_VERSION,
  SUPPORTED_REPORT_LOCALES,
  EXECUTION_STATUSES,
  RESULT_STATE_EXECUTION_STATUSES,
  REPORT_AUDIENCES,
  REPORT_STYLE_RULES,
  validateReportModel,
  renderReportMarkdown,
  computeResultDigest,
  computeModelDigest,
  digestReport,
  buildBinding,
  verifyBinding,
  checkReport,
  collectStyleWarnings,
} from "./report.mjs";

// Durable state mechanism only. Event meaning and reducer transitions remain
// consumer-owned; the harness owns ordering, integrity, fencing and recovery.
export {
  STATE_GENESIS_DIGEST,
  openStateStore,
  inspectStateStoreLock,
  recoverStateStoreLock,
  appendEvent,
  readEvents,
  readSnapshot,
  writeSnapshot,
  verifyStateStore,
  rebuildSnapshot,
  closeStateStore,
  close,
} from "./state-store.mjs";
