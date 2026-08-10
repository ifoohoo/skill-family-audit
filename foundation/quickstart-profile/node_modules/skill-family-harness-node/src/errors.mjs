import { ContractsError, isRegisteredErrorCode } from "skill-family-contracts";

/**
 * Harness error policy.
 *
 * The harness never invents error codes: every thrown or reported error
 * carries a code from the frozen contracts registry. Mechanism failures use
 * SFC2004 (EXECUTION_FAILED) whose registered meaning is "the mechanism
 * runtime failed while executing a well-formed operation; details carry the
 * mechanism evidence". The mechanism evidence is the stable `details.kind`
 * value enumerated in HARNESS_ERROR_KINDS.
 *
 * Adding a brand-new SFC code would be a contracts change (the registry file
 * lives in skill-family-contracts), which is outside this package's write
 * set; the SFC2004 + details.kind pairing keeps the public surface stable
 * without touching the frozen registry.
 */

/**
 * Stable mechanism-failure kinds. Each value appears as `details.kind` on an
 * SFC2004-coded HarnessError or operation-result error entry. The set is
 * frozen for the v1 harness; values are strings so they serialize unchanged.
 */
export const HARNESS_ERROR_KINDS = Object.freeze({
  INVALID_PATH: "invalid-path",
  ABSOLUTE_PATH: "absolute-path",
  WINDOWS_DRIVE_PATH: "windows-drive-path",
  WINDOWS_PATH: "windows-path",
  UNC_PATH: "unc-path",
  PATH_TRAVERSAL: "path-traversal",
  SYMLINK_ESCAPE: "symlink-escape",
  REALPATH_ESCAPE: "realpath-escape",
  INVALID_ROOT: "invalid-root",
  ATOMIC_WRITE_FAILED: "atomic-write-failed",
  READ_FAILED: "read-failed",
  MISSING_RESOURCE: "missing-resource",
  WORKSPACE_CREATE_FAILED: "workspace-create-failed",
  WORKSPACE_DISPOSE_FAILED: "workspace-dispose-failed",
  WORKSPACE_DISPOSED: "workspace-disposed",
  CLOSURE_CONFLICT: "closure-conflict",
  UNSUPPORTED_POLICY: "unsupported-policy",
  EXECUTION_FAILED: "execution-failed",
  INVALID_RESULT: "invalid-result",
  STORE_CLOSED: "store-closed",
  STORE_LOCKED: "store-locked",
  LOCK_CORRUPT: "lock-corrupt",
  LOCK_RECOVERY_REFUSED: "lock-recovery-refused",
  UNSAFE_STATE_ENTRY: "unsafe-state-entry",
  EVENT_SCHEMA_INVALID: "event-schema-invalid",
  DUPLICATE_SEQUENCE: "duplicate-sequence",
  IDEMPOTENCY_CONFLICT: "idempotency-conflict",
  CHAIN_BROKEN: "chain-broken",
  SNAPSHOT_MISMATCH: "snapshot-mismatch",
  HOST_CONTRACT_INVALID: "host-contract-invalid",
  HOST_BUILD_FAILED: "host-build-failed",
  HOST_PROBE_FAILED: "host-probe-failed",
  UNTRUSTED_EXECUTABLE: "untrusted-executable",
  PORTABLE_PATH_COLLISION: "portable-path-collision",
  MANIFEST_MISMATCH: "manifest-mismatch",
});

/**
 * Coded error for mechanism failures. The code must already exist in the
 * frozen contracts registry; construction with anything else is a
 * programming error and throws a TypeError immediately.
 */
export class HarnessError extends ContractsError {
  constructor(code, message, details) {
    if (!isRegisteredErrorCode(code)) {
      throw new TypeError(
        `HarnessError refuses unregistered error code: ${String(code)}`,
      );
    }
    super(code, message, details);
    this.name = "HarnessError";
  }
}

/**
 * Builds the canonical mechanism-failure error: SFC2004 with a stable
 * details.kind. Extra structured evidence may be merged into details but can
 * never override the kind.
 */
export function mechanismError(kind, message, extraDetails) {
  const values = Object.values(HARNESS_ERROR_KINDS);
  if (!values.includes(kind)) {
    throw new TypeError(`mechanismError: unknown harness error kind: ${String(kind)}`);
  }
  const details = { ...(extraDetails ?? {}), kind };
  return new HarnessError("SFC2004", message, details);
}
