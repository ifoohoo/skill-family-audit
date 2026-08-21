import { ContractsError } from "./errors.mjs";

/**
 * Minimal consumption contract of the token estimate record (SG-33, audit
 * friction F1).
 *
 * The authoritative estimator (harness-node `estimateTokens`) returns a full
 * structured record — `token-estimate-record` — never a bare number. Before
 * this contract was frozen, consumers interpolated the record directly into
 * human-facing output and produced `[object Object]` display bugs, while
 * degraded estimators returned bare numbers; both shapes coexisted with no
 * rule saying which field carries the numeric estimate.
 *
 * The frozen minimum consumption contract:
 *
 * 1. Numeric field — the numeric estimate of a record is exactly the
 *    `tokens` field (`numericField`). No other field is a consumption
 *    target; `segmentation` exists for re-derivation and audit, not for
 *    display.
 * 2. Accepted shapes — a consumer may receive either a bare non-negative
 *    integer (the degraded shape) or a record object (the authoritative
 *    shape). Both are consumed through the same extraction: an integer is
 *    the count itself; an object contributes its `tokens` field. An object
 *    that carries a `kind` must carry the frozen record kind, so one
 *    threshold decision never silently mixes estimation methods
 *    (SFA-CONTEXT-028 lineage).
 * 3. Degradation — a degraded estimator (character approximation, no
 *    foundation estimator installed) MAY return the bare integer shape.
 *    Degradation never relaxes warn/hard thresholds, and the consumer must
 *    disclose which estimator source it consumed.
 * 4. Failure policy — fail closed. A missing, malformed, or non-numeric
 *    estimate is a mechanism error; it is never coerced to `0` or any
 *    default. A legitimate `tokens: 0` measurement (empty input) passes
 *    through unchanged — zero is a measurement, never a fallback sentinel.
 *
 * Two consumption forms are frozen: `consumeTokenEstimate` is the pure
 * inspection form returning `{ ok, ... }` (never throws), and
 * `consumeTokenEstimateStrict` is the gate form returning the number or
 * throwing a stable-coded ContractsError (fail closed). Both are pure: no
 * model call, no network, no state, no timestamp.
 */

/** Stable details.kind of every fail-closed consumption refusal. */
export const TOKEN_ESTIMATE_CONSUMPTION_ERROR_KIND = "token-estimate-consumption-failed";

/** The frozen record kind a consumed object may carry. */
const RECORD_KIND = "skill-family.token-estimate-record";

/**
 * The frozen consumption contract statement. Consumers may pin or display
 * this object; its fields are the machine-readable authority for the four
 * rules above.
 */
export const TOKEN_ESTIMATE_CONSUMPTION = Object.freeze({
  schemaVersion: 1,
  kind: "skill-family.token-estimate-consumption-contract",
  numericField: "tokens",
  recordKind: RECORD_KIND,
  acceptedShapes: Object.freeze(["non-negative-integer", "token-estimate-record"]),
  degradation: Object.freeze({
    permittedShape: "non-negative-integer",
    thresholdPolicy: "degradation never relaxes warn/hard thresholds",
    disclosure: "consumers must report which estimator source was consumed",
  }),
  failurePolicy: Object.freeze({
    mode: "fail-closed",
    neverCoerce:
      "a missing, malformed, or non-numeric estimate must never be coerced to 0 or any default; a legitimate tokens=0 measurement passes through unchanged",
    errorCode: "SFC1001",
    errorKind: TOKEN_ESTIMATE_CONSUMPTION_ERROR_KIND,
  }),
});

/** Stable refusal reasons; deterministic order of checks. */
export const TOKEN_ESTIMATE_CONSUMPTION_REASONS = Object.freeze([
  "number-not-a-non-negative-integer",
  "not-a-number-or-record",
  "record-kind-mismatch",
  "record-tokens-missing",
  "record-tokens-not-a-non-negative-integer",
]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonNegativeInteger(value) {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

/**
 * Pure inspection form of the consumption contract. Never throws.
 *
 * Returns one frozen result:
 * - `{ ok: true, tokens, shape }` where shape is "integer" (the degraded
 *   bare-number shape) or "record" (the authoritative structured shape);
 * - `{ ok: false, tokens: null, shape, reasons }` where reasons is a
 *   non-empty subset of TOKEN_ESTIMATE_CONSUMPTION_REASONS in deterministic
 *   check order. `tokens` is exactly null on refusal — never 0.
 */
export function consumeTokenEstimate(raw) {
  if (typeof raw === "number") {
    if (isNonNegativeInteger(raw)) {
      return Object.freeze({ ok: true, tokens: raw, shape: "integer" });
    }
    return Object.freeze({
      ok: false,
      tokens: null,
      shape: "number",
      reasons: Object.freeze(["number-not-a-non-negative-integer"]),
    });
  }
  if (!isPlainObject(raw)) {
    return Object.freeze({
      ok: false,
      tokens: null,
      shape: raw === null ? "null" : Array.isArray(raw) ? "array" : typeof raw,
      reasons: Object.freeze(["not-a-number-or-record"]),
    });
  }
  const reasons = [];
  if (raw.kind !== undefined && raw.kind !== RECORD_KIND) {
    reasons.push("record-kind-mismatch");
  }
  if (raw.tokens === undefined) {
    reasons.push("record-tokens-missing");
  } else if (!isNonNegativeInteger(raw.tokens)) {
    reasons.push("record-tokens-not-a-non-negative-integer");
  }
  if (reasons.length > 0) {
    return Object.freeze({
      ok: false,
      tokens: null,
      shape: "record",
      reasons: Object.freeze(reasons),
    });
  }
  return Object.freeze({ ok: true, tokens: raw.tokens, shape: "record" });
}

/**
 * Gate form of the consumption contract (fail closed). Returns the numeric
 * estimate, or throws a ContractsError coded SFC1001 with
 * `details.kind === "token-estimate-consumption-failed"` and the refusal
 * reasons. Never returns a coerced default; a legitimate zero passes.
 */
export function consumeTokenEstimateStrict(raw) {
  const outcome = consumeTokenEstimate(raw);
  if (outcome.ok) return outcome.tokens;
  throw new ContractsError(
    TOKEN_ESTIMATE_CONSUMPTION.failurePolicy.errorCode,
    `token estimate consumption failed closed: ${outcome.reasons.join(", ")}`,
    {
      kind: TOKEN_ESTIMATE_CONSUMPTION_ERROR_KIND,
      shape: outcome.shape,
      reasons: [...outcome.reasons],
    },
  );
}
