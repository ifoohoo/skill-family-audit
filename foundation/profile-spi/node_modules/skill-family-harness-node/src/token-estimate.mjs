/**
 * Deterministic token upper-bound estimation (FND-ADR-009) and the
 * authoritative deterministic token estimator (audit remediation C1).
 *
 * estimateTokenUpperBound is a pure function: no model call, no tokenizer
 * dependency, no network, no persistent state import. It returns the exact
 * UTF-8 byte count of the input text as a conservative upper bound for
 * byte-level BPE tokenizers. The result document follows the frozen
 * token-estimate-result contract and carries no timestamp.
 *
 * estimateTokens is the authoritative token-count estimator referenced by
 * context-budget thresholds (audit SFA-CONTEXT-001/002). Its measurement
 * record carries the estimator identity and version required by audit
 * SFA-CONTEXT-028, so one comparison or threshold decision never silently
 * mixes estimation methods. The record shape is frozen by this module and
 * its tests; promotion into a Contracts schema object is tracked for the
 * next contracts revision.
 *
 * Algorithm "cjk-char-whitespace-split" (complete definition):
 *
 * 1. The input is a JavaScript string, traversed as Unicode code points
 *    (surrogate pairs form one code point).
 * 2. Every code point belongs to exactly one of three classes:
 *    - CJK: a code point inside one of the frozen CJK_CODE_POINT_RANGES
 *      (Extension A, Unified Ideographs, Compatibility Ideographs,
 *      Extensions B through G).
 *    - WHITESPACE: a code point matched by the ECMAScript \s class —
 *      U+0009..U+000D, U+0020, U+00A0, U+1680, U+2000..U+200A, U+2028,
 *      U+2029, U+202F, U+205F, U+3000, U+FEFF.
 *    - OTHER: every remaining code point (letters, digits, punctuation,
 *      emoji, all other scripts).
 * 3. Segmentation: each CJK code point is exactly one token and also
 *    terminates any open OTHER run; each maximal contiguous run of OTHER
 *    code points, delimited by WHITESPACE or by CJK code points, is
 *    exactly one token; WHITESPACE code points are separators and never
 *    contribute a token themselves (consecutive separators do not create
 *    empty tokens).
 * 4. tokens = cjkCharacters + otherRuns. The estimate is a deterministic
 *    measurement convention: it declares no bias direction relative to any
 *    real tokenizer. Identical input always yields the identical record.
 *
 * Scope guarantee: content text only. Model control tokens and non-text
 * content are not covered, and the bias direction (never underestimating a
 * byte-level tokenizer's byte budget) is declared in the contract.
 */

const GUARANTEES = Object.freeze([
  "covers-content-text-only",
  "no-model-calls",
  "no-tokenizer-dependency",
  "no-network-access",
  "deterministic-byte-count",
]);

const TOKEN_GUARANTEES = Object.freeze([
  "covers-content-text-only",
  "no-model-calls",
  "no-tokenizer-dependency",
  "no-network-access",
  "deterministic-segmentation",
]);

/**
 * Authoritative estimator identity (SFA-CONTEXT-028): every measurement
 * record carries this id/version pair; a threshold decision must not mix
 * records produced by different estimator identities.
 */
export const TOKEN_ESTIMATOR_ID = "skill-family.token-estimator";
export const TOKEN_ESTIMATOR_VERSION = "1.0.0";
export const TOKEN_ESTIMATION_ALGORITHM = "cjk-char-whitespace-split";

/**
 * The frozen CJK code-point ranges of the segmentation rule. Both ends are
 * inclusive. Changing these ranges changes the estimator identity and
 * requires a new TOKEN_ESTIMATOR_VERSION.
 */
export const CJK_CODE_POINT_RANGES = Object.freeze([
  Object.freeze({ start: 0x3400, end: 0x4dbf, name: "CJK Extension A" }),
  Object.freeze({ start: 0x4e00, end: 0x9fff, name: "CJK Unified Ideographs" }),
  Object.freeze({ start: 0xf900, end: 0xfaff, name: "CJK Compatibility Ideographs" }),
  Object.freeze({ start: 0x20000, end: 0x3134f, name: "CJK Extensions B through G" }),
]);

const WHITESPACE_CODE_POINT = /\s/u;

/** Classifies one code point against the frozen CJK ranges. */
export function isCjkCodePoint(codePoint) {
  if (!Number.isInteger(codePoint) || codePoint < 0) {
    throw new TypeError("isCjkCodePoint: codePoint must be a non-negative integer");
  }
  for (const range of CJK_CODE_POINT_RANGES) {
    if (codePoint >= range.start && codePoint <= range.end) return true;
  }
  return false;
}

/**
 * Deterministic token estimation (authoritative estimator).
 *
 * Pure function: no model call, no tokenizer dependency, no network, no
 * persistent state, no timestamp. Returns a frozen measurement record that
 * carries the estimator identity and version (SFA-CONTEXT-028) together
 * with the exact segmentation counts, so any consumer can re-derive the
 * token total: tokens === segmentation.cjkCharacters + segmentation.otherRuns.
 */
export function estimateTokens(text) {
  if (typeof text !== "string") {
    throw new TypeError("estimateTokens: text must be a string");
  }
  let codePoints = 0;
  let cjkCharacters = 0;
  let whitespaceSeparators = 0;
  let otherRuns = 0;
  let otherRunOpen = false;
  for (const character of text) {
    codePoints += 1;
    const codePoint = character.codePointAt(0);
    if (isCjkCodePoint(codePoint)) {
      if (otherRunOpen) {
        otherRuns += 1;
        otherRunOpen = false;
      }
      cjkCharacters += 1;
    } else if (WHITESPACE_CODE_POINT.test(character)) {
      if (otherRunOpen) {
        otherRuns += 1;
        otherRunOpen = false;
      }
      whitespaceSeparators += 1;
    } else {
      otherRunOpen = true;
    }
  }
  if (otherRunOpen) otherRuns += 1;
  const tokens = cjkCharacters + otherRuns;
  return Object.freeze({
    schemaVersion: 1,
    kind: "skill-family.token-estimate-record",
    estimator: Object.freeze({
      id: TOKEN_ESTIMATOR_ID,
      version: TOKEN_ESTIMATOR_VERSION,
    }),
    algorithm: TOKEN_ESTIMATION_ALGORITHM,
    unit: "tokens",
    input: Object.freeze({
      codePoints,
      inputBytes: Buffer.byteLength(text, "utf8"),
    }),
    segmentation: Object.freeze({
      cjkCharacters,
      whitespaceSeparators,
      otherRuns,
    }),
    tokens,
    precision: "deterministic-heuristic",
    scope: "content-text-only",
    guarantees: TOKEN_GUARANTEES,
  });
}

export function estimateTokenUpperBound(text) {
  if (typeof text !== "string") {
    throw new TypeError("estimateTokenUpperBound: text must be a string");
  }
  const inputBytes = Buffer.byteLength(text, "utf8");
  return Object.freeze({
    schemaVersion: 1,
    kind: "skill-family.token-estimate-result",
    algorithm: "utf8-byte-count",
    unit: "bytes",
    inputBytes,
    upperBound: inputBytes,
    precision: "exact",
    scope: "content-text-only",
    guarantees: GUARANTEES,
  });
}
