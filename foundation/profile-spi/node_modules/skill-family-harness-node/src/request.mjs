import {
  checkOperation,
  findProtocol,
  findSchemaByObject,
  listProtocols,
  stableError,
} from "skill-family-contracts";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { validateContractDocument } from "./validation.mjs";

/**
 * Kernel protocol intake and execution: operation-request in,
 * operation-result out.
 *
 * Everything structural is delegated to contracts: the envelope is validated
 * against the registered operation-request schema (no re-implementation of
 * envelope rules), protocol/operation intake uses the frozen registry and
 * kernel vocabulary, and every produced result is self-checked against the
 * registered operation-result schema before it is returned.
 *
 * Terminal-state semantics (from the frozen kernel protocol):
 * - a schema-valid request with an unregistered protocol, unknown operation,
 *   or params contract violation is REJECTED at intake;
 * - an accepted operation that fails during execution is FAILED;
 * - SUCCESS is only reached with an empty error list.
 *
 * The result envelope must echo operationId/operation/protocol. When the
 * request envelope is too malformed to echo, deterministic fallback values
 * are used; both branches are mechanically verified against the registered
 * result schema (two-pass build), so no pattern or envelope rule is
 * duplicated here.
 */

const REQUEST_ENVELOPE = Object.freeze({
  schemaVersion: 1,
  kind: "skill-family.operation-result",
});

const FALLBACK_OPERATION_ID = "rejected-intake";
const FALLBACK_OPERATION = "intake";

function schemaIdFor(objectName) {
  const registration = findSchemaByObject(objectName);
  if (!registration) {
    // The frozen contracts registry always registers these objects; reaching
    // this line means the contracts dependency itself is broken.
    throw mechanismError(
      HARNESS_ERROR_KINDS.EXECUTION_FAILED,
      `contracts registry has no schema for object: ${objectName}`,
    );
  }
  return registration.$id;
}

const REQUEST_SCHEMA_ID = schemaIdFor("operation-request");
const RESULT_SCHEMA_ID = schemaIdFor("operation-result");

function findingToEntry(code, finding) {
  const entry = stableError(code, finding.message || "validation failed");
  if (typeof finding.instancePath === "string" && finding.instancePath.length > 0) {
    entry.path = finding.instancePath;
  }
  const details = {};
  if (finding.keyword !== undefined) details.keyword = finding.keyword;
  if (finding.params !== undefined) details.params = finding.params;
  if (Object.keys(details).length > 0) entry.details = details;
  return entry;
}

function genericEntry(code, message) {
  return stableError(code, message);
}

function echoable(raw) {
  const source = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  return {
    protocol:
      source.protocol && typeof source.protocol === "object" && !Array.isArray(source.protocol)
        ? structuredClone(source.protocol)
        : null,
    operationId: typeof source.operationId === "string" ? source.operationId : null,
    operation: typeof source.operation === "string" ? source.operation : null,
  };
}

function fallbackProtocol() {
  const protocols = listProtocols();
  const first = protocols[0];
  if (!first) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.EXECUTION_FAILED,
      "contracts registry lists no protocol",
    );
  }
  return { name: first.name, version: first.version };
}

/**
 * Parses and intake-checks one raw operation-request without executing it.
 * Returns { ok: true, request } or
 * { ok: false, state: "rejected", errors } where errors is a non-empty
 * array of stable-coded entries. The input is deep-cloned and never mutated.
 */
export function parseRequest(raw) {
  let candidate;
  try {
    candidate = structuredClone(raw === undefined ? null : raw);
  } catch {
    return {
      ok: false,
      state: "rejected",
      errors: [
        genericEntry("SFC1001", "request envelope is not serializable structured data"),
      ],
    };
  }
  const envelope = validateContractDocument(candidate, { schemaId: REQUEST_SCHEMA_ID });
  if (!envelope.valid) {
    return {
      ok: false,
      state: "rejected",
      errors: envelope.errors.map((finding) => findingToEntry(envelope.errorCode, finding)),
    };
  }
  const request = envelope.data;
  if (!findProtocol(request.protocol.name, request.protocol.version)) {
    return {
      ok: false,
      state: "rejected",
      errors: [
        genericEntry(
          "SFC1011",
          `unknown protocol: ${request.protocol.name} version ${request.protocol.version}`,
        ),
      ],
    };
  }
  const operationCheck = checkOperation(request.operation, request.params);
  if (!operationCheck.ok) {
    return {
      ok: false,
      state: "rejected",
      errors: operationCheck.errors.map((finding) => findingToEntry(operationCheck.code, finding)),
    };
  }
  return { ok: true, request };
}

function buildResult({ echo, state, outputs, errors, completedAt }) {
  return {
    ...REQUEST_ENVELOPE,
    protocol: echo.protocol ?? fallbackProtocol(),
    operationId: echo.operationId ?? FALLBACK_OPERATION_ID,
    operation: echo.operation ?? FALLBACK_OPERATION,
    state,
    outputs,
    errors,
    completedAt,
  };
}

function assertSchemaValidResult(result) {
  const check = validateContractDocument(result, { schemaId: RESULT_SCHEMA_ID });
  if (!check.valid) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      `harness produced a result that violates the registered operation-result schema: ${check.errors
        .map((finding) => finding.message)
        .join("; ")}`,
    );
  }
}

function finalizeResult(candidate) {
  // Deterministic echo ladder: keep as much of the request echo as the
  // registered result schema accepts, falling back field-group by field-group.
  // Self-verification against the real schema replaces any hand-written
  // envelope rule; the full-fallback rung is schema-valid by construction,
  // so the ladder always converges.
  const rungs = [
    candidate,
    buildResult({
      echo: { protocol: null, operationId: candidate.operationId, operation: candidate.operation },
      state: candidate.state,
      outputs: candidate.outputs,
      errors: candidate.errors,
      completedAt: candidate.completedAt,
    }),
    buildResult({
      echo: { protocol: null, operationId: null, operation: null },
      state: candidate.state,
      outputs: candidate.outputs,
      errors: candidate.errors,
      completedAt: candidate.completedAt,
    }),
  ];
  for (const rung of rungs) {
    const check = validateContractDocument(rung, { schemaId: RESULT_SCHEMA_ID });
    if (check.valid) return rung;
  }
  assertSchemaValidResult(rungs[rungs.length - 1]); // throws INVALID_RESULT
  return rungs[rungs.length - 1]; // unreachable
}

async function executeValidateOperation(request) {
  const params = request.params;
  const dialect = params.dialect; // undefined means: use the registration's dialect
  const policy = params.policy ?? "strict";
  const outcome = validateContractDocument(params.document, {
    schemaId: params.schemaId,
    dialect,
    policy,
  });
  if (outcome.valid) {
    return {
      state: "succeeded",
      outputs: { report: { valid: true, errors: [] } },
      errors: [],
    };
  }
  const entries =
    outcome.errorCode === "SFC1001"
      ? outcome.errors.map((finding) => findingToEntry("SFC1001", finding))
      : [findingToEntry(outcome.errorCode, outcome.errors[0] ?? { message: "validation failed" })];
  return { state: "failed", outputs: null, errors: entries };
}

/**
 * Processes one raw operation-request and returns a terminal, schema-verified
 * operation-result. Never throws for request-side problems; only a harness
 * bug (an unproducible result) throws. Options: { now } clock injection for
 * deterministic completedAt values (defaults to the system clock).
 */
export async function processRequest(raw, { now = () => new Date() } = {}) {
  const completedAt = now().toISOString();
  const parsed = parseRequest(raw);
  const echo = echoable(raw);
  if (!parsed.ok) {
    return finalizeResult(
      buildResult({
        echo,
        state: parsed.state,
        outputs: null,
        errors: parsed.errors,
        completedAt,
      }),
    );
  }
  let outcome;
  try {
    outcome = await executeValidateOperation(parsed.request);
  } catch (cause) {
    // Any unexpected execution failure becomes a coded terminal result;
    // processRequest never leaks request-side problems as exceptions.
    outcome = {
      state: "failed",
      outputs: null,
      errors: [
        stableError("SFC2004", `operation execution failed: ${cause && cause.message ? cause.message : "unknown"}`, {
          kind: HARNESS_ERROR_KINDS.EXECUTION_FAILED,
        }),
      ],
    };
  }
  return finalizeResult(
    buildResult({
      echo,
      state: outcome.state,
      outputs: outcome.outputs,
      errors: outcome.errors,
      completedAt,
    }),
  );
}
