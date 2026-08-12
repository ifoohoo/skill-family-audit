import { canonicalJson, digestDocument, isRegisteredErrorCode } from "../contracts/index.mjs";
import {
  QUICKSTART_PROTOCOL,
  findNonJsonValue,
  validateQuickstartProfileDocument,
} from "../contracts-candidate/index.mjs";
import { computeResourceClosure, digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, HarnessError, mechanismError } from "./errors.mjs";

/**
 * Candidate quickstart profile v2 mechanisms (unstable).
 *
 * The harness only interprets mechanism constraints: contained reads, real
 * byte digests, profile validation, and per-field Task/Result binding. The
 * single operation is the business-neutral execute-method; params.method,
 * params.parameters, and domainResult are caller-owned and never read here.
 */

const QUICKSTART_OPERATION = "execute-method";
const RESULT_STATES = Object.freeze(["succeeded", "failed", "rejected"]);
const CORRELATION_FIELDS = Object.freeze(["run", "stage", "attempt"]);
const ERROR_ENTRY_FIELDS = new Set(["code", "message", "path", "details"]);

function invalidProfile(kind, outcome) {
  return mechanismError(
    HARNESS_ERROR_KINDS.INVALID_RESULT,
    `quickstart ${kind} violates the Foundation candidate profile`,
    { category: "profile", profileKind: kind, findings: outcome.errors },
  );
}

function assertProfile(kind, document) {
  const outcome = validateQuickstartProfileDocument(kind, document);
  if (!outcome.valid) throw invalidProfile(kind, outcome);
  return outcome.data;
}

/**
 * Caller-owned values must be pure JSON before they enter any Task or
 * Result: this refuses BigInt and friends before structuredClone,
 * digestDocument, or JSON.stringify could throw or silently drift.
 */
function assertJsonValue(caller, label, value) {
  const issue = findNonJsonValue(value);
  if (issue) {
    throw new TypeError(
      `${caller}: ${label} must be a JSON value; found ${issue.reason}` +
        (issue.instancePath ? ` at ${issue.instancePath}` : ""),
    );
  }
}

function containedPath(resource, roleDescription) {
  const relPath = resource?.location?.path;
  if (typeof relPath !== "string") {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      `the quickstart ${roleDescription} Resource must use a contained relative path`,
      { category: "resource-location", resourceId: resource?.id },
    );
  }
  return relPath;
}

/** Create one observation Resource from the actual contained file bytes. */
export async function createObservationResource({ root, path, id = "observation" } = {}) {
  const closure = await computeResourceClosure({
    root,
    resources: [{ path, role: "input" }],
  });
  const record = closure.resources[0];
  const resource = {
    schemaVersion: 1,
    kind: "skill-family.resource",
    id,
    location: { path: record.path },
    role: "observation",
    digest: { algorithm: "sha256", value: record.sha256 },
  };
  return assertProfile("resource", resource);
}

/**
 * Recomputes the real byte digest of one path-backed Resource and compares it
 * with the declared digest. URI-backed Resources are structurally checked
 * only: Foundation never fetches URIs.
 */
export async function verifyResourceBytes({ root, resource } = {}) {
  const normalized = assertProfile("resource", resource);
  const relPath = normalized.location.path;
  if (typeof relPath !== "string") {
    return { resource: normalized, byteDigest: null };
  }
  const closure = await computeResourceClosure({
    root,
    resources: [{ path: relPath, role: "input" }],
  });
  const actual = closure.resources[0].sha256;
  if (actual !== normalized.digest.value) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      `quickstart ${normalized.role} Resource digest does not match its current bytes`,
      {
        category: "resource-bytes",
        role: normalized.role,
        resourceId: normalized.id,
        expected: normalized.digest.value,
        actual,
      },
    );
  }
  return { resource: normalized, byteDigest: actual };
}

/** Verify the single observation Resource: role, path-backed location, bytes. */
export async function verifyObservationResource({ root, resource } = {}) {
  const normalized = assertProfile("resource", resource);
  if (normalized.role !== "observation") {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      "quickstart task input must have the observation role",
      { category: "resource-role", resourceId: normalized.id, role: normalized.role },
    );
  }
  containedPath(normalized, "observation");
  const { byteDigest } = await verifyResourceBytes({ root, resource: normalized });
  return { resource: normalized, byteDigest };
}

/** Build a candidate v2 Task inside the stable operation-request envelope. */
export async function createQuickstartTask({
  root,
  observationPath,
  observationId = "observation",
  operationId,
  method,
  parameters = {},
  run,
  stage,
  attempt,
} = {}) {
  assertJsonValue("createQuickstartTask", "parameters", parameters);
  const observation = await createObservationResource({
    root,
    path: observationPath,
    id: observationId,
  });
  const task = {
    schemaVersion: 1,
    kind: "skill-family.operation-request",
    protocol: { ...QUICKSTART_PROTOCOL },
    operationId,
    operation: QUICKSTART_OPERATION,
    params: {
      method,
      parameters: structuredClone(parameters),
      inputs: [observation],
      correlation: { run, stage, attempt },
    },
  };
  return assertProfile("task", task);
}

function normalizeErrorEntries(errors) {
  if (!Array.isArray(errors) || errors.length === 0) {
    throw new TypeError(
      "wrapQuickstartResult: failed and rejected results require at least one error entry",
    );
  }
  assertJsonValue("wrapQuickstartResult", "errors", errors);
  return errors.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new TypeError(`wrapQuickstartResult: error entry ${index} must be an object`);
    }
    const extraField = Object.keys(entry).find((field) => !ERROR_ENTRY_FIELDS.has(field));
    if (extraField !== undefined) {
      throw new TypeError(
        `wrapQuickstartResult: error entry ${index} has unsupported field ${extraField}`,
      );
    }
    const { code, message, path, details } = entry;
    if (typeof code !== "string" || !isRegisteredErrorCode(code)) {
      throw new TypeError(
        `wrapQuickstartResult: error entry ${index} code must be registered in the frozen contracts error registry`,
      );
    }
    if (typeof message !== "string" || message.length === 0) {
      throw new TypeError(
        `wrapQuickstartResult: error entry ${index} must carry a non-empty message`,
      );
    }
    if (path !== undefined) {
      assertJsonValue("wrapQuickstartResult", `error entry ${index} path`, path);
    }
    if (details !== undefined) {
      assertJsonValue("wrapQuickstartResult", `error entry ${index} details`, details);
    }
    const normalized = { code, message };
    if (path !== undefined) normalized.path = path;
    if (details !== undefined) normalized.details = structuredClone(details);
    return normalized;
  });
}

/**
 * Wrap one terminal Result for the candidate protocol. succeeded builds the
 * full outputs envelope (summary, outputs, evidence, domainResult,
 * taskBinding with exactly one evidenceBindings entry per evidence
 * Resource); failed and rejected always carry null outputs and at least one
 * registry-registered error.
 */
export function wrapQuickstartResult({
  task,
  state = "succeeded",
  summary,
  outputs = [],
  evidence = [],
  domainResult,
  errors,
} = {}) {
  const normalizedTask = assertProfile("task", task);
  if (!RESULT_STATES.includes(state)) {
    throw new TypeError(
      `wrapQuickstartResult: state must be one of ${RESULT_STATES.join(", ")}`,
    );
  }
  const observation = normalizedTask.params.inputs[0];
  const base = {
    schemaVersion: 1,
    kind: "skill-family.operation-result",
    protocol: structuredClone(normalizedTask.protocol),
    operationId: normalizedTask.operationId,
    operation: normalizedTask.operation,
    state,
  };
  if (state !== "succeeded") {
    for (const [name, value] of [
      ["summary", summary],
      ["outputs", outputs],
      ["evidence", evidence],
      ["domainResult", domainResult],
    ]) {
      const untouched =
        (name === "outputs" || name === "evidence") && Array.isArray(value) && value.length === 0;
      if (!untouched && value !== undefined) {
        throw new TypeError(
          `wrapQuickstartResult: ${state} results never carry ${name}; outputs must be null`,
        );
      }
    }
    return assertProfile("result", {
      ...base,
      outputs: null,
      errors: normalizeErrorEntries(errors),
    });
  }
  if (typeof summary !== "string" || summary.length === 0) {
    throw new TypeError("wrapQuickstartResult: succeeded results require a non-empty summary");
  }
  assertJsonValue("wrapQuickstartResult", "outputs", outputs);
  assertJsonValue("wrapQuickstartResult", "evidence", evidence);
  assertJsonValue("wrapQuickstartResult", "domainResult", domainResult);
  const normalizedEvidence = structuredClone(evidence);
  const correlation = structuredClone(normalizedTask.params.correlation);
  return assertProfile("result", {
    ...base,
    outputs: {
      summary,
      outputs: structuredClone(outputs),
      evidence: normalizedEvidence,
      domainResult: structuredClone(domainResult),
      taskBinding: {
        operationId: normalizedTask.operationId,
        taskDigest: digestDocument(normalizedTask),
        observationId: observation.id,
        observationDigest: observation.digest.value,
        correlation,
        evidenceBindings: normalizedEvidence.map((resource) => ({
          resourceId: resource?.id,
          operationId: normalizedTask.operationId,
          observationId: observation.id,
          correlation: structuredClone(correlation),
        })),
      },
    },
    errors: [],
  });
}

/**
 * Per-field correlation comparison: run, stage, and attempt mismatches are
 * reported as distinguishable paths instead of one opaque binding mismatch.
 */
function correlationMismatches(actual, expected, prefix) {
  const mismatches = [];
  for (const field of CORRELATION_FIELDS) {
    if (actual[field] !== expected[field]) mismatches.push(`${prefix}.${field}`);
  }
  return mismatches;
}

/**
 * Cross-checks taskBinding.evidenceBindings against the declared evidence
 * Resources: exactly one entry per evidence Resource id, each echoing the
 * exact operationId, observationId, and run/stage/attempt of this Task.
 */
function evidenceBindingMismatches(bindings, evidenceResources, normalizedTask, observation) {
  const mismatches = [];
  const evidenceIds = new Set(evidenceResources.map((resource) => resource.id));
  const bound = new Set();
  bindings.forEach((entry, index) => {
    const { resourceId } = entry;
    if (!evidenceIds.has(resourceId)) {
      mismatches.push(`binding.evidenceBindings.extra:${resourceId}`);
      return;
    }
    if (bound.has(resourceId)) {
      mismatches.push(`binding.evidenceBindings.duplicate:${resourceId}`);
      return;
    }
    bound.add(resourceId);
    const prefix = `binding.evidenceBindings[${index}]`;
    if (entry.operationId !== normalizedTask.operationId) {
      mismatches.push(`${prefix}.operationId`);
    }
    if (entry.observationId !== observation.id) {
      mismatches.push(`${prefix}.observationId`);
    }
    mismatches.push(
      ...correlationMismatches(entry.correlation, normalizedTask.params.correlation, `${prefix}.correlation`),
    );
  });
  for (const resourceId of [...evidenceIds].filter((id) => !bound.has(id)).sort()) {
    mismatches.push(`binding.evidenceBindings.missing:${resourceId}`);
  }
  return mismatches;
}

/**
 * Fail-closed exchange assertion. It validates both candidate profiles,
 * refuses duplicate Resource ids across the Task observation and all
 * output/evidence Resources, recomputes the real bytes of every path-backed
 * Resource, and proves the result echoes and binds the exact
 * protocol/operation/operationId/Task-digest/observation/correlation fields
 * plus one evidenceBindings entry per evidence Resource. No retry or
 * lifecycle state is introduced and no Result file is written.
 */
export async function assertQuickstartExchange({ root, task, result } = {}) {
  const normalizedTask = assertProfile("task", task);
  const normalizedResult = assertProfile("result", result);

  const mismatches = [];
  if (canonicalJson(normalizedResult.protocol) !== canonicalJson(normalizedTask.protocol)) {
    mismatches.push("protocol");
  }
  if (normalizedResult.operation !== normalizedTask.operation) mismatches.push("operation");
  if (normalizedResult.operationId !== normalizedTask.operationId) mismatches.push("operationId");

  const observation = normalizedTask.params.inputs[0];
  if (normalizedResult.state === "succeeded") {
    const declared = [
      observation,
      ...normalizedResult.outputs.outputs,
      ...normalizedResult.outputs.evidence,
    ];
    const seen = new Set();
    for (const resource of declared) {
      if (seen.has(resource.id)) {
        throw mechanismError(
          HARNESS_ERROR_KINDS.INVALID_RESULT,
          `quickstart result declares a duplicate Resource id: ${resource.id}`,
          { category: "duplicate-resource-id", resourceId: resource.id },
        );
      }
      seen.add(resource.id);
    }

    const binding = normalizedResult.outputs?.taskBinding;
    if (!binding) {
      mismatches.push("taskBinding");
    } else {
      if (binding.operationId !== normalizedTask.operationId) {
        mismatches.push("binding.operationId");
      }
      if (binding.taskDigest !== digestDocument(normalizedTask)) {
        mismatches.push("binding.taskDigest");
      }
      if (binding.observationId !== observation.id) mismatches.push("binding.observationId");
      if (binding.observationDigest !== observation.digest.value) {
        mismatches.push("binding.observationDigest");
      }
      mismatches.push(
        ...correlationMismatches(
          binding.correlation,
          normalizedTask.params.correlation,
          "binding.correlation",
        ),
      );
      mismatches.push(
        ...evidenceBindingMismatches(
          binding.evidenceBindings,
          normalizedResult.outputs.evidence,
          normalizedTask,
          observation,
        ),
      );
    }
  }
  if (mismatches.length > 0) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      `quickstart result does not bind the exact task: ${mismatches.join(", ")}`,
      { category: "binding", mismatches },
    );
  }

  await verifyObservationResource({ root, resource: observation });

  if (normalizedResult.state === "succeeded") {
    const declared = [
      ...normalizedResult.outputs.outputs,
      ...normalizedResult.outputs.evidence,
    ];
    for (const resource of declared) {
      await verifyResourceBytes({ root, resource });
    }
  }

  return {
    valid: true,
    state: normalizedResult.state,
    taskDigest: digestDocument(normalizedTask),
    observationDigest: observation.digest.value,
  };
}

/**
 * Non-throwing form for callers that need a structured finding. Every
 * failure resolves to code SFC2004 with a deterministic string details.kind
 * and details.category: HarnessError paths from the closure and containment
 * machinery (missing-resource, path, symlink escapes) keep their stable kind
 * and every useful detail field, ordinary TypeErrors and omitted inputs fall
 * back to the invalid-result/unexpected-failure pair.
 */
export async function verifyQuickstartExchange(input) {
  try {
    return await assertQuickstartExchange(input);
  } catch (cause) {
    const message =
      cause instanceof Error && typeof cause.message === "string" && cause.message.length > 0
        ? cause.message
        : String(cause);
    if (cause instanceof HarnessError) {
      const rawDetails =
        cause.details && typeof cause.details === "object" ? cause.details : {};
      const kind =
        typeof rawDetails.kind === "string" && rawDetails.kind.length > 0
          ? rawDetails.kind
          : HARNESS_ERROR_KINDS.EXECUTION_FAILED;
      const category =
        typeof rawDetails.category === "string" && rawDetails.category.length > 0
          ? rawDetails.category
          : "resource-closure";
      return {
        valid: false,
        code: "SFC2004",
        message,
        details: { ...rawDetails, kind, category },
      };
    }
    return {
      valid: false,
      code: "SFC2004",
      message,
      details: {
        kind: HARNESS_ERROR_KINDS.INVALID_RESULT,
        category: "unexpected-failure",
      },
    };
  }
}

// Candidate consumers may use these generic Foundation mechanisms directly.
// They are thin exports of the stable implementations, not parallel algorithms.
export { canonicalJson, computeResourceClosure, digestBytes, digestDocument };
