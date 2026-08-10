import { canonicalJson, digestDocument } from "skill-family-contracts";
import {
  QUICKSTART_PROTOCOL,
  validateQuickstartProfileDocument,
} from "skill-family-contracts/candidate/quickstart-profile";
import { computeResourceClosure, digestBytes } from "../src/closure.mjs";
import { HARNESS_ERROR_KINDS, mechanismError } from "../src/errors.mjs";

function invalidProfile(kind, outcome) {
  return mechanismError(
    HARNESS_ERROR_KINDS.INVALID_RESULT,
    `quickstart ${kind} violates the Foundation candidate profile`,
    { profileKind: kind, findings: outcome.errors },
  );
}

function assertProfile(kind, document) {
  const outcome = validateQuickstartProfileDocument(kind, document);
  if (!outcome.valid) throw invalidProfile(kind, outcome);
  return outcome.data;
}

function resourcePath(resource) {
  const relPath = resource?.location?.path;
  if (typeof relPath !== "string") {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      "the quickstart observation Resource must use a contained relative path",
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

/** Recompute and verify the single observation Resource digest. */
export async function verifyObservationResource({ root, resource } = {}) {
  const normalized = assertProfile("resource", resource);
  if (normalized.role !== "observation") {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      "quickstart task input must have the observation role",
    );
  }
  const closure = await computeResourceClosure({
    root,
    resources: [{ path: resourcePath(normalized), role: "input" }],
  });
  const actual = closure.resources[0].sha256;
  if (actual !== normalized.digest.value) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      "observation Resource digest does not match its current bytes",
      { resourceId: normalized.id, expected: normalized.digest.value, actual },
    );
  }
  return { resource: normalized, closureDigest: closure.digest };
}

/** Build a candidate Task inside the existing operation-request envelope. */
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
    operation: "audit",
    params: {
      method,
      parameters: structuredClone(parameters),
      inputs: [observation],
      correlation: { run, stage, attempt },
    },
  };
  return assertProfile("task", task);
}

/** Wrap a domain result inside the existing terminal operation-result envelope. */
export function wrapQuickstartResult({
  task,
  state = "succeeded",
  summary,
  outputs = [],
  evidence = [],
  domainResult,
  errors = [],
} = {}) {
  const normalizedTask = assertProfile("task", task);
  const observation = normalizedTask.params.inputs[0];
  const result = {
    schemaVersion: 1,
    kind: "skill-family.operation-result",
    protocol: structuredClone(normalizedTask.protocol),
    operationId: normalizedTask.operationId,
    operation: normalizedTask.operation,
    state,
    outputs: {
      summary,
      outputs: structuredClone(outputs),
      evidence: structuredClone(evidence),
      domainResult: structuredClone(domainResult),
      taskBinding: {
        operationId: normalizedTask.operationId,
        taskDigest: digestDocument(normalizedTask),
        observationId: observation.id,
        observationDigest: observation.digest.value,
        correlation: structuredClone(normalizedTask.params.correlation),
      },
    },
    errors: structuredClone(errors),
  };
  return assertProfile("result", result);
}

/**
 * Fail-closed exchange assertion. It validates both candidate profiles,
 * recomputes the observation, and proves the result echoes and binds the
 * exact Task/correlation fields. No retry or lifecycle state is introduced.
 */
export async function assertQuickstartExchange({ root, task, result } = {}) {
  const normalizedTask = assertProfile("task", task);
  const normalizedResult = assertProfile("result", result);
  const observation = normalizedTask.params.inputs[0];
  await verifyObservationResource({ root, resource: observation });

  const mismatches = [];
  if (canonicalJson(normalizedResult.protocol) !== canonicalJson(normalizedTask.protocol)) {
    mismatches.push("protocol");
  }
  if (normalizedResult.operationId !== normalizedTask.operationId) mismatches.push("operationId");
  if (normalizedResult.operation !== normalizedTask.operation) mismatches.push("operation");

  const binding = normalizedResult.outputs?.taskBinding;
  if (!binding) {
    mismatches.push("taskBinding");
  } else {
    if (binding.operationId !== normalizedTask.operationId) mismatches.push("binding.operationId");
    if (binding.taskDigest !== digestDocument(normalizedTask)) mismatches.push("binding.taskDigest");
    if (binding.observationId !== observation.id) mismatches.push("binding.observationId");
    if (binding.observationDigest !== observation.digest.value) {
      mismatches.push("binding.observationDigest");
    }
    if (
      canonicalJson(binding.correlation) !==
      canonicalJson(normalizedTask.params.correlation)
    ) {
      mismatches.push("binding.correlation");
    }
  }
  if (mismatches.length > 0) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      `quickstart result does not bind the exact task: ${mismatches.join(", ")}`,
      { mismatches },
    );
  }
  return {
    valid: true,
    taskDigest: digestDocument(normalizedTask),
    observationDigest: observation.digest.value,
  };
}

/** Non-throwing form for callers that need a structured finding. */
export async function verifyQuickstartExchange(input) {
  try {
    return await assertQuickstartExchange(input);
  } catch (cause) {
    return {
      valid: false,
      code: cause?.code ?? "SFC2004",
      message: cause?.message ?? String(cause),
      details: cause?.details,
    };
  }
}

// Candidate consumers may use these generic Foundation mechanisms directly.
// They are thin exports of the stable implementations, not parallel algorithms.
export { canonicalJson, computeResourceClosure, digestBytes, digestDocument };
