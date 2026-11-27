// @feature FND-FR-037
// @decision FND-ADR-038
// @design FND-DES-047
import { ContractsError } from "./errors.mjs";
import { preflightJsonData } from "./inert-json.mjs";
import { validateDocument } from "./validator.mjs";

/** 跨技能族任务交接信封的公共 Schema $id。 */
export const TASK_HANDOFF_ENVELOPE_SCHEMA_ID =
  "https://contracts.skill-family.example/v1/task-handoff-envelope.json";

/** 跨技能族任务交接信封的文档类型标识。 */
export const TASK_HANDOFF_ENVELOPE_KIND =
  "skill-family.task-handoff-envelope";

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function semanticFailure(message, instancePath, params = {}) {
  return {
    valid: false,
    errorCode: "SFC1001",
    errors: [{
      keyword: "taskHandoffEnvelope",
      instancePath,
      schemaPath: `${TASK_HANDOFF_ENVELOPE_SCHEMA_ID}#semantic`,
      message,
      params,
    }],
    data: undefined,
  };
}

/**
 * 校验跨技能族任务交接信封（结构校验 + 已选与排除方法互斥、上游制品路径唯一性校验）。
 */
export function validateTaskHandoffEnvelope(document) {
  const preflight = preflightJsonData(document, "", {
    keyword: "taskHandoffEnvelope",
    schemaId: TASK_HANDOFF_ENVELOPE_SCHEMA_ID,
    label: "task handoff envelope",
  });
  if (!preflight.valid) return preflight;

  const structural = validateDocument(preflight.data, {
    schemaId: TASK_HANDOFF_ENVELOPE_SCHEMA_ID,
    dialect: "2020-12",
    policy: "strict",
  });
  if (!structural.valid) return structural;

  const data = structural.data;
  const excludedSet = new Set(data.excludedMethods);
  for (let idx = 0; idx < data.selectedMethods.length; idx += 1) {
    const method = data.selectedMethods[idx];
    if (excludedSet.has(method)) {
      return semanticFailure(
        `方法 "${method}" 不能同时出现在 selectedMethods 与 excludedMethods 中`,
        `/selectedMethods/${idx}`,
        { method },
      );
    }
  }

  const seenPaths = new Set();
  for (let idx = 0; idx < data.upstreamArtifacts.length; idx += 1) {
    const artifactPath = data.upstreamArtifacts[idx].path;
    if (seenPaths.has(artifactPath)) {
      return semanticFailure(
        `upstreamArtifacts 中存在重复路径 "${artifactPath}"`,
        `/upstreamArtifacts/${idx}/path`,
        { path: artifactPath },
      );
    }
    seenPaths.add(artifactPath);
  }

  return {
    valid: true,
    errorCode: null,
    errors: [],
    data: deepFreeze(structuredClone(data)),
  };
}

/**
 * 构造并校验一份不可变的跨技能族任务交接信封。校验未通过时抛出 SFC1001。
 */
export function createTaskHandoffEnvelope(input = {}) {
  const candidate = {
    schemaVersion: 1,
    kind: TASK_HANDOFF_ENVELOPE_KIND,
    ...(input && typeof input === "object" && !Array.isArray(input) ? input : {}),
  };
  const outcome = validateTaskHandoffEnvelope(candidate);
  if (!outcome.valid) {
    throw new ContractsError(
      outcome.errorCode ?? "SFC1001",
      outcome.errors?.[0]?.message ?? "任务交接信封未通过契约校验",
      { errors: outcome.errors },
    );
  }
  return outcome.data;
}
