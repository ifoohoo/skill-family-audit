// @feature FND-FR-039
// @decision FND-ADR-040
// @design FND-DES-049
import { ContractsError } from "./errors.mjs";
import { preflightJsonData } from "./inert-json.mjs";
import {
  ORCHESTRATION_BLUEPRINT_KIND,
  ORCHESTRATION_BLUEPRINT_SCHEMA_ID,
  verifyOrchestrationBlueprintStructure,
} from "./orchestration-blueprint-structure.mjs";
import { validateDocument } from "./validator.mjs";

export {
  ORCHESTRATION_BLUEPRINT_KIND,
  ORCHESTRATION_BLUEPRINT_SCHEMA_ID,
  verifyOrchestrationBlueprintStructure,
};

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

/**
 * 校验一份多会话编排蓝图（JSON 安全预检 + Ajv 2020-12 结构校验 + 图结构与引用完整性）。
 */
export function validateOrchestrationBlueprint(document) {
  const preflight = preflightJsonData(document, "", {
    keyword: "orchestrationBlueprint",
    schemaId: ORCHESTRATION_BLUEPRINT_SCHEMA_ID,
    label: "orchestration blueprint",
  });
  if (!preflight.valid) return preflight;

  const structural = validateDocument(preflight.data, {
    schemaId: ORCHESTRATION_BLUEPRINT_SCHEMA_ID,
    dialect: "2020-12",
    policy: "strict",
  });
  if (!structural.valid) return structural;

  const graphCheck = verifyOrchestrationBlueprintStructure(structural.data);
  if (!graphCheck.valid) return graphCheck;

  return {
    valid: true,
    errorCode: null,
    errors: [],
    data: deepFreeze(structuredClone(structural.data)),
  };
}

/**
 * 构造并校验一份不可变的多会话编排蓝图；未通过时抛出 SFC1001。
 */
export function createOrchestrationBlueprint(input = {}) {
  const candidate = {
    schemaVersion: 1,
    kind: ORCHESTRATION_BLUEPRINT_KIND,
    ...(input && typeof input === "object" && !Array.isArray(input) ? input : {}),
  };
  const outcome = validateOrchestrationBlueprint(candidate);
  if (!outcome.valid) {
    throw new ContractsError(
      outcome.errorCode ?? "SFC1001",
      outcome.errors?.[0]?.message ?? "编排蓝图未通过契约校验",
      { errors: outcome.errors },
    );
  }
  return outcome.data;
}
