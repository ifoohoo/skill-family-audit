// @feature FND-FR-039
// @decision FND-ADR-040
// @design FND-DES-049
import { digestDocument } from "./audit-surface.mjs";
import { ContractsError } from "./errors.mjs";
import { preflightJsonData } from "./inert-json.mjs";
import {
  SESSION_TRACE_BUNDLE_KIND,
  SESSION_TRACE_BUNDLE_SCHEMA_ID,
  stbInvariantFailure,
  verifySessionTraceBundleInvariants,
} from "./session-trace-bundle-invariants.mjs";
import { validateDocument } from "./validator.mjs";

export {
  SESSION_TRACE_BUNDLE_KIND,
  SESSION_TRACE_BUNDLE_SCHEMA_ID,
  verifySessionTraceBundleInvariants,
};

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

/**
 * 校验一份会话追溯包（JSON 安全预检 + Ajv 2020-12 结构校验 + 诚实可观测性与引用不变量）。
 */
export function validateSessionTraceBundle(document) {
  const preflight = preflightJsonData(document, "", {
    keyword: "sessionTraceBundle",
    schemaId: SESSION_TRACE_BUNDLE_SCHEMA_ID,
    label: "session trace bundle",
  });
  if (!preflight.valid) return preflight;

  const structural = validateDocument(preflight.data, {
    schemaId: SESSION_TRACE_BUNDLE_SCHEMA_ID,
    dialect: "2020-12",
    policy: "strict",
  });
  if (!structural.valid) return structural;

  const inv = verifySessionTraceBundleInvariants(structural.data);
  if (!inv.valid) return inv;

  return {
    valid: true,
    errorCode: null,
    errors: [],
    data: deepFreeze(structuredClone(structural.data)),
  };
}

/**
 * 计算除 seal 外的整包规范化 SHA-256 摘要，生成并校验不可变封存追溯包。
 * 调用方必须显式提供 sealOptions.quiescence，机制绝不默认编造进程静默事实。
 */
export function sealSessionTraceBundle(unsignedDocument, sealOptions = {}) {
  if (!unsignedDocument || typeof unsignedDocument !== "object" || Array.isArray(unsignedDocument)) {
    throw new ContractsError("SFC1001", "sealSessionTraceBundle 需要传入对象形态的未封存追溯包");
  }
  if (!sealOptions || typeof sealOptions.quiescence !== "object" || sealOptions.quiescence === null) {
    throw new ContractsError(
      "SFC1001",
      "sealSessionTraceBundle 要求调用方显式提供 sealOptions.quiescence 真实静默探测记录，禁止缺省编造",
    );
  }
  const body = structuredClone(unsignedDocument);
  delete body.seal;
  body.schemaVersion = 1;
  body.kind = SESSION_TRACE_BUNDLE_KIND;
  const bundleDigestSha256 = digestDocument(body);
  const attemptId = sealOptions.attemptId ?? body?.attempt?.attemptId ?? "";
  const candidate = {
    ...body,
    seal: {
      attemptId,
      sealedAt: sealOptions.sealedAt ?? body.createdAt,
      algorithm: "sha256",
      digestScope: "bundle_without_seal",
      bundleDigestSha256,
      quiescence: structuredClone(sealOptions.quiescence),
      externalBinding: sealOptions.externalBinding ?? {
        status: "pending",
        kind: null,
        recordDigest: null,
      },
    },
  };
  const outcome = validateSessionTraceBundle(candidate);
  if (!outcome.valid) {
    throw new ContractsError(
      outcome.errorCode ?? "SFC1001",
      outcome.errors?.[0]?.message ?? "会话追溯包未通过封存校验",
      { errors: outcome.errors },
    );
  }
  return outcome.data;
}

/**
 * 校验一份已封存会话追溯包的结构合法性与 bundleDigestSha256 摘要一致性。
 */
export function verifySessionTraceBundleSeal(document) {
  const outcome = validateSessionTraceBundle(document);
  if (!outcome.valid) return outcome;
  const body = structuredClone(outcome.data);
  const declaredDigest = body.seal.bundleDigestSha256;
  delete body.seal;
  const actualDigest = digestDocument(body);
  if (actualDigest !== declaredDigest) {
    return stbInvariantFailure(
      `会话追溯包封存摘要失配：声明 ${declaredDigest}，重算 ${actualDigest}`,
      "/seal/bundleDigestSha256",
      { expected: declaredDigest, actual: actualDigest },
    );
  }
  return {
    valid: true,
    errorCode: null,
    errors: [],
    bundleDigestSha256: actualDigest,
    data: outcome.data,
  };
}
