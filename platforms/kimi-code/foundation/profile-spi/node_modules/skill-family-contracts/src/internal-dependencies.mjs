// @feature FND-FR-034
// @decision FND-ADR-035
// @design FND-DES-044
import { ContractsError } from "./errors.mjs";
import { digestDocument } from "./audit-surface.mjs";
import { preflightJsonData } from "./inert-json.mjs";
import { validateDocument } from "./validator.mjs";

/** 内部依赖会话选版收据的公共 Schema $id。 */
export const INTERNAL_DEPENDENCY_RECEIPT_SCHEMA_ID =
  "https://contracts.skill-family.example/v1/internal-dependency-resolution-receipt.json";

/** 内部依赖会话选版收据的文档类型标识。 */
export const INTERNAL_DEPENDENCY_RECEIPT_KIND =
  "skill-family.internal-dependency-resolution-receipt";

/** 内部依赖“固定主版本 + 最低可用版本”选版策略标识。 */
export const INTERNAL_DEPENDENCY_POLICY_ID = "fixed-major-min-version-v1";

const EXACT_SEMVER_RE = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const PACKAGE_NAME_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function semanticFailure(message, instancePath, params = {}, schemaId = INTERNAL_DEPENDENCY_RECEIPT_SCHEMA_ID) {
  return {
    valid: false,
    errorCode: "SFC1001",
    errors: [{
      keyword: "internalDependency",
      instancePath,
      schemaPath: `${schemaId}#semantic`,
      message,
      params,
    }],
    data: undefined,
  };
}

function compareLexical(left, right) {
  const leftPoints = Array.from(left, (ch) => ch.codePointAt(0));
  const rightPoints = Array.from(right, (ch) => ch.codePointAt(0));
  const limit = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < limit; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) {
      return leftPoints[index] < rightPoints[index] ? -1 : 1;
    }
  }
  return leftPoints.length - rightPoints.length;
}

/**
 * 解析精确语义化版本号（major.minor.patch，不允许前导零、范围符或预发布标签）。
 * 不合法时返回 null。
 */
export function parseExactSemver(version) {
  if (typeof version !== "string") return null;
  const match = EXACT_SEMVER_RE.exec(version);
  if (!match) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (
    !Number.isSafeInteger(major)
    || !Number.isSafeInteger(minor)
    || !Number.isSafeInteger(patch)
  ) {
    return null;
  }
  return Object.freeze({ major, minor, patch, raw: version });
}

/**
 * 比较两个精确语义化版本号：left < right 返回 -1，相等返回 0，left > right 返回 1。
 * 任一输入不是合法精确版本号时抛出 TypeError。
 */
export function compareExactSemver(left, right) {
  const parsedLeft = parseExactSemver(left);
  const parsedRight = parseExactSemver(right);
  if (!parsedLeft) {
    throw new TypeError(`compareExactSemver: 非法的精确版本号 "${String(left)}"`);
  }
  if (!parsedRight) {
    throw new TypeError(`compareExactSemver: 非法的精确版本号 "${String(right)}"`);
  }
  if (parsedLeft.major !== parsedRight.major) {
    return parsedLeft.major < parsedRight.major ? -1 : 1;
  }
  if (parsedLeft.minor !== parsedRight.minor) {
    return parsedLeft.minor < parsedRight.minor ? -1 : 1;
  }
  if (parsedLeft.patch !== parsedRight.patch) {
    return parsedLeft.patch < parsedRight.patch ? -1 : 1;
  }
  return 0;
}

/**
 * 校验并规范化单个内部依赖声明（支持精确字符串 "x.y.z" 与范围对象 { major, minVersion, verifiedCeiling? }）。
 */
export function validateInternalDependencySpec(spec, instancePath = "") {
  const preflight = preflightJsonData(spec, instancePath, {
    keyword: "internalDependency",
    schemaId: "https://contracts.skill-family.example/v1/project-manifest.json",
    label: "internal dependency spec",
  });
  if (!preflight.valid) return preflight;
  const value = preflight.data;

  if (typeof value === "string") {
    const parsed = parseExactSemver(value);
    if (!parsed) {
      return semanticFailure(
        `内部依赖版本字符串 "${value}" 必须是精确的 major.minor.patch 格式`,
        instancePath,
        { received: value },
        "https://contracts.skill-family.example/v1/project-manifest.json",
      );
    }
    return {
      valid: true,
      errorCode: null,
      errors: [],
      data: deepFreeze({
        mode: "exact",
        major: parsed.major,
        minVersion: parsed.raw,
        verifiedCeiling: parsed.raw,
      }),
    };
  }

  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return semanticFailure(
      "内部依赖声明必须是精确版本字符串或 { major, minVersion, verifiedCeiling? } 对象",
      instancePath,
      {},
      "https://contracts.skill-family.example/v1/project-manifest.json",
    );
  }

  const allowedKeys = new Set(["major", "minVersion", "verifiedCeiling"]);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) {
      return semanticFailure(
        `内部依赖范围声明包含未知字段 "${key}"`,
        `${instancePath}/${key}`,
        { additionalProperty: key },
        "https://contracts.skill-family.example/v1/project-manifest.json",
      );
    }
  }

  if (!Number.isSafeInteger(value.major) || value.major < 0) {
    return semanticFailure(
      "内部依赖范围声明的 major 必须是非负整数（0 表示 0.x 轨道，N>=1 表示 N.x 轨道）",
      `${instancePath}/major`,
      { received: value.major },
      "https://contracts.skill-family.example/v1/project-manifest.json",
    );
  }

  const parsedMin = parseExactSemver(value.minVersion);
  if (!parsedMin) {
    return semanticFailure(
      "内部依赖范围声明的 minVersion 必须是精确的 major.minor.patch 版本号",
      `${instancePath}/minVersion`,
      { received: value.minVersion },
      "https://contracts.skill-family.example/v1/project-manifest.json",
    );
  }
  if (parsedMin.major !== value.major) {
    return semanticFailure(
      `minVersion "${parsedMin.raw}" 的主版本号（${parsedMin.major}）与声明的 major（${value.major}）不一致`,
      `${instancePath}/minVersion`,
      { major: value.major, minVersion: parsedMin.raw },
      "https://contracts.skill-family.example/v1/project-manifest.json",
    );
  }

  let ceiling = null;
  if (value.verifiedCeiling !== undefined) {
    const parsedCeiling = parseExactSemver(value.verifiedCeiling);
    if (!parsedCeiling) {
      return semanticFailure(
        "verifiedCeiling 必须是精确的 major.minor.patch 版本号",
        `${instancePath}/verifiedCeiling`,
        { received: value.verifiedCeiling },
        "https://contracts.skill-family.example/v1/project-manifest.json",
      );
    }
    if (parsedCeiling.major !== value.major) {
      return semanticFailure(
        `verifiedCeiling "${parsedCeiling.raw}" 的主版本号（${parsedCeiling.major}）与声明的 major（${value.major}）不一致`,
        `${instancePath}/verifiedCeiling`,
        { major: value.major, verifiedCeiling: parsedCeiling.raw },
        "https://contracts.skill-family.example/v1/project-manifest.json",
      );
    }
    if (compareExactSemver(parsedCeiling.raw, parsedMin.raw) < 0) {
      return semanticFailure(
        `verifiedCeiling "${parsedCeiling.raw}" 不得低于 minVersion "${parsedMin.raw}"`,
        `${instancePath}/verifiedCeiling`,
        { minVersion: parsedMin.raw, verifiedCeiling: parsedCeiling.raw },
        "https://contracts.skill-family.example/v1/project-manifest.json",
      );
    }
    ceiling = parsedCeiling.raw;
  }

  return {
    valid: true,
    errorCode: null,
    errors: [],
    data: deepFreeze({
      mode: "range",
      major: value.major,
      minVersion: parsedMin.raw,
      verifiedCeiling: ceiling,
    }),
  };
}

/**
 * 校验项目清单中的 internalDependencies 映射，返回按包名字典序规范化的结果。
 */
export function validateInternalDependencyMap(dependencyMap, instancePath = "/internalDependencies") {
  const preflight = preflightJsonData(dependencyMap, instancePath, {
    keyword: "internalDependency",
    schemaId: "https://contracts.skill-family.example/v1/project-manifest.json",
    label: "internal dependencies map",
  });
  if (!preflight.valid) return preflight;
  const map = preflight.data;
  if (!map || typeof map !== "object" || Array.isArray(map)) {
    return semanticFailure(
      "internalDependencies 必须是键值对象",
      instancePath,
      {},
      "https://contracts.skill-family.example/v1/project-manifest.json",
    );
  }
  const normalized = {};
  const names = Object.keys(map).sort(compareLexical);
  for (const pkgName of names) {
    if (!PACKAGE_NAME_RE.test(pkgName)) {
      return semanticFailure(
        `内部依赖包名 "${pkgName}" 不符合 npm 包名格式`,
        `${instancePath}/${pkgName}`,
        { packageName: pkgName },
        "https://contracts.skill-family.example/v1/project-manifest.json",
      );
    }
    const checked = validateInternalDependencySpec(map[pkgName], `${instancePath}/${pkgName}`);
    if (!checked.valid) return checked;
    normalized[pkgName] = checked.data;
  }
  return { valid: true, errorCode: null, errors: [], data: deepFreeze(normalized) };
}

function validateResolutionEntries(resolutions, overallStatus) {
  for (let index = 0; index < resolutions.length; index += 1) {
    const entry = resolutions[index];
    const basePath = `/resolutions/${index}`;
    if (index > 0) {
      const prev = resolutions[index - 1].packageName;
      if (prev === entry.packageName) {
        return semanticFailure(
          `resolutions 中存在重复包名 "${entry.packageName}"`,
          `${basePath}/packageName`,
          { packageName: entry.packageName },
        );
      }
      if (compareLexical(prev, entry.packageName) > 0) {
        return semanticFailure(
          "resolutions 必须按 packageName 的 Unicode 码位升序排列",
          `${basePath}/packageName`,
          { previous: prev, current: entry.packageName },
        );
      }
    }
    const minParsed = parseExactSemver(entry.minVersion);
    if (!minParsed || minParsed.major !== entry.major) {
      return semanticFailure(
        `minVersion "${entry.minVersion}" 的主版本号必须等于 major (${entry.major})`,
        `${basePath}/minVersion`,
        { major: entry.major, minVersion: entry.minVersion },
      );
    }
    if (entry.mode === "exact" && entry.verifiedCeiling !== entry.minVersion) {
      return semanticFailure(
        "exact 模式下的 verifiedCeiling 必须等于 minVersion",
        `${basePath}/verifiedCeiling`,
        { minVersion: entry.minVersion, verifiedCeiling: entry.verifiedCeiling },
      );
    }
    if (entry.verifiedCeiling !== null) {
      const ceilingParsed = parseExactSemver(entry.verifiedCeiling);
      if (!ceilingParsed || ceilingParsed.major !== entry.major) {
        return semanticFailure(
          `verifiedCeiling "${entry.verifiedCeiling}" 的主版本号必须等于 major (${entry.major})`,
          `${basePath}/verifiedCeiling`,
          { major: entry.major, verifiedCeiling: entry.verifiedCeiling },
        );
      }
      if (compareExactSemver(entry.verifiedCeiling, entry.minVersion) < 0) {
        return semanticFailure(
          `verifiedCeiling "${entry.verifiedCeiling}" 不得低于 minVersion "${entry.minVersion}"`,
          `${basePath}/verifiedCeiling`,
          { minVersion: entry.minVersion, verifiedCeiling: entry.verifiedCeiling },
        );
      }
    }
    if (entry.status === "resolved") {
      const selectedParsed = parseExactSemver(entry.selectedVersion);
      if (!selectedParsed || selectedParsed.major !== entry.major) {
        return semanticFailure(
          `selectedVersion "${entry.selectedVersion}" 的主版本号必须等于 major (${entry.major})`,
          `${basePath}/selectedVersion`,
          { major: entry.major, selectedVersion: entry.selectedVersion },
        );
      }
      if (compareExactSemver(entry.selectedVersion, entry.minVersion) < 0) {
        return semanticFailure(
          `selectedVersion "${entry.selectedVersion}" 不得低于 minVersion "${entry.minVersion}"`,
          `${basePath}/selectedVersion`,
          { minVersion: entry.minVersion, selectedVersion: entry.selectedVersion },
        );
      }
      if (
        entry.verifiedCeiling !== null
        && compareExactSemver(entry.selectedVersion, entry.verifiedCeiling) > 0
      ) {
        return semanticFailure(
          `selectedVersion "${entry.selectedVersion}" 不得高于 verifiedCeiling "${entry.verifiedCeiling}"`,
          `${basePath}/selectedVersion`,
          { verifiedCeiling: entry.verifiedCeiling, selectedVersion: entry.selectedVersion },
        );
      }
    }
  }

  const expectedOverall = resolutions.every((item) => item.status === "resolved")
    ? "resolved"
    : "unresolved";
  if (overallStatus !== expectedOverall) {
    return semanticFailure(
      `收据顶层 status "${overallStatus}" 与逐项选版结果推导出的 "${expectedOverall}" 不一致`,
      "/status",
      { expected: expectedOverall, received: overallStatus },
    );
  }
  return null;
}

/**
 * 校验会话级内部依赖选版收据（包含 JSON Schema 结构校验、主版本与上下界不变量及自绑定 SHA-256 摘要校验）。
 */
export function validateInternalDependencyResolutionReceipt(receipt) {
  const preflight = preflightJsonData(receipt, "", {
    keyword: "internalDependencyReceipt",
    schemaId: INTERNAL_DEPENDENCY_RECEIPT_SCHEMA_ID,
    label: "internal dependency resolution receipt",
  });
  if (!preflight.valid) return preflight;
  const result = validateDocument(preflight.data, {
    schemaId: INTERNAL_DEPENDENCY_RECEIPT_SCHEMA_ID,
    dialect: "2020-12",
    policy: "strict",
  });
  if (!result.valid) return result;
  const semanticError = validateResolutionEntries(result.data.resolutions, result.data.status);
  if (semanticError) return semanticError;
  const { digest, ...withoutDigest } = result.data;
  const expectedDigest = digestDocument(withoutDigest);
  if (digest !== expectedDigest) {
    return semanticFailure(
      "digest 必须等于剔除 digest 字段后整份收据规范化 JSON 的 SHA-256 摘要",
      "/digest",
      { expected: expectedDigest, received: digest },
    );
  }
  return {
    ...result,
    data: deepFreeze(result.data),
  };
}

/**
 * 构造确定性的会话级内部依赖选版收据并自动计算自绑定 SHA-256 摘要。
 */
export function describeInternalDependencyResolutionReceipt(options) {
  const preflight = preflightJsonData(options, "", {
    keyword: "internalDependencyReceipt",
    schemaId: INTERNAL_DEPENDENCY_RECEIPT_SCHEMA_ID,
    label: "internal dependency resolution receipt options",
  });
  if (!preflight.valid) {
    throw new ContractsError(
      preflight.errorCode ?? "SFC1001",
      `describeInternalDependencyResolutionReceipt: 输入无效：${preflight.errors[0]?.message ?? "校验失败"}`,
      { errors: preflight.errors },
    );
  }
  const safe = preflight.data;
  if (!safe || typeof safe !== "object" || Array.isArray(safe)) {
    throw new TypeError("describeInternalDependencyResolutionReceipt: options 必须是对象");
  }
  for (const key of ["projectId", "resolvedAt", "manifestDigest", "resolutions"]) {
    if (safe[key] === undefined) {
      throw new TypeError(`describeInternalDependencyResolutionReceipt: 缺少必填参数 "${key}"`);
    }
  }
  if (!Array.isArray(safe.resolutions)) {
    throw new TypeError("describeInternalDependencyResolutionReceipt: resolutions 必须是数组");
  }
  const sortedResolutions = [...safe.resolutions]
    .map((entry) => ({
      ...structuredClone(entry),
      candidatesEvaluated: Array.isArray(entry?.candidatesEvaluated)
        ? [...entry.candidatesEvaluated].sort(compareExactSemver)
        : entry?.candidatesEvaluated,
    }))
    .sort((left, right) => compareLexical(String(left?.packageName ?? ""), String(right?.packageName ?? "")));

  const status = sortedResolutions.every((item) => item?.status === "resolved")
    ? "resolved"
    : "unresolved";
  const withoutDigest = {
    schemaVersion: 1,
    kind: INTERNAL_DEPENDENCY_RECEIPT_KIND,
    projectId: safe.projectId,
    policy: INTERNAL_DEPENDENCY_POLICY_ID,
    status,
    ...(safe.sessionId !== undefined ? { sessionId: safe.sessionId } : {}),
    resolvedAt: safe.resolvedAt,
    manifestDigest: safe.manifestDigest,
    resolutions: sortedResolutions,
  };
  const candidate = {
    ...withoutDigest,
    digest: digestDocument(withoutDigest),
  };
  const checked = validateInternalDependencyResolutionReceipt(candidate);
  if (!checked.valid) {
    throw new ContractsError(
      checked.errorCode ?? "SFC1001",
      `describeInternalDependencyResolutionReceipt: 生成的收据未通过校验：${checked.errors[0]?.message ?? "校验失败"}`,
      { errors: checked.errors },
    );
  }
  return checked.data;
}
