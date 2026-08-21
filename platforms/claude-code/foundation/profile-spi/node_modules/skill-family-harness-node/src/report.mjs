import { readFileSync } from "node:fs";
import {
  canonicalJson,
  digestDocument,
  findSchemaByObject,
  isRegisteredErrorCode,
} from "skill-family-contracts";
import { digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { validateContractDocument } from "./validation.mjs";

/**
 * Deterministic report mechanism (FND-ADR-005 / FND-DES-004).
 *
 * The caller owns every report fact and submits a registered report-model.
 * Harness only validates that model, verifies its source binding, renders
 * neutral Markdown, and checks the rendered bytes. It never interprets an
 * operation's outputs, derives an execution status, or fills missing facts.
 */

const PACKAGE_META = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const REPORT_RENDERER_NAME = "skill-family-harness-node/report";
export const REPORT_RENDERER_VERSION = PACKAGE_META.version;
export const SUPPORTED_REPORT_LOCALES = Object.freeze(["zh-CN", "en-US"]);
export const EXECUTION_STATUSES = Object.freeze([
  "SUCCEEDED",
  "SUCCEEDED_WITH_WARNINGS",
  "FAILED",
  "BLOCKED",
  "NEEDS_INPUT",
  "SKIPPED",
  "CANCELLED",
]);
export const REPORT_AUDIENCES = Object.freeze(["operator", "reviewer", "consumer"]);
export const RESULT_STATE_EXECUTION_STATUSES = Object.freeze({
  succeeded: Object.freeze(["SUCCEEDED", "SUCCEEDED_WITH_WARNINGS"]),
  failed: Object.freeze(["FAILED"]),
  rejected: Object.freeze(["BLOCKED", "NEEDS_INPUT", "SKIPPED", "CANCELLED"]),
});
export const REPORT_STYLE_RULES = Object.freeze([
  "sentence-too-long",
  "duplicate-paragraph",
  "translationese",
  "unexplained-term",
]);

const SENTENCE_MAX_CHARS = 80;
const TRANSLATESE_ZH = Object.freeze([
  "进行一个",
  "的一个情况",
  "被完成",
  "值得注意的是",
  "就我们而言",
]);
const TRANSLATESE_EN = Object.freeze([
  "in order to",
  "it is important to note",
  "leverage",
  "utilize",
]);
const UNEXPLAINED_TERMS = Object.freeze(["SPI", "DSL", "SDK"]);

const REPORT_MODEL_SCHEMA_ID = findSchemaByObject("report-model").$id;
const REPORT_BINDING_SCHEMA_ID = findSchemaByObject("report-binding").$id;
const OPERATION_RESULT_SCHEMA_ID = findSchemaByObject("operation-result").$id;

const TEXT = Object.freeze({
  "zh-CN": {
    title: "运行报告",
    audience: "读者",
    stage: "阶段",
    locale: "语言",
    timeRange: "时间范围",
    status: "执行状态",
    source: "机器结果摘要（sha256）",
    sourceKind: "机器结果类型",
    renderer: "渲染器",
    blocking: "阻塞原因",
    reference: "引用",
    note: "备注",
    errorPath: "位置",
    errorDetails: "详情",
    sections: {
      conclusion: "结论",
      errors: "错误",
      changes: "变更",
      evidence: "证据",
      risks: "风险",
      unresolved: "未决问题",
      nextActions: "后续行动",
      appendices: "附录",
    },
    empty: {
      errors: "（机器结果未申报错误。）",
      changes: "（本次运行无申报变更。）",
      risks: "（本次运行未申报风险。）",
      unresolved: "（本次运行无未决问题。）",
      nextActions: "（本次运行无后续行动。）",
      appendices: "（本次运行无附录。）",
    },
  },
  "en-US": {
    title: "Run Report",
    audience: "Audience",
    stage: "Stage",
    locale: "Locale",
    timeRange: "Time range",
    status: "Execution status",
    source: "Machine result digest (sha256)",
    sourceKind: "Machine result kind",
    renderer: "Renderer",
    blocking: "Blocking reason",
    reference: "ref",
    note: "note",
    errorPath: "path",
    errorDetails: "details",
    sections: {
      conclusion: "Conclusion",
      errors: "Errors",
      changes: "Changes",
      evidence: "Evidence",
      risks: "Risks",
      unresolved: "Unresolved",
      nextActions: "Next Actions",
      appendices: "Appendices",
    },
    empty: {
      errors: "(The machine result declared no errors.)",
      changes: "(No declared changes for this run.)",
      risks: "(No declared risks for this run.)",
      unresolved: "(No unresolved questions for this run.)",
      nextActions: "(No follow-up actions for this run.)",
      appendices: "(No appendices for this run.)",
    },
  },
});

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hardFailure(code, message, details) {
  return { code, message, details };
}

/**
 * Converts untrusted prose to one Markdown text line. Newlines become visible
 * escape sequences and every ASCII punctuation character is backslash-escaped,
 * so headings, links, HTML, lists, block quotes and code spans remain literal.
 */
function literalMarkdown(value) {
  return String(value)
    .replace(/\\/g, "\\\\")
    .replace(/\r\n|\r|\n/g, "\\n")
    .replace(/[\u0000-\u001f\u007f]/g, (character) =>
      `\\u${character.codePointAt(0).toString(16).padStart(4, "0")}`)
    .replace(/([!"#$%&'()*+,\-./:;<=>?@[\]^_`{|}~])/g, "\\$1");
}

function countFailures(model) {
  const expected = {
    changes: model.changes.length,
    evidence: model.evidence.length,
    risks: model.risks.length,
    unresolved: model.unresolved.length,
    nextActions: model.nextActions.length,
    appendices: model.appendices.length,
  };
  const failures = [];
  for (const [field, count] of Object.entries(expected)) {
    if (model.outcome.counts[field] !== count) {
      failures.push(hardFailure(
        "SFC3003",
        `report model count mismatch: ${field}`,
        { field: `outcome.counts.${field}`, expected: count, observed: model.outcome.counts[field] },
      ));
    }
  }
  return failures;
}

/**
 * Validates one caller-authored report model. If resultDocument is supplied,
 * source digest and the complete coded-error array must match it exactly.
 */
export function validateReportModel(reportModel, { resultDocument } = {}) {
  const hardFailures = [];
  if (!isPlainObject(reportModel)) {
    return {
      ok: false,
      hardFailures: [hardFailure("SFC3002", "missing or invalid report model", { element: "report-model" })],
    };
  }

  const modelValidation = validateContractDocument(reportModel, {
    schemaId: REPORT_MODEL_SCHEMA_ID,
    policy: "strict",
  });
  if (!modelValidation.valid) {
    return {
      ok: false,
      hardFailures: [hardFailure(
        "SFC3002",
        "report model fails its registered contract",
        { element: "report-model", validationErrors: modelValidation.errors },
      )],
    };
  }

  if (
    reportModel.renderer.name !== REPORT_RENDERER_NAME ||
    reportModel.renderer.version !== REPORT_RENDERER_VERSION
  ) {
    hardFailures.push(hardFailure(
      "SFC3003",
      "report model names a different renderer",
      {
        field: "renderer",
        expected: { name: REPORT_RENDERER_NAME, version: REPORT_RENDERER_VERSION },
        observed: reportModel.renderer,
      },
    ));
  }
  hardFailures.push(...countFailures(reportModel));
  for (const [index, entry] of reportModel.errors.entries()) {
    if (!isRegisteredErrorCode(entry.code)) {
      hardFailures.push(hardFailure(
        "SFC3002",
        "report model contains an unregistered machine error code",
        { element: "registered-error-code", index, code: entry.code },
      ));
    }
  }

  if (resultDocument !== undefined) {
    const resultValidation = validateContractDocument(resultDocument, {
      schemaId: OPERATION_RESULT_SCHEMA_ID,
      policy: "strict",
    });
    if (!resultValidation.valid || !resultDocument.errors.every((entry) => isRegisteredErrorCode(entry.code))) {
      hardFailures.push(hardFailure(
        "SFC3002",
        "source machine result is invalid or contains an unregistered error code",
        { element: "machine-result", validationErrors: resultValidation.errors },
      ));
    } else {
      const expectedDigest = computeResultDigest(resultDocument);
      if (reportModel.source.resultDigest !== expectedDigest) {
        hardFailures.push(hardFailure(
          "SFC3001",
          "report model source digest does not match the machine result",
          { field: "source.resultDigest", expected: expectedDigest, observed: reportModel.source.resultDigest },
        ));
      }
      if (reportModel.source.resultState !== resultDocument.state) {
        hardFailures.push(hardFailure(
          "SFC3003",
          "report model source state does not match the machine result",
          { field: "source.resultState", expected: resultDocument.state, observed: reportModel.source.resultState },
        ));
      }
      const allowedStatuses = RESULT_STATE_EXECUTION_STATUSES[resultDocument.state] ?? [];
      if (!allowedStatuses.includes(reportModel.outcome.executionStatus)) {
        hardFailures.push(hardFailure(
          "SFC3003",
          "report execution status is incompatible with the machine result state",
          {
            field: "outcome.executionStatus",
            resultState: resultDocument.state,
            expected: allowedStatuses,
            observed: reportModel.outcome.executionStatus,
          },
        ));
      }
      if (canonicalJson(reportModel.errors) !== canonicalJson(resultDocument.errors)) {
        hardFailures.push(hardFailure(
          "SFC3003",
          "report model errors do not losslessly match machine result errors",
          { field: "errors", expected: resultDocument.errors, observed: reportModel.errors },
        ));
      }
    }
  }

  return { ok: hardFailures.length === 0, hardFailures };
}

/** Deterministically renders a validated model; it never reads other state. */
export function renderReportMarkdown(model) {
  const validation = validateReportModel(model);
  if (!validation.ok) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      "report model is not renderable",
      { hardFailures: validation.hardFailures },
    );
  }
  const text = TEXT[model.identity.locale];
  const lines = [];
  lines.push(`# ${text.title}: ${literalMarkdown(model.identity.skillFamily)} / ${literalMarkdown(model.identity.runId)}`);
  lines.push("");
  lines.push(`- ${text.audience}: ${literalMarkdown(model.identity.audience)}`);
  if (typeof model.identity.stageId === "string") {
    lines.push(`- ${text.stage}: ${literalMarkdown(model.identity.stageId)}`);
  }
  lines.push(`- ${text.locale}: ${literalMarkdown(model.identity.locale)}`);
  lines.push(`- ${text.timeRange}: ${literalMarkdown(model.timeRange.startedAt)} — ${literalMarkdown(model.timeRange.completedAt)}`);
  lines.push(`- ${text.status}: ${literalMarkdown(model.outcome.executionStatus)}`);
  lines.push(`- ${text.source}: ${literalMarkdown(model.source.resultDigest)}`);
  if (typeof model.source.resultKind === "string") {
    lines.push(`- ${text.sourceKind}: ${literalMarkdown(model.source.resultKind)}`);
  }
  lines.push(`- ${text.renderer}: ${literalMarkdown(model.renderer.name)}@${literalMarkdown(model.renderer.version)}`);
  lines.push("");

  lines.push(`## ${text.sections.conclusion}`, "", literalMarkdown(model.outcome.summary));
  if (typeof model.outcome.blockingReason === "string" && model.outcome.blockingReason.length > 0) {
    lines.push("", `> ${text.blocking}: ${literalMarkdown(model.outcome.blockingReason)}`);
  }
  lines.push("");

  lines.push(`## ${text.sections.errors}`, "");
  if (model.errors.length === 0) {
    lines.push(text.empty.errors);
  } else {
    for (const error of model.errors) {
      lines.push(`- ${literalMarkdown(error.code)}: ${literalMarkdown(error.message)}`);
      if (typeof error.path === "string") {
        lines.push(`  - ${text.errorPath}: ${literalMarkdown(error.path)}`);
      }
      if (error.details !== undefined) {
        lines.push(`  - ${text.errorDetails}: ${literalMarkdown(canonicalJson(error.details))}`);
      }
    }
  }
  lines.push("");

  lines.push(`## ${text.sections.changes}`, "");
  if (model.changes.length === 0) lines.push(text.empty.changes);
  for (const change of model.changes) {
    lines.push(`- ${literalMarkdown(change.path)}: ${literalMarkdown(change.description)}`);
  }
  lines.push("");

  lines.push(`## ${text.sections.evidence}`, "");
  for (const entry of model.evidence) {
    lines.push(`- ${literalMarkdown(entry.id)}: ${literalMarkdown(entry.title)}`);
    lines.push(`  - ${text.reference}: ${literalMarkdown(entry.reference)}`);
    if (typeof entry.note === "string" && entry.note.length > 0) {
      lines.push(`  - ${text.note}: ${literalMarkdown(entry.note)}`);
    }
  }
  lines.push("");

  for (const [field, section] of [
    ["risks", "risks"],
    ["unresolved", "unresolved"],
    ["nextActions", "nextActions"],
  ]) {
    lines.push(`## ${text.sections[section]}`, "");
    if (model[field].length === 0) lines.push(text.empty[field]);
    for (const item of model[field]) lines.push(`- ${literalMarkdown(item)}`);
    lines.push("");
  }

  lines.push(`## ${text.sections.appendices}`, "");
  if (model.appendices.length === 0) {
    lines.push(text.empty.appendices);
  } else {
    model.appendices.forEach((appendix, index) => {
      if (index > 0) lines.push("");
      lines.push(`### ${literalMarkdown(appendix.title)}`, "", literalMarkdown(appendix.body));
    });
  }
  return `${lines.join("\n")}\n`;
}

export function computeResultDigest(resultDocument) {
  return digestDocument(resultDocument);
}

export function computeModelDigest(reportModel) {
  return digestDocument(reportModel);
}

export function digestReport(reportMarkdown) {
  if (typeof reportMarkdown !== "string") {
    throw new TypeError("digestReport: reportMarkdown must be a string");
  }
  return digestBytes(Buffer.from(reportMarkdown, "utf8"));
}

/** Builds a binding only after model/result consistency has been proved. */
export function buildBinding(reportModel, resultDocument, reportMarkdown) {
  const validation = validateReportModel(reportModel, { resultDocument });
  if (!validation.ok) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      "report model does not match its source result",
      { hardFailures: validation.hardFailures },
    );
  }
  const canonical = renderReportMarkdown(reportModel);
  if (canonical !== reportMarkdown) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      "report Markdown is not the canonical render of its model",
      {
        hardFailures: [hardFailure(
          "SFC3003",
          "report bytes diverge from the deterministic render of the submitted report model",
          { expectedDigest: digestReport(canonical), observedDigest: digestReport(reportMarkdown) },
        )],
      },
    );
  }
  return {
    schemaVersion: 1,
    kind: "skill-family.report-binding",
    runId: reportModel.identity.runId,
    modelDigest: computeModelDigest(reportModel),
    resultDigest: computeResultDigest(resultDocument),
    reportDigest: digestReport(reportMarkdown),
    rendererVersion: REPORT_RENDERER_VERSION,
  };
}

export function verifyBinding(binding, { reportModel, resultDocument, reportMarkdown } = {}) {
  const mismatches = [];
  if (!isPlainObject(binding)) {
    return {
      ok: false,
      code: "SFC3001",
      mismatches: [{ field: "binding", expected: "skill-family.report-binding object", observed: typeof binding }],
    };
  }
  const contract = validateContractDocument(binding, {
    schemaId: REPORT_BINDING_SCHEMA_ID,
    policy: "strict",
  });
  if (!contract.valid) {
    return {
      ok: false,
      code: "SFC3001",
      mismatches: [{ field: "binding-schema", expected: "valid report-binding", observed: contract.errors }],
    };
  }
  if (!isPlainObject(reportModel)) {
    mismatches.push({ field: "reportModel", expected: "skill-family.report-model object", observed: typeof reportModel });
  }
  if (!isPlainObject(resultDocument)) {
    mismatches.push({ field: "resultDocument", expected: "skill-family.operation-result object", observed: typeof resultDocument });
  }
  if (typeof reportMarkdown !== "string") {
    mismatches.push({ field: "reportMarkdown", expected: "canonical Markdown string", observed: typeof reportMarkdown });
  }
  const modelValidation = isPlainObject(reportModel) && isPlainObject(resultDocument)
    ? validateReportModel(reportModel, { resultDocument })
    : { ok: false, hardFailures: [] };
  if (!modelValidation.ok && isPlainObject(reportModel) && isPlainObject(resultDocument)) {
    mismatches.push({ field: "reportModel", expected: "model bound to supplied result", observed: modelValidation.hardFailures });
  }
  if (isPlainObject(reportModel)) {
    const expected = computeModelDigest(reportModel);
    if (binding.modelDigest !== expected) {
      mismatches.push({ field: "modelDigest", expected, observed: binding.modelDigest });
    }
    if (binding.runId !== reportModel.identity?.runId) {
      mismatches.push({ field: "runId", expected: reportModel.identity?.runId, observed: binding.runId });
    }
  }
  if (resultDocument !== undefined) {
    const expected = computeResultDigest(resultDocument);
    if (binding.resultDigest !== expected) {
      mismatches.push({ field: "resultDigest", expected, observed: binding.resultDigest });
    }
  }
  if (typeof reportMarkdown === "string") {
    const expected = digestReport(reportMarkdown);
    if (binding.reportDigest !== expected) {
      mismatches.push({ field: "reportDigest", expected, observed: binding.reportDigest });
    }
  }
  if (binding.rendererVersion !== REPORT_RENDERER_VERSION) {
    mismatches.push({
      field: "rendererVersion",
      expected: REPORT_RENDERER_VERSION,
      observed: binding.rendererVersion,
    });
  }
  if (modelValidation.ok && typeof reportMarkdown === "string") {
    const canonical = renderReportMarkdown(reportModel);
    if (canonical !== reportMarkdown) {
      mismatches.push({
        field: "canonicalReport",
        expected: digestReport(canonical),
        observed: digestReport(reportMarkdown),
      });
    }
  }
  return mismatches.length === 0
    ? { ok: true, code: null, mismatches: [] }
    : { ok: false, code: "SFC3001", mismatches };
}

/** Graded check: contract/digest/fact failures block; style remains advisory. */
export function checkReport({ reportMarkdown, reportModel, resultDocument, binding } = {}) {
  if (typeof reportMarkdown !== "string") {
    throw new TypeError("checkReport: reportMarkdown must be a string");
  }
  const validated = validateReportModel(reportModel, { resultDocument });
  const hardFailures = [...validated.hardFailures];
  if (validated.ok) {
    if (binding === undefined) {
      hardFailures.push(hardFailure(
        "SFC3002",
        "missing report element: binding",
        { element: "binding" },
      ));
    } else {
      const verification = verifyBinding(binding, {
        reportModel,
        resultDocument,
        reportMarkdown,
      });
      for (const mismatch of verification.mismatches) {
        hardFailures.push(hardFailure(
          "SFC3001",
          `report binding mismatch: ${mismatch.field}`,
          mismatch,
        ));
      }
    }
    const canonical = renderReportMarkdown(reportModel);
    if (canonical !== reportMarkdown) {
      hardFailures.push(hardFailure(
        "SFC3003",
        "report bytes diverge from the deterministic render of the submitted report model",
        { expectedDigest: digestReport(canonical), observedDigest: digestReport(reportMarkdown) },
      ));
    }
  }
  return {
    ok: hardFailures.length === 0,
    hardFailures,
    styleWarnings: collectStyleWarnings(reportMarkdown),
  };
}

/** Frozen deterministic style rules; advisory only, never blocking. */
export function collectStyleWarnings(reportMarkdown) {
  if (typeof reportMarkdown !== "string") {
    throw new TypeError("collectStyleWarnings: reportMarkdown must be a string");
  }
  const lines = reportMarkdown.split("\n");
  const warnings = [];
  const seen = new Set();
  const record = (rule, line, message) => {
    const key = `${rule}|${line}|${message}`;
    if (seen.has(key)) return;
    seen.add(key);
    warnings.push({ rule, line, message });
  };

  lines.forEach((raw, index) => {
    for (const sentence of raw.split(/(?<=[。！？!?；;])/)) {
      const trimmed = sentence.trim();
      if (trimmed.length > SENTENCE_MAX_CHARS) {
        record("sentence-too-long", index + 1, `sentence exceeds ${SENTENCE_MAX_CHARS} characters (${trimmed.length})`);
      }
    }
  });

  const lineCounts = new Map();
  lines.forEach((raw, index) => {
    const trimmed = raw.trim();
    if (trimmed.length === 0) return;
    const entry = lineCounts.get(trimmed) ?? { count: 0, first: index + 1 };
    entry.count += 1;
    lineCounts.set(trimmed, entry);
  });
  for (const [content, entry] of lineCounts) {
    if (entry.count > 1) {
      record("duplicate-paragraph", entry.first, `line repeats ${entry.count} times: ${truncate(content)}`);
    }
  }

  lines.forEach((raw, index) => {
    for (const phrase of TRANSLATESE_ZH) {
      if (raw.includes(phrase)) record("translationese", index + 1, `translationese phrase: ${phrase}`);
    }
    const lowered = raw.toLowerCase();
    for (const phrase of TRANSLATESE_EN) {
      if (lowered.includes(phrase)) record("translationese", index + 1, `translationese phrase: ${phrase}`);
    }
  });

  for (const term of UNEXPLAINED_TERMS) {
    let usedAt = null;
    let explained = false;
    lines.forEach((raw, index) => {
      if (raw.includes(term)) {
        if (usedAt === null) usedAt = index + 1;
        if (raw.includes(`${term}：`) || raw.includes(`${term}:`)) explained = true;
      }
    });
    if (usedAt !== null && !explained) {
      record("unexplained-term", usedAt, `term used without inline explanation: ${term}`);
    }
  }
  warnings.sort((a, b) => a.line - b.line || a.rule.localeCompare(b.rule) || a.message.localeCompare(b.message));
  return warnings;
}

function truncate(content) {
  return content.length <= 40 ? content : `${content.slice(0, 40)}…`;
}
