#!/usr/bin/env node
/**
 * Thin professional-proof consumption adapter.
 *
 * Applies the approved skill-family version policy with semver.valid/compare
 * only. Baseline, proof identity and reader_status must already be derived
 * from a locatable proof and the product manifest. Does not scan targets,
 * does not execute commands from proofs, and does not invent a second proof
 * contract or generic executor.
 */
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const INPUT_KEYS = new Set([
  "action",
  "applicable",
  "baseline_version",
  "entry_available",
  "entry_ref",
  "identity_matched",
  "proof_present",
  "proof_version",
  "provider_id",
  "reader_status",
  "selected",
]);
const ACTIONS = new Set(["none", "refresh", "reuse", "scan"]);
const READER_STATUSES = new Set(["not_pass", "pass", "unavailable"]);

function resolveSemver() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const require = createRequire(import.meta.url);
  const vendor = path.resolve(here, "../vendor/semver");
  try {
    return require(vendor);
  } catch (error) {
    throw new Error(
      `SEMVER_MODULE_UNAVAILABLE:${vendor}:${error instanceof Error ? error.message : error}`,
    );
  }
}

const semver = resolveSemver();

function fail(code, detail) {
  const error = new Error(`${code}:${detail}`);
  error.code = code;
  throw error;
}

function rejectCommands(value, label) {
  if (value === null || value === undefined) {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectCommands(item, `${label}[${index}]`));
    return;
  }
  if (typeof value === "object") {
    if (Object.prototype.hasOwnProperty.call(value, "command")) {
      fail("PROFESSIONAL_PROOF_COMMAND_REJECTED", label);
    }
    for (const [key, child] of Object.entries(value)) {
      rejectCommands(child, `${label}.${key}`);
    }
  }
}

function requireString(value, label) {
  if (typeof value !== "string" || !value) {
    fail("PROFESSIONAL_PROOF_INPUT_INVALID", label);
  }
  return value;
}

function optionalString(value, label) {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== "string" || !value) {
    fail("PROFESSIONAL_PROOF_INPUT_INVALID", label);
  }
  return value;
}

function requireBoolean(value, label) {
  if (typeof value !== "boolean") {
    fail("PROFESSIONAL_PROOF_INPUT_INVALID", label);
  }
  return value;
}

function result(fields) {
  return {
    baseline_version: fields.baseline_version ?? null,
    does_not_certify_author: fields.does_not_certify_author === true,
    does_not_mean_rescan: fields.does_not_mean_rescan === true,
    entry_ref: fields.entry_ref ?? "",
    mode: fields.mode,
    proof_version: fields.proof_version ?? null,
    provider_id: fields.provider_id,
    reader_status: fields.reader_status ?? null,
    reason: fields.reason,
    refresh_suggested: fields.refresh_suggested === true,
    status: fields.status,
    version_relation: fields.version_relation ?? "absent",
  };
}

function recordMode(action) {
  if (action === "scan" || action === "refresh") {
    return "scanned";
  }
  return "reused_proof";
}

export function consumeProfessionalProof(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    fail("PROFESSIONAL_PROOF_INPUT_INVALID", "root");
  }
  rejectCommands(input, "input");
  const unknown = Object.keys(input).filter((key) => !INPUT_KEYS.has(key));
  if (unknown.length) {
    fail("PROFESSIONAL_PROOF_UNKNOWN_FIELD", unknown.sort().join(","));
  }
  const providerId = requireString(input.provider_id, "provider_id");
  const baselineVersion = requireString(input.baseline_version, "baseline_version");
  const selected = requireBoolean(input.selected, "selected");
  const applicable = requireBoolean(input.applicable, "applicable");
  const entryAvailable = requireBoolean(input.entry_available, "entry_available");
  const proofPresent = requireBoolean(input.proof_present, "proof_present");
  const identityMatched = requireBoolean(input.identity_matched, "identity_matched");
  const action = requireString(input.action, "action");
  if (!ACTIONS.has(action)) {
    fail("PROFESSIONAL_PROOF_INPUT_INVALID", "action");
  }
  const entryRef = optionalString(input.entry_ref, "entry_ref") ?? "";
  const proofVersion = optionalString(input.proof_version, "proof_version");
  const readerStatus = optionalString(input.reader_status, "reader_status");
  if (readerStatus !== null && !READER_STATUSES.has(readerStatus)) {
    fail("PROFESSIONAL_PROOF_INPUT_INVALID", "reader_status");
  }
  if (proofPresent && proofVersion === null) {
    fail("PROFESSIONAL_PROOF_INPUT_INVALID", "proof_version");
  }

  if (!proofPresent) {
    if (!selected && !applicable) {
      return result({
        baseline_version: baselineVersion,
        entry_ref: entryRef,
        mode: "not_selected",
        provider_id: providerId,
        reason: "未选且不适用；不把未选当成失败，docs 不强制建站。",
        status: "pass",
        version_relation: "absent",
      });
    }
    if (selected && !entryAvailable) {
      return result({
        baseline_version: baselineVersion,
        entry_ref: entryRef,
        mode: "missing_entry",
        provider_id: providerId,
        reason: "所选公开入口当前不可用；记为缺证，不虚构可调用命令。",
        status: "not_pass",
      });
    }
    return result({
      baseline_version: baselineVersion,
      entry_ref: entryRef,
      mode: "missing_proof",
      provider_id: providerId,
      reason: "适用但没有可定位的专业证明；记为缺证，不阻断无关检查。",
      status: "not_pass",
    });
  }

  if (!identityMatched) {
    return result({
      baseline_version: baselineVersion,
      entry_ref: entryRef,
      mode: "missing_proof",
      proof_version: proofVersion,
      provider_id: providerId,
      reason: "可定位证明的提供方身份与所选专业族不符；跨族证明不能按版本政策通过。",
      status: "not_pass",
      version_relation: "absent",
    });
  }

  if (semver.valid(proofVersion) === null || semver.valid(baselineVersion) === null) {
    return result({
      baseline_version: baselineVersion,
      entry_ref: entryRef,
      mode: "version_policy",
      proof_version: proofVersion,
      provider_id: providerId,
      reason: "出具版本或产品基准不是严格 SemVer，不能比较高低；建议专业方刷新证明。",
      refresh_suggested: true,
      status: "not_pass",
      version_relation: "invalid",
    });
  }

  const compared = semver.compare(proofVersion, baselineVersion);
  if (compared > 0) {
    return result({
      baseline_version: baselineVersion,
      does_not_certify_author: true,
      does_not_mean_rescan: true,
      entry_ref: entryRef,
      mode: "version_policy",
      proof_version: proofVersion,
      provider_id: providerId,
      reason: "出具技能族版本高于产品基准，按批准政策通过；不表示来源获认证，也不表示本次重扫。",
      status: "pass",
      version_relation: "higher",
    });
  }
  if (compared < 0) {
    return result({
      baseline_version: baselineVersion,
      entry_ref: entryRef,
      mode: "version_policy",
      proof_version: proofVersion,
      provider_id: providerId,
      reason: "出具技能族版本低于产品基准，未通过；建议使用更新版本刷新证明，不强制升级。",
      refresh_suggested: true,
      status: "not_pass",
      version_relation: "lower",
    });
  }

  const mode = recordMode(action);
  if (readerStatus === null || readerStatus === "unavailable") {
    return result({
      baseline_version: baselineVersion,
      entry_ref: entryRef,
      mode,
      proof_version: proofVersion,
      provider_id: providerId,
      reader_status: readerStatus ?? "unavailable",
      reason: "同版本须消费专业方 reader 的实际结果；当前无法读取或解释。",
      status: "not_pass",
      version_relation: "same",
    });
  }
  if (readerStatus === "pass") {
    return result({
      baseline_version: baselineVersion,
      entry_ref: entryRef,
      mode,
      proof_version: proofVersion,
      provider_id: providerId,
      reader_status: readerStatus,
      reason: "同版本消费专业方 reader 结果：pass。",
      status: "pass",
      version_relation: "same",
    });
  }
  return result({
    baseline_version: baselineVersion,
    entry_ref: entryRef,
    mode,
    proof_version: proofVersion,
    provider_id: providerId,
    reader_status: readerStatus,
    reason: "同版本消费专业方 reader 结果：not_pass。",
    status: "not_pass",
    version_relation: "same",
  });
}

function isMain() {
  const entry = process.argv[1];
  return Boolean(entry) && import.meta.url === pathToFileURL(path.resolve(entry)).href;
}

if (isMain()) {
  const raw = fs.readFileSync(0, "utf8");
  let document;
  try {
    document = JSON.parse(raw);
  } catch (error) {
    process.stderr.write(`PROFESSIONAL_PROOF_INPUT_INVALID:${error instanceof Error ? error.message : error}\n`);
    process.exit(2);
  }
  try {
    process.stdout.write(`${JSON.stringify(consumeProfessionalProof(document))}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
    process.exit(2);
  }
}
