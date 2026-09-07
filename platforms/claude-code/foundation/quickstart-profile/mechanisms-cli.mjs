#!/usr/bin/env node
import { stdin, stdout, stderr } from "node:process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  invokeFoundationMechanism,
  verifyManagedBundleIdentity,
} from "./runner.mjs";

const CLI_NAME = "mechanisms-cli.mjs";

async function readRequest(input) {
  const chunks = [];
  for await (const chunk of input) chunks.push(Buffer.from(chunk));
  const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  return JSON.parse(text);
}

function errorResponse(cause) {
  return {
    ok: false,
    error: {
      name: typeof cause?.name === "string" ? cause.name : "Error",
      message: cause?.message ?? String(cause),
      ...(typeof cause?.code === "string" ? { code: cause.code } : {}),
      ...(cause?.details !== undefined ? { details: cause.details } : {}),
    },
  };
}

/**
 * Fixed dispatch for the publish-fixed-set operation.
 *
 * This operation is fail-closed: if the native addon is unavailable or the
 * platform is unsupported, the operation returns a receipt with status=refused
 * and error code UNSUPPORTED_PLATFORM. No JS rename fallback is attempted.
 *
 * The operation takes a frozen sibling-directory source/target tuple and
 * returns a receipt. It does NOT
 * expose any module/function/pathToFileURL call surface.
 */
async function runPublishFixedSet(params, invoke) {
  if (
    params === null ||
    typeof params !== "object" ||
    Array.isArray(params) ||
    Object.keys(params).sort().join(",") !== "manifest,sourceRoot,targetParent,targetSegment" ||
    typeof params.sourceRoot !== "string" ||
    typeof params.targetParent !== "string" ||
    typeof params.targetSegment !== "string" ||
    params.manifest === null ||
    typeof params.manifest !== "object"
  ) {
    throw new TypeError("publish-fixed-set requires exactly sourceRoot, targetParent, targetSegment, and manifest");
  }

  let publishFixedSet;
  try {
    const mod = await import("./rename-directory-no-replace/rename-directory-no-replace.mjs");
    publishFixedSet = mod.publishFixedSet;
  } catch (cause) {
    const manifestDigest = await invoke({ operation: "digest-document", params: { document: params.manifest } });
    return {
      schemaVersion: 1,
      kind: "skill-family.fixed-set-publication-receipt",
      manifestDigest: manifestDigest.digest,
      targetRootBinding: params.manifest?.target?.rootBinding ?? {
        kind: "trusted-filesystem-root-binding", digestAlgorithm: "sha256",
        basis: "canonical-realpath-device-inode-type-mode-v1", digest: "0".repeat(64),
      },
      platform: "other",
      primitive: "none",
      status: "refused",
      targetState: "absent",
      commitState: "not-committed",
      verification: "not-run",
      durability: "not-attempted",
      error: {
        code: "UNSUPPORTED_PLATFORM",
        message: `publish-fixed-set module unavailable: ${cause?.message ?? "unknown"}`.slice(0, 300),
      },
    };
  }

  return publishFixedSet(params);
}

/** Fixed manifest construction for the same receipt-bound publication mechanism. */
async function runCreateFixedSetPublicationManifest(params) {
  if (
    params === null ||
    typeof params !== "object" ||
    Array.isArray(params) ||
    Object.keys(params).sort().join(",") !== "sourceRoot,targetParent,targetSegment" ||
    typeof params.sourceRoot !== "string" ||
    typeof params.targetParent !== "string" ||
    typeof params.targetSegment !== "string"
  ) {
    throw new TypeError(
      "create-fixed-set-publication-manifest requires exactly sourceRoot, targetParent, and targetSegment",
    );
  }
  const { createFixedSetPublicationManifest } = await import(
    "./rename-directory-no-replace/rename-directory-no-replace.mjs"
  );
  return createFixedSetPublicationManifest(params);
}

/**
 * One-request/one-response JSON transport for the fixed Foundation mechanism
 * bridge. The offline Bundle rewrites the import above to its managed runner,
 * which injects the Bundle-owned schema validator. No request can name a
 * module, export, or arbitrary function.
 */
export async function runMechanismCli({
  input = stdin,
  output = stdout,
  error = stderr,
  invoke = invokeFoundationMechanism,
} = {}) {
  try {
    const request = await readRequest(input);
    let result;
    if (request?.operation === "self-check") {
      result = await runSelfCheck(request);
    } else if (request?.operation === "create-fixed-set-publication-manifest") {
      result = await runCreateFixedSetPublicationManifest(request.params);
    } else if (request?.operation === "publish-fixed-set") {
      result = await runPublishFixedSet(request.params, invoke);
    } else {
      result = await invoke(request);
    }
    output.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (cause) {
    error.write(`${JSON.stringify(errorResponse(cause))}\n`);
    return 2;
  }
}

async function runSelfCheck(request) {
  if (
    request === null ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    Object.keys(request).sort().join(",") !== "operation,params" ||
    request.params === null ||
    typeof request.params !== "object" ||
    Array.isArray(request.params) ||
    Object.keys(request.params).length !== 0
  ) {
    throw new TypeError("mechanisms CLI self-check requires exactly operation and empty params");
  }
  return verifyManagedBundleIdentity({ cliUrl: import.meta.url, cliName: CLI_NAME });
}

if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  process.exitCode = await runMechanismCli();
}
