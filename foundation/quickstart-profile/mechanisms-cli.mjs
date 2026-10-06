#!/usr/bin/env node
import { stdin, stdout, stderr } from "node:process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  invokeFoundationMechanism,
  verifyManagedBundleIdentity,
} from "./runner.mjs";
import { loadMechanismBatchPolicy } from "./runtime/contracts-candidate/index.mjs";

const CLI_NAME = "mechanisms-cli.mjs";

// Fixed capacity authority and serialization envelope for the bounded
// mechanism batch transport (FND-DES-022); both derive from the single
// Contracts authority rather than a second copy.
const MECHANISM_BATCH_POLICY = loadMechanismBatchPolicy();
const BATCH_OUTPUT_PREFIX = '{"results":[';
const BATCH_OUTPUT_SUFFIX = "]}\n";

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

function batchRefusal(kind, message) {
  const cause = new TypeError(message);
  cause.details = { kind };
  return cause;
}

/**
 * Bounded raw-byte read through explicit listeners (never `for await`, whose
 * early break would destroy the caller stream). The current chunk is kept only
 * after the running total plus its bytes is confirmed within the limit, so an
 * over-limit chunk is never copied into the accumulation cache. Every exit
 * path releases this function's listeners; refusal never terminates the
 * caller process.
 */
function readBoundedBatchInput(input, byteLimit, outputWatch) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    let settled = false;
    let preexistingErrorFallback;
    let deferredFailure;
    let stopWatchingOutput = () => {};
    const startedFlowing = input.readableFlowing !== true && input.listenerCount("data") === 0;
    const cleanup = () => {
      input.removeListener("data", onData);
      input.removeListener("end", onEnd);
      input.removeListener("error", onError);
      input.removeListener("close", onClose);
      stopWatchingOutput();
      if (preexistingErrorFallback !== undefined) {
        clearImmediate(preexistingErrorFallback);
        preexistingErrorFallback = undefined;
      }
    };
    const rejectRead = (cause) => {
      if (settled) return;
      settled = true;
      cleanup();
      chunks.length = 0;
      if (
        startedFlowing &&
        input.readableFlowing === true &&
        input.listenerCount("data") === 0
      ) {
        input.pause();
      }
      reject(cause);
    };
    const onData = (chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const next = received + bytes.length;
      if (next > byteLimit) {
        rejectRead(
          batchRefusal(
            "batch-input-limit",
            `mechanism batch input exceeds ${byteLimit} raw UTF-8 bytes`,
          ),
        );
        return;
      }
      received = next;
      chunks.push(bytes);
    };
    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      const bytes = Buffer.concat(chunks, received);
      chunks.length = 0;
      resolve(bytes);
    };
    const onError = (cause) => {
      rejectRead(deferredFailure ?? cause);
    };
    const onClose = () => {
      rejectRead(
        deferredFailure ?? input.errored ?? new Error("mechanism batch input closed before the request ended"),
      );
    };
    const onOutputFailure = (cause) => {
      if (input.errored) {
        deferredFailure ??= cause;
        if (preexistingErrorFallback === undefined) {
          preexistingErrorFallback = setImmediate(() => rejectRead(deferredFailure));
        }
        return;
      }
      rejectRead(cause);
    };
    input.on("data", onData);
    input.on("end", onEnd);
    input.on("error", onError);
    input.on("close", onClose);
    // A destroy(error) may have set `closed` while its public error event is
    // still queued. Keep our listener through that event; the immediate also
    // handles a stream whose error event had already been observed by callers.
    if (input.errored) {
      preexistingErrorFallback = setImmediate(() => rejectRead(deferredFailure ?? input.errored));
    } else if (input.closed || input.readableEnded || input.destroyed) {
      onClose();
    }
    stopWatchingOutput = outputWatch.onFailure(onOutputFailure);
    if (settled) stopWatchingOutput();
  });
}

/**
 * Whole-batch shape precheck (FND-DES-022 section 3): the outer layer of every
 * item is checked before the first item executes. Structure failures never
 * reach the mechanism dispatcher and never fabricate per-item results.
 */
function assertMechanismBatchShape(request) {
  if (
    request === null ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    Object.keys(request).sort().join(",") !== "inputs,operation" ||
    request.operation !== "canonical-json" ||
    !Array.isArray(request.inputs) ||
    request.inputs.length === 0
  ) {
    throw batchRefusal(
      "batch-structure-invalid",
      "mechanism batch request must carry exactly operation canonical-json and a non-empty inputs array",
    );
  }
  for (const item of request.inputs) {
    if (
      item === null ||
      typeof item !== "object" ||
      Array.isArray(item) ||
      Object.keys(item).sort().join(",") !== "document"
    ) {
      throw batchRefusal(
        "batch-structure-invalid",
        "each mechanism batch input must be an object carrying exactly document",
      );
    }
  }
}

// Keeps only the batch call's short-lived listeners active before the actual
// write begins. This closes the gap where an already-destroyed Writable still
// owes its public error event, without ending or otherwise managing the stream.
function watchBatchWritable(stream, channelName) {
  let failure = stream.errored;
  let failureListener;
  let pendingErrorFallback;
  let resolvePendingError;
  const pendingError = failure
    ? new Promise((resolve) => {
      resolvePendingError = resolve;
      pendingErrorFallback = setImmediate(resolve);
    })
    : undefined;
  const onError = (cause) => {
    failure ??= cause;
    failureListener?.(failure);
    if (resolvePendingError) {
      clearImmediate(pendingErrorFallback);
      pendingErrorFallback = undefined;
      const resolve = resolvePendingError;
      resolvePendingError = undefined;
      resolve();
    }
  };
  const onClose = () => {
    failure ??= stream.errored ?? new Error(
      `mechanism batch ${channelName} closed before its write completed`,
    );
    failureListener?.(failure);
  };
  stream.on("error", onError);
  stream.on("close", onClose);
  if (!failure && (stream.closed || stream.writableEnded || stream.destroyed)) onClose();
  return {
    pendingError,
    failure: () => failure,
    onFailure(listener) {
      failureListener = listener;
      if (failure) listener(failure);
      return () => {
        if (failureListener === listener) failureListener = undefined;
      };
    },
    release() {
      failureListener = undefined;
      stream.removeListener("error", onError);
      stream.removeListener("close", onClose);
      if (pendingErrorFallback !== undefined) clearImmediate(pendingErrorFallback);
    },
  };
}

/**
 * Waits for this write's callback rather than treating the writable's buffer
 * signal as delivery completion. The caller retains ownership of the stream,
 * so completion neither ends it nor waits for the whole stream to finish.
 */
function writeAll(stream, text, channelName) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let callbackFailureFallback;
    const cleanup = () => {
      stream.removeListener("error", onError);
      stream.removeListener("close", onClose);
      if (callbackFailureFallback !== undefined) {
        clearImmediate(callbackFailureFallback);
        callbackFailureFallback = undefined;
      }
    };
    const rejectWrite = (cause) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(cause);
    };
    const onError = (cause) => {
      rejectWrite(cause);
    };
    const onClose = () => {
      rejectWrite(
        stream.errored ?? new Error(`mechanism batch ${channelName} closed before its write completed`),
      );
    };
    const onWrite = (cause) => {
      if (settled) return;
      if (cause) {
        // A standard Writable emits its matching error just after invoking the
        // write callback. Keep our listener through that event so the failure
        // cannot become an unhandled error; the immediate is a fallback for a
        // writable-like caller that reports only through the callback.
        callbackFailureFallback = setImmediate(() => rejectWrite(cause));
        return;
      }
      settled = true;
      cleanup();
      resolve();
    };
    stream.on("error", onError);
    stream.on("close", onClose);
    // As with input, an errored destroy may still owe its public error event.
    // Waiting for that event preserves the cause and prevents it from becoming
    // unhandled after an eager preflight rejection.
    if (stream.errored) {
      callbackFailureFallback = setImmediate(() => rejectWrite(stream.errored));
      return;
    }
    if (stream.closed || stream.writableEnded || stream.destroyed) {
      onClose();
      return;
    }
    try {
      stream.write(text, onWrite);
    } catch (cause) {
      rejectWrite(cause);
    }
  });
}

/**
 * Bounded, same-operation, ordered mechanism batch transport (FND-DES-022).
 *
 * The request stream is read once under the raw-byte budget, strictly decoded
 * as UTF-8, parsed once, shape-prechecked, then executed item by item through
 * the fixed single-request dispatcher — no second algorithm is introduced.
 * Every item's serialized response bytes are accumulated with the envelope
 * commas, prefix, and mandatory closing newline; nothing is written to the
 * output until the complete response is confirmed within the output budget.
 * Item failures follow the original CLI error projection into that item's
 * `response` and continue; whole-batch refusals and transport failures write
 * one batch error object to the error channel and never touch the output.
 */
export async function runMechanismCliBatch({
  input = stdin,
  output = stdout,
  error = stderr,
  invoke = invokeFoundationMechanism,
} = {}) {
  const outputWatch = watchBatchWritable(output, "output");
  const errorWatch = watchBatchWritable(error, "error output");
  try {
    // Start the input read synchronously so a queued input error is covered
    // before any output preflight can await or fail this batch.
    const bytes = await readBoundedBatchInput(
      input,
      MECHANISM_BATCH_POLICY.inputByteLimit,
      outputWatch,
    );
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const request = JSON.parse(text);
    assertMechanismBatchShape(request);
    const inputs = request.inputs;
    if (inputs.length > MECHANISM_BATCH_POLICY.itemLimit) {
      throw batchRefusal(
        "batch-item-limit",
        `mechanism batch exceeds the ${MECHANISM_BATCH_POLICY.itemLimit} item limit`,
      );
    }
    const fragments = [];
    let outputBytes = Buffer.byteLength(BATCH_OUTPUT_PREFIX, "utf8");
    let anyItemFailure = false;
    for (let inputIndex = 0; inputIndex < inputs.length; inputIndex += 1) {
      const item = inputs[inputIndex];
      let exitCode = 0;
      let response;
      try {
        response = await invoke({ operation: "canonical-json", params: item });
      } catch (cause) {
        response = errorResponse(cause);
        exitCode = 2;
      }
      const fragment = JSON.stringify({ inputIndex, exitCode, response });
      if (inputIndex > 0) outputBytes += 1; // separating comma between items
      outputBytes += Buffer.byteLength(fragment, "utf8");
      // The closing bytes are mandatory, so the check includes them before the
      // next item may execute; an overrun never delivers a partial result.
      if (outputBytes + Buffer.byteLength(BATCH_OUTPUT_SUFFIX, "utf8") > MECHANISM_BATCH_POLICY.outputByteLimit) {
        throw batchRefusal(
          "batch-output-limit",
          `mechanism batch response exceeds the ${MECHANISM_BATCH_POLICY.outputByteLimit} byte limit`,
        );
      }
      fragments.push(fragment);
      if (exitCode === 2) anyItemFailure = true;
    }
    const outputFailure = outputWatch.failure();
    outputWatch.release();
    if (outputFailure) throw outputFailure;
    await writeAll(
      output,
      `${BATCH_OUTPUT_PREFIX}${fragments.join(",")}${BATCH_OUTPUT_SUFFIX}`,
      "output",
    );
    if (errorWatch.pendingError) await errorWatch.pendingError;
    errorWatch.release();
    return anyItemFailure ? 2 : 0;
  } catch (cause) {
    const pendingErrors = [outputWatch.pendingError, errorWatch.pendingError].filter(Boolean);
    if (pendingErrors.length > 0) await Promise.all(pendingErrors);
    outputWatch.release();
    const errorFailure = errorWatch.failure();
    errorWatch.release();
    if (!errorFailure) {
      try {
        await writeAll(error, `${JSON.stringify(errorResponse(cause))}\n`, "error output");
      } catch {
        // The error channel itself failed; the batch still exits failed.
      }
    }
    return 2;
  } finally {
    outputWatch.release();
    errorWatch.release();
  }
}

if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  const args = process.argv.slice(2);
  if (args[0] === "--batch") {
    if (args.length > 1) {
      // Refuse before reading any input: the batch mode takes no positional
      // arguments, and the old single-request entry must stay unchanged.
      stderr.write(
        `${JSON.stringify(errorResponse(new TypeError("mechanisms CLI --batch accepts no additional arguments")))}\n`,
      );
      process.exitCode = 2;
    } else {
      const exitCode = await runMechanismCliBatch();
      if (exitCode === 2 && !stdin.destroyed) stdin.destroy();
      process.exitCode = exitCode;
    }
  } else {
    process.exitCode = await runMechanismCli();
  }
}
