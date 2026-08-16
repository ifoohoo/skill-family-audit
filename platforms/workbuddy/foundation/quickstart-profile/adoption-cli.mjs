#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { stdin, stdout, stderr } from "node:process";
import { fileURLToPath } from "node:url";
import {
  invokeFoundationAdoption,
  verifyManagedBundleIdentity,
} from "./adoption-mechanisms.mjs";

const CLI_NAME = "adoption-cli.mjs";

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
    },
  };
}

/** One-request/one-response transport for the fixed adoption operation set. */
export async function runAdoptionCli({
  input = stdin,
  output = stdout,
  error = stderr,
  invoke = invokeFoundationAdoption,
} = {}) {
  try {
    const request = await readRequest(input);
    const result = request?.operation === "self-check"
      ? await runSelfCheck(request)
      : await invoke(request);
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
    throw new TypeError("adoption CLI self-check requires exactly operation and empty params");
  }
  return verifyManagedBundleIdentity({ cliUrl: import.meta.url, cliName: CLI_NAME });
}

if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  process.exitCode = await runAdoptionCli();
}
