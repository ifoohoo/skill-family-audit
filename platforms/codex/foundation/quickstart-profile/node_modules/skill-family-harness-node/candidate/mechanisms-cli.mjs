#!/usr/bin/env node
import { stdin, stdout, stderr } from "node:process";
import {
  canonicalJson,
  computeResourceClosure,
  digestDocument,
} from "./quickstart-profile.mjs";

async function readRequest() {
  const chunks = [];
  for await (const chunk of stdin) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export async function runMechanismCli() {
  try {
    const request = await readRequest();
    let result;
    if (request.operation === "canonical-json") {
      result = { text: canonicalJson(request.document) };
    } else if (request.operation === "digest-document") {
      result = { digest: digestDocument(request.document) };
    } else if (request.operation === "resource-closure") {
      result = await computeResourceClosure({
        root: request.root,
        resources: request.resources,
      });
    } else {
      throw new TypeError(`unknown Foundation mechanism: ${String(request.operation)}`);
    }
    stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (cause) {
    stderr.write(`${cause?.message ?? String(cause)}\n`);
    return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await runMechanismCli();
}
