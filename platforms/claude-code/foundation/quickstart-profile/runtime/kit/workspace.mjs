import { readFile } from "node:fs/promises";
import path from "node:path";
import { HARNESS_ERROR_KINDS } from "../harness/errors.mjs";
import { readFileBound } from "../harness/bound-read.mjs";

export async function readOptionalFile(root, relPath, options) {
  if (options && Object.hasOwn(options, "rootBinding")) {
    try {
      return (await readFileBound(root, relPath, { rootBinding: options.rootBinding, encoding: "utf8" })).content;
    } catch (cause) {
      if (cause?.details?.kind === HARNESS_ERROR_KINDS.MISSING_RESOURCE) return null;
      throw cause;
    }
  }
  try {
    return await readFile(path.join(root, relPath), "utf8");
  } catch (cause) {
    if (cause && cause.code === "ENOENT") return null;
    throw cause;
  }
}

export async function readOptionalJson(root, relPath, options) {
  const text = await readOptionalFile(root, relPath, options);
  if (text === null) return { ok: false, reason: "missing" };
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, reason: "parse-failed" };
  }
}

export function normalizeRelPath(relPath) {
  return String(relPath).replaceAll("\\", "/").replace(/\/+/g, "/").replace(/^\.\//, "");
}
