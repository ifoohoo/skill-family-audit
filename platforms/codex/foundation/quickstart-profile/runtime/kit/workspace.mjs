import { readFile } from "node:fs/promises";
import path from "node:path";

export async function readOptionalFile(root, relPath) {
  try {
    return await readFile(path.join(root, relPath), "utf8");
  } catch (cause) {
    if (cause && cause.code === "ENOENT") return null;
    throw cause;
  }
}

export async function readOptionalJson(root, relPath) {
  const text = await readOptionalFile(root, relPath);
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
