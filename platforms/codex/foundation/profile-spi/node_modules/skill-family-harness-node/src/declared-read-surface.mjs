import path from "node:path";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";

/**
 * Static declared read surface verification (FND-ADR-010).
 *
 * assertDeclaredReadSurface({ root, declaredReaders }) checks, by static
 * source analysis, that every `.mjs`/`.js` module under `root` only reads
 * node:fs through the consumer-declared reader set:
 *
 *   - a module that imports named APIs from "node:fs" without being declared
 *     violates rule `undeclared-module-imports-fs`;
 *   - a declared module importing an API outside its declared set violates
 *     rule `fs-api-outside-declared-set`;
 *   - any write-family fs API name appearing anywhere in the tree (whole
 *     source substring detection, including comments and string literals)
 *     violates rule `write-family-fs-api` (conservative approximation: static
 *     syntax-level violations are never under-reported).
 *
 * The verdict semantics mirror the audit tree's P3 check one-to-one; the
 * result is shaped as the contracts `declared-read-surface-result` envelope
 * whose scope, rule enumeration and guarantees are the machine contract.
 * Input is fully parameterized: root and declaredReaders are consumer data,
 * the mechanism knows no audit paths, no workspace layout, and no business
 * meaning of any module.
 *
 * Violations are collected as an evidence list (deterministic order:
 * sorted module list, then rule order per module) rather than stopping at
 * the first hit; `ok` is false exactly when the list is non-empty.
 *
 * Mechanism purity: read-only (never writes, never executes the scanned
 * modules, no model call, no network); symlinked entries under the root are
 * never followed and never scanned (conservative: a symlink may not smuggle
 * a module out of the declared surface).
 */

const MODULE_EXTENSIONS = [".mjs", ".js"];
const FS_NAMED_IMPORT_PATTERN = /import\s*\{([^}]*)\}\s*from\s*"node:fs"/g;

// Write-family API names are built by composition so this module's own
// source never contains the full forbidden names as literals (self-hit
// hygiene, inherited from the audit tree's P3 check). Detection of scanned
// modules is unaffected: they would spell the full names.
const WRITE_FS_VERBS = ["writeFile", "appendFile", "mkdir", "rm", "unlink", "rename", "copyFile"];
const WRITE_FS_APIS = WRITE_FS_VERBS.map((verb) => `${verb}Sync`).concat([
  `${"createWrite"}Stream`,
]);

export const DECLARED_READ_SURFACE_RULES = Object.freeze({
  UNDECLARED_MODULE_IMPORTS_FS: "undeclared-module-imports-fs",
  FS_API_OUTSIDE_DECLARED_SET: "fs-api-outside-declared-set",
  WRITE_FAMILY_FS_API: "write-family-fs-api",
});

const RESULT_GUARANTEES = Object.freeze([
  "syntax-surface-only",
  "conservative-approximation",
  "no-execution",
  "no-model-calls",
  "no-network-access",
]);

function invalidInput(reason, extra) {
  return mechanismError(
    HARNESS_ERROR_KINDS.DECLARED_READ_SURFACE_INVALID,
    `assertDeclaredReadSurface: ${reason}`,
    extra,
  );
}

function assertPlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalidInput(`${label} must be a plain object`);
  }
}

function isValidDeclaredModulePath(modulePath) {
  if (typeof modulePath !== "string" || modulePath.length === 0) return false;
  if (modulePath.includes("\0")) return false;
  if (modulePath.includes("\\")) return false;
  if (path.posix.isAbsolute(modulePath)) return false;
  if (/^[A-Za-z]:/.test(modulePath)) return false;
  const normalized = path.posix.normalize(modulePath);
  if (normalized === "." || normalized === "..") return false;
  if (normalized.split("/").some((segment) => segment === "..")) return false;
  return normalized === modulePath;
}

function collectModules(root) {
  const modules = [];
  const walk = (directory) => {
    const entries = readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue; // never followed, never scanned
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && MODULE_EXTENSIONS.some((ext) => entry.name.endsWith(ext))) {
        modules.push(fullPath);
      }
    }
  };
  walk(root);
  return modules;
}

function namedFsImports(source) {
  return [...source.matchAll(FS_NAMED_IMPORT_PATTERN)].flatMap((match) =>
    match[1].split(",").map((api) => api.trim()).filter(Boolean),
  );
}

/**
 * Static declared read surface verification. Returns the contracts
 * declared-read-surface-result envelope (frozen). Invalid inputs (non-empty
 * root that is not a directory, empty declaredReaders, illegal module path
 * shapes, malformed declared sets) throw SFC2004 with details.kind
 * declared-read-surface-invalid; a detected violation is reported in the
 * result's violations list (ok: false), never as an exception.
 */
export function assertDeclaredReadSurface({ root, declaredReaders } = {}) {
  if (typeof root !== "string" || root.length === 0) {
    throw invalidInput("root must be a non-empty path");
  }
  assertPlainObject(declaredReaders, "declaredReaders");
  const readerKeys = Object.keys(declaredReaders);
  if (readerKeys.length === 0) {
    throw invalidInput("declaredReaders must declare at least one reader module");
  }
  const declared = new Map();
  for (const key of readerKeys) {
    if (!isValidDeclaredModulePath(key)) {
      throw invalidInput(`declared reader module path has an illegal shape: ${JSON.stringify(key)}`);
    }
    const apis = declaredReaders[key];
    if (!Array.isArray(apis)) {
      throw invalidInput(`declared set for ${key} must be an array of fs API names`);
    }
    for (const api of apis) {
      if (typeof api !== "string" || api.length === 0) {
        throw invalidInput(`declared set for ${key} contains a malformed fs API name`);
      }
    }
    declared.set(key, apis);
  }

  const rootResolved = path.resolve(root);
  let rootStat;
  try {
    rootStat = statSync(rootResolved);
  } catch {
    throw invalidInput("root does not exist or cannot be inspected", { root: "<opaque>" });
  }
  if (!rootStat.isDirectory()) {
    throw invalidInput("root is not a directory", { root: "<opaque>" });
  }

  const modules = collectModules(rootResolved);
  const violations = [];
  const pushViolation = (entry) => violations.push(entry);

  for (const module of modules) {
    const relative = path.relative(rootResolved, module).split(path.sep).join("/");
    const source = readFileSync(module, "utf8");
    const fsImports = namedFsImports(source);
    const allowed = declared.get(relative);
    if (fsImports.length > 0 && allowed === undefined) {
      pushViolation({ module: relative, rule: DECLARED_READ_SURFACE_RULES.UNDECLARED_MODULE_IMPORTS_FS });
    }
    if (allowed !== undefined) {
      for (const api of fsImports) {
        if (!allowed.includes(api)) {
          pushViolation({ module: relative, api, rule: DECLARED_READ_SURFACE_RULES.FS_API_OUTSIDE_DECLARED_SET });
        }
      }
    }
    for (const api of WRITE_FS_APIS) {
      if (source.includes(api)) {
        pushViolation({ module: relative, api, rule: DECLARED_READ_SURFACE_RULES.WRITE_FAMILY_FS_API });
      }
    }
  }

  return Object.freeze({
    schemaVersion: 1,
    kind: "skill-family.declared-read-surface-result",
    ok: violations.length === 0,
    violations,
    scannedModules: modules.map((module) =>
      path.relative(rootResolved, module).split(path.sep).join("/"),
    ),
    scope: "esm-named-imports-only",
    guarantees: [...RESULT_GUARANTEES],
  });
}
