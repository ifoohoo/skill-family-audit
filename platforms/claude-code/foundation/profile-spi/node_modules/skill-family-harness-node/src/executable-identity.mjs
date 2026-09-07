import { lstat, readlink } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";
import { digestDocument } from "skill-family-contracts";
import { digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { createFilesystemRootBinding, readFileBound } from "./bound-read.mjs";

const POSIX = path.posix;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const MAX_SYMLINK_DEPTH = 40;
const MAX_SYMLINK_BYTES = 1024 * 1024;
const ROOT_BINDING_KEYS = "basis,digest,digestAlgorithm,kind";
const INPUT_KEYS = "boundRoots,interpreterPolicy,lookup";
const LOOKUP_KEYS = {
  "absolute-path": "mode,path",
  "explicit-path-search": "command,mode,pathEntries",
};
const WINDOWS_DRIVE = /^[A-Za-z]:/u;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function ownKeys(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value).sort().join(",")
    : "";
}

function assertObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
}

function assertCanonicalAbsolute(value, label) {
  if (typeof value !== "string" || value.length === 0 || !POSIX.isAbsolute(value) ||
      value.includes("\\") || value.includes("\0") || POSIX.normalize(value) !== value ||
      (value.length > 1 && value.endsWith("/")) ||
      value.split("/").some((segment) => segment === "." || segment === "..")) {
    throw new TypeError(`${label} must be a normalized POSIX absolute path`);
  }
  return value;
}

function assertBareCommand(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 ||
      value.includes("/") || value.includes("\\") || value.includes("\0") ||
      value === "." || value === ".." || WINDOWS_DRIVE.test(value)) {
    throw new TypeError(`${label} must be a bare command without path separators`);
  }
  return value;
}

function assertRootBindingShape(binding, label) {
  assertObject(binding, label);
  if (ownKeys(binding) !== ROOT_BINDING_KEYS || binding.kind !== "trusted-filesystem-root-binding" ||
      binding.digestAlgorithm !== "sha256" ||
      binding.basis !== "canonical-realpath-device-inode-type-mode-v1" ||
      typeof binding.digest !== "string" || !SHA256_PATTERN.test(binding.digest)) {
    throw new TypeError(`${label} is not a filesystem-root-binding value`);
  }
}

function assertRootEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 64) {
    throw new TypeError("boundRoots must be a non-empty array");
  }
  const roots = [];
  const seen = new Set();
  for (const [index, entry] of entries.entries()) {
    assertObject(entry, `boundRoots[${index}]`);
    if (ownKeys(entry) !== "root,rootBinding") throw new TypeError("boundRoots entries are closed");
    const root = assertCanonicalAbsolute(entry.root, `boundRoots[${index}].root`);
    assertRootBindingShape(entry.rootBinding, `boundRoots[${index}].rootBinding`);
    if (seen.has(root)) throw new TypeError("boundRoots must not contain duplicate roots");
    seen.add(root);
    roots.push({
      root,
      rootBinding: {
        basis: entry.rootBinding.basis,
        digest: entry.rootBinding.digest,
        digestAlgorithm: entry.rootBinding.digestAlgorithm,
        kind: entry.rootBinding.kind,
      },
    });
  }
  const ordered = [...roots].sort((left, right) => left.root.length - right.root.length || left.root.localeCompare(right.root));
  for (let parentIndex = 0; parentIndex < ordered.length; parentIndex += 1) {
    const parent = ordered[parentIndex].root;
    for (let childIndex = parentIndex + 1; childIndex < ordered.length; childIndex += 1) {
      if (pathWithinRoot(parent, ordered[childIndex].root)) {
        throw new TypeError("boundRoots must not contain overlapping roots");
      }
    }
  }
  return roots;
}

function pathWithinRoot(root, value) {
  return root === "/" ? value.startsWith("/") : value === root || value.startsWith(`${root}/`);
}

function assertRootReferenceArray(value, label, roots, { optional = true } = {}) {
  if (value === undefined && optional) return undefined;
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new TypeError(`${label} must be a non-empty array of bound root references`);
  }
  const seen = new Set();
  return value.map((root, index) => {
    assertCanonicalAbsolute(root, `${label}[${index}]`);
    if (!roots.some((entry) => entry.root === root)) {
      throw new TypeError(`${label}[${index}] must exactly reference a bound root`);
    }
    if (seen.has(root)) throw new TypeError(`${label} must not contain duplicate roots`);
    seen.add(root);
    return root;
  });
}

function validateInput(input) {
  assertObject(input, "observeExecutableIdentity input");
  if (ownKeys(input) !== INPUT_KEYS && ownKeys(input) !== "boundRoots,lookup") {
    throw new TypeError("observeExecutableIdentity input has unknown fields");
  }
  const roots = assertRootEntries(input.boundRoots);
  assertObject(input.lookup, "lookup");
  const mode = input.lookup.mode;
  if (!Object.hasOwn(LOOKUP_KEYS, mode) || ownKeys(input.lookup) !== LOOKUP_KEYS[mode]) {
    throw new TypeError("lookup does not match its closed mode shape");
  }
  const lookup = { mode };
  if (mode === "absolute-path") {
    lookup.path = assertCanonicalAbsolute(input.lookup.path, "lookup.path");
  } else {
    lookup.command = assertBareCommand(input.lookup.command, "lookup.command");
    lookup.pathEntries = assertRootReferenceArray(input.lookup.pathEntries, "lookup.pathEntries", roots, { optional: false });
  }
  const requested = input.lookup.requested ?? (mode === "absolute-path" ? lookup.path : lookup.command);
  if (typeof requested !== "string" || requested.length === 0 || requested.length > 4096 ||
      requested.includes("\0") || requested.includes("\r") || requested.includes("\n")) {
    throw new TypeError("lookup.requested must be a bounded string");
  }
  if (requested !== (mode === "absolute-path" ? lookup.path : lookup.command)) {
    throw new TypeError("lookup.requested must equal the lookup target");
  }
  lookup.requested = requested;
  let interpreterPolicy;
  if (input.interpreterPolicy !== undefined) {
    assertObject(input.interpreterPolicy, "interpreterPolicy");
    const keys = ownKeys(input.interpreterPolicy);
    if (keys !== "absoluteRoots" && keys !== "pathEntries" && keys !== "absoluteRoots,pathEntries") {
      throw new TypeError("interpreterPolicy has unknown fields");
    }
    interpreterPolicy = {
      absoluteRoots: assertRootReferenceArray(input.interpreterPolicy.absoluteRoots, "interpreterPolicy.absoluteRoots", roots),
      pathEntries: assertRootReferenceArray(input.interpreterPolicy.pathEntries, "interpreterPolicy.pathEntries", roots),
    };
    if (interpreterPolicy.absoluteRoots === undefined && interpreterPolicy.pathEntries === undefined) {
      throw new TypeError("interpreterPolicy must provide an interpreter root policy");
    }
  }
  return { roots, lookup, interpreterPolicy };
}

function rootForPath(roots, value) {
  const matches = roots.filter(({ root }) => pathWithinRoot(root, value));
  if (matches.length !== 1) return null;
  return matches[0];
}

function relativeToRoot(root, value) {
  const relative = POSIX.relative(root, value);
  if (!relative || relative.startsWith("../") || relative === ".." || POSIX.isAbsolute(relative) || relative.includes("\\")) return null;
  return relative;
}

function statIdentity(value) {
  return [value.dev, value.ino, value.mode, value.nlink, value.size].map(String).join(":");
}

function unsafe(message, details = {}) {
  return mechanismError(HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY, message, details);
}

function untrusted(message, details = {}) {
  return mechanismError(HARNESS_ERROR_KINDS.UNTRUSTED_EXECUTABLE, message, details);
}

function notFound(message, details = {}) {
  return mechanismError(HARNESS_ERROR_KINDS.EXECUTABLE_NOT_FOUND, message, details);
}

function unsupportedInterpreter(message, details = {}) {
  return mechanismError(HARNESS_ERROR_KINDS.UNSUPPORTED_INTERPRETER, message, details);
}

function decodeTarget(bytes, linkPath) {
  if (bytes.length > MAX_SYMLINK_BYTES) throw untrusted("symbolic link target is too large", { input: linkPath });
  let target;
  try {
    target = decoder.decode(bytes);
  } catch {
    throw untrusted("symbolic link target is not valid UTF-8", { input: linkPath });
  }
  if (target.length === 0 || target.includes("\0") || target.includes("\\") || target.includes("\r") || target.includes("\n")) {
    throw untrusted("symbolic link target cannot be represented as a safe path", { input: linkPath });
  }
  return target;
}

async function captureLink(linkPath, before, relative) {
  let first;
  let second;
  let after;
  try {
    first = Buffer.from(await readlink(linkPath, { encoding: "buffer" }));
    after = await lstat(linkPath, { bigint: false });
    second = Buffer.from(await readlink(linkPath, { encoding: "buffer" }));
  } catch (cause) {
    throw unsafe("symbolic link changed while being observed", {
      input: relative,
      boundReadDisposition: "boundary-indeterminate",
      code: cause?.code,
    });
  }
  if (!sameStatIdentity(before, after) || !first.equals(second)) {
    throw unsafe("symbolic link changed while being observed", {
      input: relative,
      boundReadDisposition: "boundary-indeterminate",
    });
  }
  return {
    path: linkPath,
    targetBase64: first.toString("base64"),
    bytes: first.length,
    target: decodeTarget(first, linkPath),
  };
}

function sameStatIdentity(left, right) {
  return statIdentity(left) === statIdentity(right);
}

function safeSegment(segment) {
  return segment.length > 0 && segment !== "." && segment !== ".." && !segment.includes("\\") &&
    !segment.includes("\0") && !WINDOWS_DRIVE.test(segment) && !segment.includes("/");
}

/**
 * Resolves an absolute path one component at a time.  Every component is
 * lstat'd, and symbolic links are read as bytes without ever opening or
 * recursing through their targets by descriptor.  The returned chain is
 * intentionally local to this invocation; no namespace observation is cached.
 */
async function resolveEntry(startPath, roots, visited = new Set(), chain = [], depth = 0) {
  if (depth > MAX_SYMLINK_DEPTH) throw unsafe("symbolic link chain exceeds the fixed depth", { input: startPath });
  const root = rootForPath(roots, startPath);
  if (!root) throw unsafe("executable path leaves the union of bound roots", { input: startPath });
  const relative = relativeToRoot(root.root, startPath);
  if (relative === null) throw mechanismError(HARNESS_ERROR_KINDS.SYMLINK_ESCAPE, "executable path is not contained by its bound root", { input: startPath });
  const segments = relative.split("/");
  let cursor = root.root;
  for (let index = 0; index < segments.length; index += 1) {
    if (!safeSegment(segments[index])) throw new TypeError("executable path contains an unsafe segment");
    const memberPath = POSIX.join(cursor, segments[index]);
    let before;
    try {
      before = await lstat(memberPath, { bigint: false });
    } catch (cause) {
      if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return { missing: true, chain };
      throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, "executable path could not be inspected", { input: memberPath, code: cause?.code });
    }
    if (before.isSymbolicLink()) {
      if (visited.has(memberPath)) throw unsafe("symbolic link chain loops", { input: memberPath });
      const nextVisited = new Set(visited);
      nextVisited.add(memberPath);
      const link = await captureLink(memberPath, before, memberPath);
      const remainder = segments.slice(index + 1);
      const targetPath = POSIX.isAbsolute(link.target)
        ? POSIX.resolve(link.target, ...remainder)
        : POSIX.resolve(POSIX.dirname(memberPath), link.target, ...remainder);
      if (!rootForPath(roots, targetPath)) {
        throw mechanismError(HARNESS_ERROR_KINDS.SYMLINK_ESCAPE, "symbolic link target leaves the union of bound roots", { input: memberPath });
      }
      return resolveEntry(targetPath, roots, nextVisited, [...chain, {
        path: link.path,
        targetBase64: link.targetBase64,
        bytes: link.bytes,
      }], depth + 1);
    }
    if (index < segments.length - 1 && !before.isDirectory()) return { missing: true, chain };
    if (index === segments.length - 1) return { path: memberPath, stat: before, chain };
    cursor = memberPath;
  }
  return { missing: true, chain };
}

function isNativeMagic(bytes) {
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return true;
  if (bytes.length < 4) return false;
  const magic = bytes.readUInt32BE(0);
  return [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].includes(magic);
}

function parseShebang(bytes) {
  if (bytes.length < 2 || bytes[0] !== 0x23 || bytes[1] !== 0x21) return null;
  let line;
  try {
    line = decoder.decode(bytes.subarray(2, bytes.indexOf(0x0a, 2) === -1 ? bytes.length : bytes.indexOf(0x0a, 2))).replace(/\r$/u, "");
  } catch {
    throw unsupportedInterpreter("shebang is not valid UTF-8");
  }
  if (line.length === 0 || /["'=$]/u.test(line)) throw unsupportedInterpreter("shebang uses unsupported shell syntax");
  const tokens = line.trim().split(/[\t ]+/u).filter(Boolean);
  if (tokens.length === 1 && POSIX.isAbsolute(tokens[0]) && !tokens[0].includes("\\") && !tokens[0].includes("\0")) {
    return { path: assertCanonicalAbsolute(POSIX.normalize(tokens[0]), "shebang interpreter"), request: POSIX.normalize(tokens[0]), shebangArgs: [] };
  }
  if (tokens.length === 2 && tokens[0] === "/usr/bin/env") {
    return { command: assertBareCommand(tokens[1], "shebang env interpreter"), request: tokens[1], shebangArgs: [] };
  }
  throw unsupportedInterpreter("shebang form is outside the fixed interpreter grammar");
}

async function observeResolved(resolved, roots) {
  if (resolved.missing) return null;
  if (!resolved.stat.isFile() || Number(resolved.stat.nlink) !== 1 || (Number(resolved.stat.mode) & 0o111) === 0) {
    throw untrusted("executable entry must be one executable ordinary file", { input: resolved.path });
  }
  const root = rootForPath(roots, resolved.path);
  const relPath = relativeToRoot(root.root, resolved.path);
  if (!root || relPath === null) throw mechanismError(HARNESS_ERROR_KINDS.SYMLINK_ESCAPE, "canonical executable leaves bound roots", { input: resolved.path });
  const receipt = await readFileBound(root.root, relPath, { rootBinding: root.rootBinding });
  if (Number(receipt.statMode) !== Number(resolved.stat.mode) || Number(receipt.bytes) !== Number(resolved.stat.size)) {
    throw unsafe("executable changed during bound observation", { input: resolved.path, boundReadDisposition: "boundary-indeterminate" });
  }
  const bytes = Buffer.from(receipt.content);
  const entryKind = isNativeMagic(bytes) ? "native-binary" : bytes[0] === 0x23 && bytes[1] === 0x21 ? "interpreter-script" : "opaque-executable";
  return {
    path: resolved.path,
    symlinkChain: resolved.chain,
    binding: root.rootBinding,
    relPath,
    sha256: digestBytes(bytes),
    bytes: bytes.length,
    statMode: Number(receipt.statMode),
    entryKind,
    content: bytes,
    stat: resolved.stat,
  };
}

async function assertStableEntry(selectedPath, selected, observed, roots) {
  let after;
  let final;
  try {
    after = await resolveEntry(selectedPath, roots);
    if (after.missing || after.path !== selected.path || !sameStatIdentity(after.stat, selected.stat) ||
        chainKey(after.chain) !== chainKey(selected.chain)) {
      throw new Error("executable namespace changed during bound observation");
    }
    // Re-read the resolved entry through the same bound-read chokepoint.  A
    // writer can preserve inode, mode, link count, and byte length while
    // replacing its bytes; the digest comparison below closes that gap only
    // for the interval between these two bound reads.
    final = await observeResolved(after, roots);
    if (!final || final.path !== observed.path ||
        chainKey(final.symlinkChain) !== chainKey(observed.symlinkChain) ||
        !sameStatIdentity(final.stat, observed.stat) ||
        final.sha256 !== observed.sha256) {
      throw new Error("executable content or identity changed during bound observation");
    }
  } catch {
    throw unsafe("executable changed during bound observation", {
      input: selectedPath,
      boundReadDisposition: "boundary-indeterminate",
    });
  }
}

function freezeDeep(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function chainKey(chain) {
  return JSON.stringify(chain);
}

async function verifyRootBindings(roots) {
  await Promise.all(roots.map(async (entry) => {
    const actual = await createFilesystemRootBinding(entry.root);
    if (actual.digest !== entry.rootBinding.digest) {
      throw unsafe("approved root binding does not match the current root", { input: entry.root, boundReadDisposition: "boundary-indeterminate" });
    }
  }));
}

/**
 * Observes a deterministic explicit launch image.  PATH is entirely supplied
 * by the caller; process.env.PATH and any ambient executable cache are never
 * consulted.  Callers must invoke this again immediately before spawning.
 */
export async function observeExecutableIdentity(input = {}) {
  const parsed = validateInput(input);
  await verifyRootBindings(parsed.roots);
  let selected;
  let selectedPath;
  if (parsed.lookup.mode === "absolute-path") {
    selected = await resolveEntry(parsed.lookup.path, parsed.roots);
    if (selected.missing) throw notFound("requested executable was not found", { input: parsed.lookup.path });
    selectedPath = parsed.lookup.path;
  } else {
    for (const rootPath of parsed.lookup.pathEntries) {
      const candidate = POSIX.join(rootPath, parsed.lookup.command);
      const resolved = await resolveEntry(candidate, parsed.roots);
      if (resolved.missing || !resolved.stat?.isFile() || Number(resolved.stat.nlink) !== 1 || (Number(resolved.stat.mode) & 0o111) === 0) continue;
      selected = resolved;
      selectedPath = candidate;
      break;
    }
    if (!selected) throw notFound("no executable matched the explicit path search", { input: parsed.lookup.command });
  }
  const canonical = await observeResolved(selected, parsed.roots);
  if (!canonical) throw notFound("requested executable was not found", { input: parsed.lookup.requested });
  await assertStableEntry(selectedPath, selected, canonical, parsed.roots);
  let interpreter = null;
  let launch = { file: canonical.path, argvPrefix: [] };
  if (canonical.entryKind === "interpreter-script") {
    const shebang = parseShebang(canonical.content);
    if (!shebang) throw unsupportedInterpreter("interpreter-script has no usable shebang");
    const policy = parsed.interpreterPolicy;
    if (!policy) throw unsupportedInterpreter("script interpretation requires an explicit interpreter policy");
    let interpreterPath = shebang.path;
    let interpreterResolved;
    if (shebang.command !== undefined) {
      if (!policy.pathEntries) throw unsupportedInterpreter("env shebang requires explicit interpreter path entries");
      for (const rootPath of policy.pathEntries) {
        const candidate = POSIX.join(rootPath, shebang.command);
        const resolved = await resolveEntry(candidate, parsed.roots);
        if (!resolved.missing && resolved.stat?.isFile() && Number(resolved.stat.nlink) === 1 && (Number(resolved.stat.mode) & 0o111) !== 0) {
          interpreterPath = candidate;
          interpreterResolved = resolved;
          break;
        }
      }
      if (!interpreterPath) throw unsupportedInterpreter("env shebang interpreter was not found");
    } else if (!policy.absoluteRoots || !rootForPath(policy.absoluteRoots.map((root) => parsed.roots.find((entry) => entry.root === root)), interpreterPath)) {
      throw unsupportedInterpreter("absolute shebang interpreter is outside its explicit policy roots", { input: interpreterPath });
    }
    interpreterResolved ??= await resolveEntry(interpreterPath, parsed.roots);
    if (interpreterResolved.missing) throw unsupportedInterpreter("shebang interpreter was not found", { input: interpreterPath });
    interpreter = await observeResolved(interpreterResolved, parsed.roots);
    if (!interpreter || interpreter.entryKind !== "native-binary") {
      throw untrusted("shebang interpreter must be a native binary", { input: interpreterPath });
    }
    await assertStableEntry(interpreterPath, interpreterResolved, interpreter, parsed.roots);
    await assertStableEntry(selectedPath, selected, canonical, parsed.roots);
    launch = { file: interpreter.path, argvPrefix: [canonical.path] };
    interpreter = { request: shebang.request, canonicalEntry: { ...interpreter, content: undefined, stat: undefined }, shebangArgs: shebang.shebangArgs };
    delete interpreter.canonicalEntry.content;
    delete interpreter.canonicalEntry.stat;
  }
  await verifyRootBindings(parsed.roots);
  const output = {
    schemaVersion: 1,
    kind: "skill-family.executable-identity-observation",
    lookup: parsed.lookup.mode === "absolute-path"
      ? { requested: parsed.lookup.requested, mode: parsed.lookup.mode, path: parsed.lookup.path, selectedPath: parsed.lookup.path }
      : { requested: parsed.lookup.requested, mode: parsed.lookup.mode, pathEntries: parsed.lookup.pathEntries, selectedPath },
    canonicalEntry: { ...canonical, content: undefined, stat: undefined },
    interpreter,
    launch,
  };
  delete output.canonicalEntry.content;
  delete output.canonicalEntry.stat;
  output.observationDigest = digestDocument(output);
  return freezeDeep(output);
}
