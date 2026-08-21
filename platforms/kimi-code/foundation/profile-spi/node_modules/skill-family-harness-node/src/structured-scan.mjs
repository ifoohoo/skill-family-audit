import { findSchemaByObject } from "skill-family-contracts";
import { mkdtempSync, rmSync, writeFileSync, lstatSync, readlinkSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import ipaddr from "ipaddr.js";
import { readWantedLockfile } from "@pnpm/lockfile.fs";
import { parseDocument, visit } from "yaml";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { classifyPathInput, readFileContained, resolveContained } from "./paths.mjs";
import { validateContractDocument } from "./validation.mjs";

const POLICY_SCHEMA_ID = findSchemaByObject("structured-scan-policy").$id;

/**
 * Structured surface scanner (FND-ADR-011).
 *
 * scanSurfaceStructured({ root, relPaths, policy }) is the public,
 * consumer-parameterized form of the same mechanism family as scanSurface:
 * it scans consumer-declared files under a consumer-declared root against a
 * consumer-declared structured-scan-policy contract document, and fails
 * closed on the first hit (structured-scan-violation with details.rule from
 * the closed vocabulary). The mechanism owns no private identity, no
 * workspace layout, no approval list: every network, registry, coordinate,
 * adapter, host-key pattern and binary approval is consumer data.
 *
 * Closed rule vocabulary (details.rule):
 *   non-public-address                  CIDR-outside or unparseable IP-shaped token
 *   private-npm-scope                   scoped coordinate outside approvedCoordinates
 *   unapproved-dependency-coordinate    unscoped coordinate outside approvedCoordinates
 *   non-approved-registry               URL reference outside approvedRegistries
 *   non-reserved-hostname               host that is not localhost, not an approved
 *                                       registry host, and not hostKeyPattern-shaped
 *   format-adapter-parse-failed         a registered adapter could not parse the file
 *   format-adapter-unknown              a registered adapter name is not implemented
 *   binary-unclassified                 non-text file outside binaryPolicy.approvedPaths
 *   symlink-forbidden                   symlinked entry (readlink records the target
 *                                       text; the target is never followed)
 *
 * Address semantics: lexical candidate boundaries (rules (A)-(E) for
 * IPv6-shaped runs plus dotted-decimal IPv4 shape) feed a single standard
 * parse entry (ipaddr.js); an unparseable candidate fails closed
 * (non-public-address) — no undocumented syntax exemption exists. IPv4-mapped
 * and compatible embedded addresses delegate to the embedded IPv4's CIDR
 * classification. Bias direction is declared in the policy contract:
 * conservative, never silently skipped.
 *
 * Format adapters: files whose relative path matches a registered
 * formatAdapters[].pathPattern are parsed structurally; a parse failure is
 * format-adapter-parse-failed (fail-closed) and an unregistered adapter name
 * is format-adapter-unknown (fail-closed). There is no position-level whole
 * key or whole file exemption: every key and every string leaf value of a
 * parsed document still runs the full structure rules. Built-in adapters:
 * "pnpm-lockfile" (@pnpm/lockfile.fs semantic object plus yaml AST comment
 * regions) and "tree-json" (JSON.parse).
 *
 * Mechanism purity: never executes scanned files, no model call, no network;
 * the only write is a temporary lockfile copy under the OS temp directory
 * (cleaned up) for the pnpm-lockfile adapter. Symlinked entries are never
 * followed.
 */

export const STRUCTURED_SCAN_RULES = Object.freeze({
  NON_PUBLIC_ADDRESS: "non-public-address",
  PRIVATE_NPM_SCOPE: "private-npm-scope",
  UNAPPROVED_DEPENDENCY_COORDINATE: "unapproved-dependency-coordinate",
  NON_APPROVED_REGISTRY: "non-approved-registry",
  NON_RESERVED_HOSTNAME: "non-reserved-hostname",
  FORMAT_ADAPTER_PARSE_FAILED: "format-adapter-parse-failed",
  FORMAT_ADAPTER_UNKNOWN: "format-adapter-unknown",
  BINARY_UNCLASSIFIED: "binary-unclassified",
  SYMLINK_FORBIDDEN: "symlink-forbidden",
});

// ---------------------------------------------------------------- patterns

const URL_PATTERN = /[A-Za-z][A-Za-z0-9+.-]*:\/\/(\[[^\]/\s]+\]|[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+[^/\s"'<>\\:]*)/g;
const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})/g;
const HOST_KEY_STRING_PATTERN = /"(?:host|hostname|server|endpoint)"\s*:\s*"([^"]+)"/g;
const HOST_KEY_ARRAY_PATTERN = /"hosts"\s*:\s*\[([^\]]*)\]/g;
const QUOTED_TOKEN_PATTERN = /"([^"]+)"/g;
const NPM_SCOPE_PATTERN = /(?<![A-Za-z0-9._%+-])@([a-z0-9][a-z0-9._-]*)\/([a-z0-9][a-z0-9._-]*)/g;
const IP_RUN_PATTERN = /[0-9A-Za-z:.]+(?:%[0-9A-Za-z._~-]+)?/g;
const IPV4_SHAPED_PATTERN = /\d{1,3}(?:\.\d{1,3}){3}/g;
const HEX_GROUP_SEGMENT_PATTERN = /^[0-9A-Fa-f]{1,4}$/;
const ALPHA_SHORT_SEGMENT_PATTERN = /^[A-Za-z]{1,4}$/;
const HEX_LETTER_PATTERN = /[A-Fa-f]/;
const DECIMAL_DIGIT_PATTERN = /[0-9]/;
const LOCKFILE_URL_REFERENCE_PATTERN = /^(https?|git|git\+https|git\+ssh|ssh):/;
const LOCAL_LOCKFILE_REF_PREFIXES = ["link:", "file:", "path:", "workspace:"];

/**
 * Lexical boundary judgement: is a colon-containing run IP-shaped?
 * Rules (A)-(E) are the public lexical boundary: (A) contains "::"; (B) at
 * least four non-empty colon segments; (C) at least three segments and all
 * non-empty segments are 1-4 hex digits with a hex letter present; (D) an
 * empty segment exists, all non-empty segments are hex groups, at least two
 * non-empty segments, with a hex letter present; (E) at least one non-empty
 * segment is a 1-4 letter alpha run while a decimal digit exists elsewhere.
 * Documented non-address classes (pure-decimal colon runs, pure-alpha colon
 * runs, digest-prefix runs, single-group colon labels, semver/plain text)
 * are kept clean by independent positive fixtures; everything that cannot be
 * classified as non-address enters the single parse entry and fails closed
 * when unparseable.
 */
export function isIpv6ShapedRun(run) {
  if (!run.includes(":")) return false;
  if (run.includes("::")) return true; // (A)
  const segments = run.split(":");
  const nonEmptySegments = segments.filter((segment) => segment.length > 0);
  const hasEmptySegment = nonEmptySegments.length !== segments.length;
  if (nonEmptySegments.length >= 4) return true; // (B)
  const allHexGroups =
    nonEmptySegments.length > 0 && nonEmptySegments.every((segment) => HEX_GROUP_SEGMENT_PATTERN.test(segment));
  if (allHexGroups && nonEmptySegments.length >= 3 && HEX_LETTER_PATTERN.test(run)) return true; // (C)
  if (hasEmptySegment && allHexGroups && nonEmptySegments.length >= 2 && HEX_LETTER_PATTERN.test(run)) return true; // (D)
  if (nonEmptySegments.some((segment) => ALPHA_SHORT_SEGMENT_PATTERN.test(segment)) && DECIMAL_DIGIT_PATTERN.test(run)) return true; // (E)
  return false;
}

/** IP-shaped candidate extraction. Sentence punctuation is stripped before
 * the rules; IPv4 candidates not covered by a colon candidate are added. */
export function extractIpCandidates(text) {
  const candidates = [];
  for (const match of text.matchAll(IP_RUN_PATTERN)) {
    let run = match[0];
    let index = match.index;
    const leadingDots = run.match(/^\.+/);
    if (leadingDots) {
      index += leadingDots[0].length;
      run = run.slice(leadingDots[0].length);
    }
    const trailingDots = run.match(/\.+$/);
    if (trailingDots) run = run.slice(0, run.length - trailingDots[0].length);
    if (isIpv6ShapedRun(run)) {
      candidates.push({ token: run, index, shape: "ipv6" });
    }
  }
  for (const match of text.matchAll(IPV4_SHAPED_PATTERN)) {
    const coveredByColonCandidate = candidates.some(
      (entry) => match.index >= entry.index && match.index + match[0].length <= entry.index + entry.token.length,
    );
    if (!coveredByColonCandidate) {
      candidates.push({ token: match[0], index: match.index, shape: "ipv4" });
    }
  }
  candidates.sort((a, b) => a.index - b.index);
  return candidates;
}

/** Normalizes a candidate for the parse entry: URL brackets and %zone-id. */
export function normalizeIpToken(token) {
  let core = String(token);
  if (core.startsWith("[")) {
    const close = core.indexOf("]");
    core = close === -1 ? core.slice(1) : core.slice(1, close);
  }
  const zone = core.indexOf("%");
  if (zone !== -1) core = core.slice(0, zone);
  return core;
}

function withinApprovedNetworks(cidrs, addr) {
  for (const [cidrAddress, cidrRange] of cidrs) {
    if (cidrAddress.kind() !== addr.kind()) continue; // ipaddr.match throws across kinds; classify by family
    if (addr.match(cidrAddress, cidrRange)) return { allowed: true, reason: "approved-network" };
  }
  return { allowed: false, reason: "outside-approved-networks" };
}

function classifyIpv4Octets(cidrs, octets) {
  return withinApprovedNetworks(cidrs, new ipaddr.IPv4(octets));
}

/**
 * Single address classification entry: brackets/zone id/case/IPv4/IPv6 all
 * pass through here. ipaddr.parse failure is fail-closed
 * (unparseable-ip-shaped-token); IPv4-mapped/compatible embeddings delegate
 * to the embedded IPv4's CIDR classification.
 */
export function classifyIpToken(cidrs, token) {
  const core = normalizeIpToken(token);
  let addr;
  try {
    addr = ipaddr.parse(core);
  } catch {
    return { allowed: false, reason: "unparseable-ip-shaped-token" };
  }
  if (addr.kind() === "ipv6") {
    const bytes = addr.toByteArray();
    const embedded =
      bytes.slice(0, 10).every((byte) => byte === 0) &&
      ((bytes[10] === 0xff && bytes[11] === 0xff) || (bytes[10] === 0 && bytes[11] === 0));
    if (embedded) {
      const verdict = classifyIpv4Octets(cidrs, bytes.slice(12));
      return { allowed: verdict.allowed, reason: `embedded-ipv4:${verdict.reason}` };
    }
  }
  return withinApprovedNetworks(cidrs, addr);
}

function lineOf(bytes, index) {
  let line = 1;
  for (let i = 0; i < index && i < bytes.length; i += 1) {
    if (bytes[i] === 0x0a) line += 1;
  }
  return line;
}

function isIpShapedToken(bare) {
  if (isIpv6ShapedRun(bare)) return true;
  return IPV4_SHAPED_PATTERN.test(bare);
}

function registryHosts(approvedRegistries) {
  const hosts = new Set();
  for (const registry of approvedRegistries) {
    const match = registry.match(/^[a-z][a-z0-9+.-]*:\/\/([^/]+)/i);
    if (match) {
      const bare = match[1].toLowerCase().replace(/\.$/, "");
      const portIndex = bare.indexOf(":");
      hosts.add(portIndex === -1 ? bare : bare.slice(0, portIndex));
    }
  }
  return hosts;
}

// ----------------------------------------------------------- policy loading

function loadPolicy(policy) {
  const checked = validateContractDocument(policy, { schemaId: POLICY_SCHEMA_ID });
  if (!checked.valid) {
    throw mechanismError(HARNESS_ERROR_KINDS.STRUCTURED_SCAN_INVALID, "structured-scan policy document is invalid", {
      errors: checked.errors,
    });
  }

  const cidrs = [];
  for (const cidr of policy.allowedNetworks) {
    let parsed;
    try {
      parsed = ipaddr.parseCIDR(cidr);
    } catch (cause) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.STRUCTURED_SCAN_INVALID,
        `structured-scan policy contains an invalid CIDR: ${cidr}`,
        { cidr, cause: cause && cause.message ? cause.message : String(cause) },
      );
    }
    cidrs.push(parsed);
  }

  let hostKeyPattern = null;
  if (typeof policy.hostKeyPattern === "string") {
    try {
      hostKeyPattern = new RegExp(policy.hostKeyPattern);
    } catch (cause) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.STRUCTURED_SCAN_INVALID,
        "structured-scan policy hostKeyPattern does not compile",
        { cause: cause && cause.message ? cause.message : String(cause) },
      );
    }
  }

  const adapters = [];
  for (const adapter of policy.formatAdapters) {
    let pattern;
    try {
      pattern = new RegExp(adapter.pathPattern);
    } catch (cause) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.STRUCTURED_SCAN_INVALID,
        `structured-scan policy adapter ${adapter.name} pathPattern does not compile`,
        { adapter: adapter.name, cause: cause && cause.message ? cause.message : String(cause) },
      );
    }
    adapters.push({ name: adapter.name, pattern });
  }

  return {
    schemaVersion: policy.schemaVersion,
    kind: policy.kind,
    allowedNetworks: cidrs,
    approvedRegistries: [...policy.approvedRegistries],
    approvedCoordinates: new Set(policy.approvedCoordinates),
    formatAdapters: adapters,
    symlinkPolicy: policy.symlinkPolicy.mode,
    binaryPolicy: { mode: policy.binaryPolicy.mode, approvedPaths: new Set(policy.binaryPolicy.approvedPaths) },
    hostKeyPattern,
    approvedRegistryHosts: registryHosts(policy.approvedRegistries),
  };
}

// ---------------------------------------------------------------- scanning

function scanViolation(relPath, rule, evidence) {
  return mechanismError(HARNESS_ERROR_KINDS.STRUCTURED_SCAN_VIOLATION, "structured scan matched a violation", {
    path: relPath,
    rule,
    evidence,
  });
}

function checkHost(ctx, relPath, host, context, text, index) {
  if (typeof host !== "string" || host.length === 0) return;
  let bare = host;
  const atIndex = bare.lastIndexOf("@");
  if (atIndex !== -1) bare = bare.slice(atIndex + 1);
  if (bare.startsWith("[")) {
    const verdict = classifyIpToken(ctx.allowedNetworks, bare);
    if (!verdict.allowed) {
      throw scanViolation(relPath, STRUCTURED_SCAN_RULES.NON_PUBLIC_ADDRESS, `${host}（${verdict.reason}）`);
    }
    return;
  }
  const portIndex = bare.indexOf(":");
  if (portIndex !== -1) bare = bare.slice(0, portIndex);
  bare = bare.toLowerCase().replace(/\.$/, "");
  if (bare.length === 0) return;
  if (isIpShapedToken(bare)) {
    const verdict = classifyIpToken(ctx.allowedNetworks, bare);
    if (!verdict.allowed) {
      throw scanViolation(relPath, STRUCTURED_SCAN_RULES.NON_PUBLIC_ADDRESS, `${host}（${verdict.reason}）`);
    }
    return;
  }
  if (!bare.includes(".")) {
    if (bare === "localhost") return;
    if (context === "host-key" && ctx.hostKeyPattern?.test(bare)) return;
    throw scanViolation(relPath, STRUCTURED_SCAN_RULES.NON_RESERVED_HOSTNAME, host);
  }
  if (ctx.approvedRegistryHosts.has(bare)) return;
  throw scanViolation(relPath, STRUCTURED_SCAN_RULES.NON_RESERVED_HOSTNAME, host);
}

/** Full structure rules over one text buffer. Throws on first hit. */
function scanStructure(ctx, relPath, bytes) {
  const text = bytes.toString("utf8");

  for (const match of text.matchAll(URL_PATTERN)) checkHost(ctx, relPath, match[1], "url", text, match.index);
  for (const match of text.matchAll(EMAIL_PATTERN)) checkHost(ctx, relPath, match[1], "email", text, match.index);
  for (const match of text.matchAll(HOST_KEY_STRING_PATTERN)) checkHost(ctx, relPath, match[1], "host-key", text, match.index);
  for (const arrayMatch of text.matchAll(HOST_KEY_ARRAY_PATTERN)) {
    for (const tokenMatch of arrayMatch[1].matchAll(QUOTED_TOKEN_PATTERN)) {
      checkHost(ctx, relPath, tokenMatch[1], "host-key", text, arrayMatch.index);
    }
  }

  for (const match of text.matchAll(NPM_SCOPE_PATTERN)) {
    const coordinate = `@${match[1]}/${match[2]}`;
    if (!ctx.approvedCoordinates.has(coordinate)) {
      throw scanViolation(relPath, STRUCTURED_SCAN_RULES.PRIVATE_NPM_SCOPE, match[0]);
    }
  }

  for (const { token, index } of extractIpCandidates(text)) {
    const verdict = classifyIpToken(ctx.allowedNetworks, token);
    if (!verdict.allowed) {
      throw scanViolation(relPath, STRUCTURED_SCAN_RULES.NON_PUBLIC_ADDRESS, `${token}（${verdict.reason}）`);
    }
  }
}

/** Binary judgement (fail-closed): non-text control bytes in the first 8KB. */
function looksBinary(bytes) {
  const limit = Math.min(bytes.length, 8192);
  for (let i = 0; i < limit; i += 1) {
    const b = bytes[i];
    if (b === 9 || b === 10 || b === 11 || b === 12 || b === 13) continue;
    if (b < 32 || b === 127) return true;
  }
  return false;
}

// ----------------------------------------------------------- format adapters

/** yaml AST comment regions; an unparseable document yields none (the
 * semantic parse path reports format-adapter-parse-failed). */
export function collectLockfileCommentRegions(bytes) {
  const text = Buffer.isBuffer(bytes) ? bytes.toString("utf8") : String(bytes);
  let doc;
  try {
    doc = parseDocument(text);
  } catch {
    return [];
  }
  const regions = [];
  if (doc.commentBefore) regions.push(doc.commentBefore);
  if (doc.comment) regions.push(doc.comment);
  visit(doc, {
    Node(_key, node) {
      if (node.commentBefore) regions.push(node.commentBefore);
      if (node.comment) regions.push(node.comment);
    },
  });
  return regions;
}

function lockfileDependencyName(depPath) {
  let dep = String(depPath);
  if (dep.startsWith("/")) dep = dep.slice(1);
  if (dep.startsWith("@")) {
    const secondAt = dep.indexOf("@", 1);
    return secondAt === -1 ? dep : dep.slice(0, secondAt);
  }
  const firstAt = dep.indexOf("@");
  return firstAt === -1 ? dep : dep.slice(0, firstAt);
}

function isLocalLockfileRef(depPathOrVersion) {
  return (
    typeof depPathOrVersion === "string" &&
    LOCAL_LOCKFILE_REF_PREFIXES.some((prefix) => depPathOrVersion.startsWith(prefix))
  );
}

/**
 * "pnpm-lockfile" adapter: comment regions are scanned first (independent of
 * the semantic parse), then @pnpm/lockfile.fs parses the document (parse
 * failure fails closed); every non-local importer dependency and every
 * packages/snapshots coordinate must be in approvedCoordinates (scoped =
 * private-npm-scope, unscoped = unapproved-dependency-coordinate; orphan
 * entries are judged too); URL references must start with an approved
 * registry; keys and string leaf values continue through the full structure
 * rules. The adapter writes one temporary copy under the OS temp directory
 * for the parser and removes it afterwards.
 */
async function scanLockfileContent(ctx, relPath, bytes) {
  const commentRegions = collectLockfileCommentRegions(bytes);
  commentRegions.forEach((region, index) => {
    scanStructure(ctx, `${relPath}#yaml-comment-${index + 1}`, Buffer.from(region, "utf8"));
  });

  let lockfile = null;
  let parseError = null;
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "sf-structured-lockfile-"));
  try {
    writeFileSync(path.join(tmpDir, "pnpm-lock.yaml"), bytes);
    lockfile = await readWantedLockfile(tmpDir, { ignoreIncompatible: false });
  } catch (cause) {
    parseError = cause;
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
  // The semantic parse must yield a lockfile document (a versioned map); a
  // scalar or otherwise non-semantic parse result is a parse failure.
  if (
    parseError ||
    lockfile === null ||
    typeof lockfile !== "object" ||
    typeof lockfile.lockfileVersion !== "string"
  ) {
    throw scanViolation(
      relPath,
      STRUCTURED_SCAN_RULES.FORMAT_ADAPTER_PARSE_FAILED,
      `pnpm-lock.yaml could not be parsed by @pnpm/lockfile.fs, fail-closed（${String(parseError?.message ?? "no semantic lockfile document").slice(0, 200)}）`,
    );
  }

  for (const [importerId, importer] of Object.entries(lockfile.importers ?? {})) {
    for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
      for (const [name, entry] of Object.entries(importer?.[section] ?? {})) {
        if (isLocalLockfileRef(entry?.version)) continue;
        if (!ctx.approvedCoordinates.has(name)) {
          throw scanViolation(
            relPath,
            name.startsWith("@") ? STRUCTURED_SCAN_RULES.PRIVATE_NPM_SCOPE : STRUCTURED_SCAN_RULES.UNAPPROVED_DEPENDENCY_COORDINATE,
            `importer ${importerId} dependency ${name}（version ${entry?.version ?? "?"}）not in approvedCoordinates`,
          );
        }
      }
    }
  }

  for (const [mapName, map] of [["packages", lockfile.packages ?? {}], ["snapshots", lockfile.snapshots ?? {}]]) {
    for (const [depPath, entry] of Object.entries(map)) {
      const baseDepPath = depPath.split("(")[0];
      if (isLocalLockfileRef(baseDepPath)) continue;
      const name = lockfileDependencyName(baseDepPath);
      if (!ctx.approvedCoordinates.has(name)) {
        throw scanViolation(
          relPath,
          name.startsWith("@") ? STRUCTURED_SCAN_RULES.PRIVATE_NPM_SCOPE : STRUCTURED_SCAN_RULES.UNAPPROVED_DEPENDENCY_COORDINATE,
          `${mapName} coordinate ${depPath} not in approvedCoordinates（orphan entries are not exempt）`,
        );
      }
    }
  }

  const walk = (node, segments) => {
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, [...segments, String(index)]));
      return;
    }
    if (node && typeof node === "object") {
      for (const [key, value] of Object.entries(node)) {
        if (typeof key === "string" && key.length > 0) {
          scanStructure(ctx, `${relPath}#/${[...segments, key].join("/")}（key）`, Buffer.from(key, "utf8"));
        }
        walk(value, [...segments, key]);
      }
      return;
    }
    if (typeof node === "string") {
      if (LOCKFILE_URL_REFERENCE_PATTERN.test(node) && !ctx.approvedRegistries.some((registry) => node.startsWith(registry))) {
        throw scanViolation(relPath, STRUCTURED_SCAN_RULES.NON_APPROVED_REGISTRY, `${segments.join("/") || "<root>"} references an unapproved registry: ${node.slice(0, 120)}`);
      }
      scanStructure(ctx, `${relPath}#/${segments.join("/")}`, Buffer.from(node, "utf8"));
    } else if (node !== null && node !== undefined) {
      scanStructure(ctx, `${relPath}#/${segments.join("/")}`, Buffer.from(String(node), "utf8"));
    }
  };
  walk(lockfile, []);
}

/**
 * "tree-json" adapter: JSON.parse; a parse failure is
 * format-adapter-parse-failed (fail-closed). There is no position-level
 * whole-key exemption: every key and every value runs the full structure
 * rules first.
 */
function scanTreeJsonContent(ctx, relPath, bytes) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    throw scanViolation(
      relPath,
      STRUCTURED_SCAN_RULES.FORMAT_ADAPTER_PARSE_FAILED,
      `tree.json could not be JSON.parse'd, fail-closed（${String(cause?.message ?? cause).slice(0, 200)}）`,
    );
  }

  const walk = (node, segments) => {
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, [...segments, String(index)]));
      return;
    }
    if (node && typeof node === "object") {
      for (const [key, value] of Object.entries(node)) {
        if (typeof key === "string" && key.length > 0) {
          scanStructure(ctx, `${relPath}#/${[...segments, key].join("/")}（key）`, Buffer.from(key, "utf8"));
        }
        walk(value, [...segments, key]);
      }
      return;
    }
    if (node !== null && node !== undefined) {
      scanStructure(ctx, `${relPath}#/${segments.join("/")}`, Buffer.from(String(node), "utf8"));
    }
  };
  walk(parsed, []);
}

function findAdapter(ctx, relPath) {
  const normalized = relPath.split(path.sep).join("/");
  for (const adapter of ctx.formatAdapters) {
    if (adapter.pattern.test(normalized)) return adapter;
  }
  return null;
}

const BUILTIN_ADAPTERS = Object.freeze({
  "pnpm-lockfile": scanLockfileContent,
  "tree-json": scanTreeJsonContent,
});

// ------------------------------------------------------------------- entry

/**
 * Structured surface scan. Returns a frozen { scanned, bytes, policy } result
 * mirroring scanSurface; a violation throws SFC2004 with details.kind
 * structured-scan-violation and details.rule from the closed vocabulary, and
 * an invalid policy throws structured-scan-invalid.
 */
export async function scanSurfaceStructured({ root, relPaths, policy, encoding = "utf8" } = {}) {
  if (typeof root !== "string" || root.length === 0) {
    throw new TypeError("scanSurfaceStructured: root must be a non-empty path");
  }
  if (!Array.isArray(relPaths)) {
    throw new TypeError("scanSurfaceStructured: relPaths must be an array of root-relative path strings");
  }
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new TypeError("scanSurfaceStructured: policy must be a structured-scan-policy contract document");
  }
  const ctx = loadPolicy(policy);

  const scanned = [];
  let bytes = 0;
  for (const relPath of relPaths) {
    if (typeof relPath !== "string" || relPath.length === 0) {
      throw new TypeError("scanSurfaceStructured: every relPath entry must be a non-empty string");
    }
    const normalized = relPath.split(path.sep).join("/");
    const classification = classifyPathInput(relPath);
    if (!classification.ok) {
      throw mechanismError(
        classification.kind,
        `path rejected before resolution (kind: ${classification.kind})`,
        { input: relPath },
      );
    }
    // Symlink entries are judged before any resolution: readlink-no-follow
    // records the target text and the target is never read. This applies to
    // in-tree links and links that would escape alike.
    const fullPath = path.resolve(root, relPath);
    let stat;
    try {
      stat = lstatSync(fullPath);
    } catch (cause) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.STRUCTURED_SCAN_INVALID,
        "scanSurfaceStructured: declared resource cannot be inspected",
        { path: normalized, cause: cause && cause.message ? cause.message : String(cause) },
      );
    }
    if (stat.isSymbolicLink()) {
      let target = "<unreadable>";
      try {
        target = readlinkSync(fullPath);
      } catch {
        // readlink failure is itself evidence: never follow, only record.
      }
      throw scanViolation(normalized, STRUCTURED_SCAN_RULES.SYMLINK_FORBIDDEN, `target: ${target}`);
    }
    await resolveContained(root, relPath);
    const readResult = await readFileContained(root, relPath);
    const raw = Buffer.isBuffer(readResult) ? readResult : Buffer.from(readResult);
    bytes += raw.length;
    scanned.push(normalized);

    if (looksBinary(raw)) {
      if (!ctx.binaryPolicy.approvedPaths.has(normalized)) {
        throw scanViolation(normalized, STRUCTURED_SCAN_RULES.BINARY_UNCLASSIFIED, "<non-text control byte; fail-closed>");
      }
      continue;
    }

    const adapter = findAdapter(ctx, normalized);
    if (adapter !== null) {
      const implementation = BUILTIN_ADAPTERS[adapter.name];
      if (!implementation) {
        throw scanViolation(normalized, STRUCTURED_SCAN_RULES.FORMAT_ADAPTER_UNKNOWN, `unimplemented adapter ${adapter.name}, fail-closed`);
      }
      await implementation(ctx, normalized, raw);
      continue;
    }
    scanStructure(ctx, normalized, raw);
  }

  return Object.freeze({ scanned, bytes, policy: structuredClone(policy) });
}
