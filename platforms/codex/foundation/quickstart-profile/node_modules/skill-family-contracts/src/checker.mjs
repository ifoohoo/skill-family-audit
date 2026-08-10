import { readFileSync } from "node:fs";
import { ContractsError, isRegisteredErrorCode } from "./errors.mjs";
import { loadRegistry } from "./registry.mjs";
import { listFixtures, verifyFixture } from "./fixtures.mjs";
import { SUPPORTED_DIALECTS, detectDialect, compileSchema } from "./validator.mjs";

/**
 * Finite mechanical rule system.
 *
 * Exactly nine check types exist; the set is closed (adding a type is a
 * contracts change). Mandatory rules stay within the first-version budget
 * (<= 20) with an absolute cap (30); the budget rule is a mechanical gate:
 * exceeding it fails the run with SFC1008.
 *
 * runChecks accepts optional overrides (rules, registry, fixtures, loadSchema)
 * so synthetic registries and fixtures can exercise every failure branch.
 */

const RULES_DOCUMENT = JSON.parse(
  readFileSync(new URL("./rules.json", import.meta.url), "utf8"),
);

/** Frozen list of the nine check type names. */
export const CHECK_TYPES = Object.freeze(RULES_DOCUMENT.checkTypes.map((entry) => entry.type));

/** Frozen mandatory rule set as shipped. */
export const MANDATORY_RULES = Object.freeze(
  RULES_DOCUMENT.rules.filter((rule) => rule.severity === "mandatory"),
);

/** Frozen budget: { firstVersionMax, absoluteMax }. */
export const RULE_BUDGET = Object.freeze({
  firstVersionMax: RULES_DOCUMENT.budget.firstVersionMax,
  absoluteMax: RULES_DOCUMENT.budget.absoluteMax,
});

function pass(rule) {
  return { ruleId: rule.ruleId, checkType: rule.checkType, ok: true };
}

function fail(rule, code, message) {
  return { ruleId: rule.ruleId, checkType: rule.checkType, ok: false, code, message };
}

function defaultLoadSchema(registration) {
  return JSON.parse(readFileSync(new URL(`../${registration.file}`, import.meta.url), "utf8"));
}

/**
 * Collects unresolved $ref targets across a set of schemas.
 * Input: array of { $id, document }. Output: array of { $id, ref, reason }.
 */
export function collectUnresolvedRefs(schemaEntries) {
  const byId = new Map(schemaEntries.map((entry) => [entry.$id, entry.document]));
  const unresolved = [];
  for (const { $id, document } of schemaEntries) {
    walkRefs(document, (ref) => {
      if (typeof ref !== "string") {
        unresolved.push({ $id, ref: String(ref), reason: "ref is not a string" });
        return;
      }
      if (ref.startsWith("#")) {
        if (!resolvePointer(document, ref.slice(1))) {
          unresolved.push({ $id, ref, reason: "internal pointer does not resolve" });
        }
        return;
      }
      const hashIndex = ref.indexOf("#");
      const base = hashIndex === -1 ? ref : ref.slice(0, hashIndex);
      const pointer = hashIndex === -1 ? "" : ref.slice(hashIndex + 1);
      const target = byId.get(base);
      if (!target) {
        unresolved.push({ $id, ref, reason: "base $id is not registered" });
      } else if (!resolvePointer(target, pointer)) {
        unresolved.push({ $id, ref, reason: "pointer in target schema does not resolve" });
      }
    });
  }
  return unresolved;
}

function walkRefs(node, visit) {
  if (Array.isArray(node)) {
    for (const child of node) walkRefs(child, visit);
    return;
  }
  if (node && typeof node === "object") {
    for (const [key, value] of Object.entries(node)) {
      if (key === "$ref") visit(value);
      walkRefs(value, visit);
    }
  }
}

function resolvePointer(document, pointer) {
  if (pointer === "") return true;
  if (!pointer.startsWith("/")) return false;
  let node = document;
  for (const rawSegment of pointer.slice(1).split("/")) {
    const segment = rawSegment.replace(/~1/g, "/").replace(/~0/g, "~");
    if (node && typeof node === "object" && segment in node) {
      node = node[segment];
    } else {
      return false;
    }
  }
  return true;
}

function schemaEntries(ctx) {
  return ctx.registry.schemas.map((registration) => ({
    $id: registration.$id,
    registration,
    document: ctx.loadSchema(registration),
  }));
}

const HANDLERS = {
  "schema.compile": (rule, ctx) => {
    const registrations = rule.target.registry === "schemas"
      ? ctx.registry.schemas
      : ctx.registry.schemas.filter((entry) => entry.object === rule.target.object);
    if (registrations.length === 0) {
      return fail(rule, "SFC1002", `no registered schema for target: ${rule.target.object ?? rule.target.registry}`);
    }
    for (const registration of registrations) {
      try {
        compileSchema(
          { schema: ctx.loadSchema(registration) },
          { dialect: registration.dialect, policy: "strict" },
        );
      } catch (cause) {
        if (cause instanceof ContractsError) {
          return fail(rule, cause.code, `${registration.object}: ${cause.message}`);
        }
        throw cause;
      }
    }
    return pass(rule);
  },

  "schema.unique-id": (rule, ctx) => {
    const seen = new Set();
    const duplicates = [];
    for (const entry of ctx.registry.schemas) {
      if (seen.has(entry.$id)) duplicates.push(entry.$id);
      seen.add(entry.$id);
    }
    return duplicates.length > 0
      ? fail(rule, "SFC1003", `duplicate schema $id: ${duplicates.join(", ")}`)
      : pass(rule);
  },

  "protocol.unique-name": (rule, ctx) => {
    const seen = new Set();
    const duplicates = [];
    for (const entry of ctx.registry.protocols) {
      const key = `${entry.name}@${entry.version}`;
      if (seen.has(key)) duplicates.push(key);
      seen.add(key);
    }
    return duplicates.length > 0
      ? fail(rule, "SFC1004", `duplicate protocol: ${duplicates.join(", ")}`)
      : pass(rule);
  },

  "schema.ref-resolves": (rule, ctx) => {
    const unresolved = collectUnresolvedRefs(schemaEntries(ctx));
    return unresolved.length > 0
      ? fail(rule, "SFC1005", JSON.stringify(unresolved))
      : pass(rule);
  },

  "schema.dialect-declared": (rule, ctx) => {
    for (const registration of ctx.registry.schemas) {
      if (!Object.hasOwn(SUPPORTED_DIALECTS, registration.dialect)) {
        return fail(
          rule,
          "SFC1006",
          `${registration.$id}: unsupported dialect "${registration.dialect}"`,
        );
      }
      const detected = detectDialect(ctx.loadSchema(registration));
      if (detected !== registration.dialect) {
        return fail(
          rule,
          "SFC1006",
          `${registration.$id}: $schema URI detects "${detected}" but registry declares "${registration.dialect}"`,
        );
      }
    }
    return pass(rule);
  },

  "fixture.positive-passes": (rule, ctx) => {
    const mismatches = ctx.fixtures
      .filter((fixture) => fixture.expect.valid === true)
      .map((fixture) => verifyFixture(fixture))
      .filter((result) => !result.ok);
    return mismatches.length > 0
      ? fail(
          rule,
          "SFC1010",
          mismatches
            .map((mismatch) => `${mismatch.fixtureId}: observed ${JSON.stringify(mismatch.observed)}`)
            .join("; "),
        )
      : pass(rule);
  },

  "fixture.negative-coded": (rule, ctx) => {
    const mismatches = ctx.fixtures
      .filter((fixture) => fixture.expect.valid === false)
      .map((fixture) => verifyFixture(fixture))
      .filter((result) => !result.ok);
    return mismatches.length > 0
      ? fail(
          rule,
          "SFC1010",
          mismatches
            .map((mismatch) => `${mismatch.fixtureId}: observed ${JSON.stringify(mismatch.observed)}`)
            .join("; "),
        )
      : pass(rule);
  },

  "error-code.registered": (rule, ctx) => {
    const unknown = [];
    for (const fixture of ctx.fixtures) {
      const code = fixture.expect.errorCode;
      if (code !== undefined && !isRegisteredErrorCode(code)) {
        unknown.push(`${fixture.fixtureId}: ${code}`);
      }
    }
    return unknown.length > 0
      ? fail(rule, "SFC1009", `unregistered expected codes: ${unknown.join(", ")}`)
      : pass(rule);
  },

  "rules.budget": (rule, ctx) => {
    const count = ctx.rules.filter((candidate) => candidate.severity === "mandatory").length;
    if (count > RULE_BUDGET.absoluteMax) {
      return fail(
        rule,
        "SFC1008",
        `mandatory rule count ${count} exceeds absolute cap ${RULE_BUDGET.absoluteMax}`,
      );
    }
    if (count > RULE_BUDGET.firstVersionMax) {
      return fail(
        rule,
        "SFC1008",
        `mandatory rule count ${count} exceeds first-version budget ${RULE_BUDGET.firstVersionMax}`,
      );
    }
    return pass(rule);
  },
};

function runRule(rule, ctx) {
  if (!CHECK_TYPES.includes(rule.checkType)) {
    return fail(rule, "SFC1007", `unknown check type: ${rule.checkType}`);
  }
  return HANDLERS[rule.checkType](rule, ctx);
}

/**
 * Runs a rule set (default: the frozen mandatory rules over the shipped
 * registry and fixtures). Returns { ok, mandatoryCount, budget, results }.
 */
export function runChecks({
  rules = MANDATORY_RULES,
  registry = loadRegistry(),
  fixtures = listFixtures(),
  loadSchema = defaultLoadSchema,
} = {}) {
  const ctx = { rules, registry, fixtures, loadSchema };
  const results = rules.map((rule) => runRule(rule, ctx));
  return {
    ok: results.every((result) => result.ok),
    mandatoryCount: rules.filter((rule) => rule.severity === "mandatory").length,
    budget: RULE_BUDGET,
    results,
  };
}
