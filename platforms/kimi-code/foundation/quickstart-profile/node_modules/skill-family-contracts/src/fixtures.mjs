import { readdirSync, readFileSync } from "node:fs";
import { isRegisteredErrorCode } from "./errors.mjs";
import { findSchemaRegistration, findProtocol } from "./registry.mjs";
import { checkOperation } from "./kernel.mjs";
import { SUPPORTED_DIALECTS, validateDocument } from "./validator.mjs";

/**
 * Contract fixtures: positive, negative, and dialect-boundary examples for
 * every top-level contract. Each fixture declares its target schema, dialect,
 * policy, and expectation; verifyFixture replays the expectation mechanically.
 *
 * Pipeline order (deterministic):
 *   dialect supported? -> SFC1006
 *   schemaId registered? -> SFC1002
 *   schema validation -> SFC1001 / SFC1012
 *   kernel post-checks for requests (SFC1011, SFC2002, SFC2003)
 *   error-code post-checks for results (SFC1009)
 * A declared/observed mismatch is reported as SFC1010 by verifyFixture.
 */

const FIXTURE_CLASSES = Object.freeze(["positive", "negative", "dialect-boundary"]);
const FIXTURES_DIR = new URL("./fixtures/", import.meta.url);

let fixturesCache = null;

/** All fixtures, sorted by fixtureId for deterministic order. */
export function listFixtures() {
  if (fixturesCache) return fixturesCache;
  const fixtures = [];
  for (const contract of readdirSync(FIXTURES_DIR).sort()) {
    const contractDir = new URL(`${contract}/`, FIXTURES_DIR);
    let names;
    try {
      names = readdirSync(contractDir);
    } catch {
      continue;
    }
    for (const name of names.sort()) {
      if (!name.endsWith(".json")) continue;
      const fixture = JSON.parse(readFileSync(new URL(name, contractDir), "utf8"));
      fixtures.push(fixture);
    }
  }
  fixtures.sort((a, b) => a.fixtureId.localeCompare(b.fixtureId));
  fixturesCache = fixtures;
  return fixtures;
}

/** Frozen list of fixture classes. */
export function fixtureClasses() {
  return FIXTURE_CLASSES;
}

/**
 * Runs the fixture pipeline and compares against the declared expectation.
 * Returns { fixtureId, ok, expected, observed, mismatchCode }.
 */
export function verifyFixture(fixture) {
  const expected = fixture.expect;
  const observed = runFixturePipeline(fixture);
  const ok =
    observed.valid === expected.valid &&
    (expected.valid
      ? observed.errorCode === null
      : observed.errorCode === expected.errorCode);
  return {
    fixtureId: fixture.fixtureId,
    ok,
    expected,
    observed,
    mismatchCode: ok ? null : "SFC1010",
  };
}

/** Verifies every shipped fixture. Returns { allOk, results }. */
export function verifyAllFixtures() {
  const results = listFixtures().map((fixture) => verifyFixture(fixture));
  return { allOk: results.every((result) => result.ok), results };
}

function runFixturePipeline(fixture) {
  const { schemaId, dialect, policy = "strict" } = fixture.validation;

  if (!Object.hasOwn(SUPPORTED_DIALECTS, dialect)) {
    return { valid: false, errorCode: "SFC1006" };
  }
  if (!findSchemaRegistration(schemaId)) {
    return { valid: false, errorCode: "SFC1002" };
  }

  const result = validateDocument(fixture.data, { schemaId, dialect, policy });
  if (!result.valid) {
    return { valid: false, errorCode: result.errorCode };
  }

  const document = result.data;
  if (fixture.contract === "operation-request") {
    if (!findProtocol(document.protocol.name, document.protocol.version)) {
      return { valid: false, errorCode: "SFC1011" };
    }
    const operationCheck = checkOperation(document.operation, document.params);
    if (!operationCheck.ok) {
      return { valid: false, errorCode: operationCheck.code };
    }
  }
  if (fixture.contract === "operation-result") {
    for (const error of document.errors ?? []) {
      if (!isRegisteredErrorCode(error.code)) {
        return { valid: false, errorCode: "SFC1009" };
      }
    }
  }
  return { valid: true, errorCode: null };
}
