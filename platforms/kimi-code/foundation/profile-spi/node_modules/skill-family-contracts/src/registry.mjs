import { readFileSync } from "node:fs";
import { ContractsError } from "./errors.mjs";

function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const val = obj[key];
    if (val !== null && typeof val === 'object' && !Object.isFrozen(val)) {
      deepFreeze(val);
    }
  }
  return obj;
}

/**
 * Protocol-name and schema-$id registry.
 *
 * Registration is append-only and mechanically rejects duplicates:
 * - duplicate $id            -> ContractsError SFC1003
 * - duplicate name + version -> ContractsError SFC1004
 * register* functions never mutate their input; they return an updated copy.
 */

const REGISTRY = deepFreeze(JSON.parse(
  readFileSync(new URL("./registry.json", import.meta.url), "utf8"),
));

/** The frozen registry document as shipped. */
export function loadRegistry() {
  return REGISTRY;
}

export function listSchemas(registry = REGISTRY) {
  return registry.schemas;
}

export function listProtocols(registry = REGISTRY) {
  return registry.protocols;
}

/** Schema registration entry for a $id, or null. */
export function findSchemaRegistration(schemaId, registry = REGISTRY) {
  return registry.schemas.find((entry) => entry.$id === schemaId) ?? null;
}

/** Schema registration entry for a top-level object name, or null. */
export function findSchemaByObject(object, registry = REGISTRY) {
  return registry.schemas.find((entry) => entry.object === object) ?? null;
}

/** Protocol registration entry for name + version, or null. */
export function findProtocol(name, version, registry = REGISTRY) {
  return (
    registry.protocols.find(
      (entry) => entry.name === name && entry.version === version,
    ) ?? null
  );
}

/**
 * Registers a schema entry. Returns a new registry; the input is not mutated.
 * Mechanically rejects a duplicate $id with SFC1003.
 */
export function registerSchema(entry, registry = REGISTRY) {
  requireKeys(entry, ["$id", "object", "dialect", "status"], "registerSchema");
  if (findSchemaRegistration(entry.$id, registry)) {
    throw new ContractsError(
      "SFC1003",
      `duplicate schema $id rejected: ${entry.$id}`,
      { $id: entry.$id },
    );
  }
  const next = structuredClone(registry);
  next.schemas.push(structuredClone(entry));
  return next;
}

/**
 * Registers a protocol entry. Returns a new registry; the input is not mutated.
 * Mechanically rejects a duplicate name + version with SFC1004.
 */
export function registerProtocol(entry, registry = REGISTRY) {
  requireKeys(entry, ["name", "version", "status"], "registerProtocol");
  if (findProtocol(entry.name, entry.version, registry)) {
    throw new ContractsError(
      "SFC1004",
      `duplicate protocol rejected: ${entry.name} version ${entry.version}`,
      { name: entry.name, version: entry.version },
    );
  }
  const next = structuredClone(registry);
  next.protocols.push(structuredClone(entry));
  return next;
}

function requireKeys(entry, keys, api) {
  if (!entry || typeof entry !== "object") {
    throw new TypeError(`${api}: entry must be an object`);
  }
  for (const key of keys) {
    if (entry[key] === undefined || entry[key] === null) {
      throw new TypeError(`${api}: entry is missing required key "${key}"`);
    }
  }
}
