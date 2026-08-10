import { readFileSync } from "node:fs";
import { detectDialect, validateDocument } from "../../src/validator.mjs";

const documents = Object.freeze({
  resource: load("resource.schema.json"),
  task: load("task.schema.json"),
  result: load("result.schema.json"),
});

function load(name) {
  return Object.freeze(
    JSON.parse(readFileSync(new URL(name, import.meta.url), "utf8")),
  );
}

export const QUICKSTART_PROFILE_ID = "quickstart-profile";
export const QUICKSTART_PROFILE_VERSION = 1;
export const QUICKSTART_PROTOCOL = Object.freeze({
  name: "skill-family.quickstart-profile",
  version: 1,
});

/** Candidate-only schemas. They are deliberately absent from registry.json. */
export function quickstartProfileSchemas() {
  return structuredClone(documents);
}

function linkResourceSchema(schema) {
  const linked = structuredClone(schema);
  const resourceId = documents.resource.$id;
  const visit = (value) => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }
    if (!value || typeof value !== "object") return;
    if (value.$ref === resourceId) value.$ref = "#/$defs/quickstartResource";
    for (const child of Object.values(value)) visit(child);
  };
  visit(linked);
  linked.$defs = {
    ...(linked.$defs ?? {}),
    quickstartResource: structuredClone(documents.resource),
  };
  return linked;
}

/** Validate one candidate profile document through the shared Ajv validator. */
export function validateQuickstartProfileDocument(kind, document) {
  if (!Object.hasOwn(documents, kind)) {
    throw new TypeError(`unknown quickstart profile document kind: ${String(kind)}`);
  }
  const schema = kind === "resource" ? documents.resource : linkResourceSchema(documents[kind]);
  return validateDocument(document, {
    schema,
    dialect: detectDialect(schema),
    policy: "strict",
  });
}
