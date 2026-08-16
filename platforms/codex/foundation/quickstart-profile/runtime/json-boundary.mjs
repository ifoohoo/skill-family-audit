// Verbatim projection of the candidate JSON-boundary probe and the Ajv error
// normalization from the contracts candidate validation entry.
function normalizeErrors(ajvErrors) {
  if (!ajvErrors) return [];
  return ajvErrors.map((error) => ({
    keyword: error.keyword,
    instancePath: error.instancePath,
    schemaPath: error.schemaPath,
    message: error.message,
    params: error.params,
  }));
}

function escapePointerSegment(segment) {
  return String(segment).replaceAll("~", "~0").replaceAll("/", "~1");
}

const ARRAY_INDEX_PATTERN = /^(0|[1-9]\d*)$/;

// Inspects own properties through descriptors only, so accessors are refused
// without ever being invoked. JSON would drop symbol-keyed and non-enumerable
// properties silently and execute accessors, so all three classes fail closed.
function probeObjectMembers(value, instancePath, ancestors) {
  const symbolKeys = Object.getOwnPropertySymbols(value);
  if (symbolKeys.length > 0) {
    return {
      instancePath: `${instancePath}/${escapePointerSegment(String(symbolKeys[0]))}`,
      reason: "symbol-keyed property",
    };
  }
  const isArray = Array.isArray(value);
  let arrayLength = 0;
  if (isArray) {
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (!lengthDescriptor || lengthDescriptor.get || lengthDescriptor.set) {
      return { instancePath: `${instancePath}/length`, reason: "accessor property" };
    }
    arrayLength = lengthDescriptor.value;
  }
  for (const key of Object.getOwnPropertyNames(value)) {
    if (isArray && key === "length") continue;
    const memberPath = `${instancePath}/${escapePointerSegment(key)}`;
    if (isArray && (!ARRAY_INDEX_PATTERN.test(key) || Number(key) >= arrayLength)) {
      return { instancePath: memberPath, reason: "non-index array property" };
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor) continue;
    if (descriptor.get || descriptor.set) {
      return { instancePath: memberPath, reason: "accessor property" };
    }
    if (!descriptor.enumerable) {
      return { instancePath: memberPath, reason: "non-enumerable property" };
    }
    const issue = probeJsonValue(descriptor.value, memberPath, ancestors);
    if (issue) return issue;
  }
  return null;
}

function probeJsonValue(value, instancePath, ancestors) {
  if (value === null) return null;
  const type = typeof value;
  if (type === "boolean" || type === "string") return null;
  if (type === "number") {
    return Number.isFinite(value) ? null : { instancePath, reason: "non-finite number" };
  }
  if (type === "bigint") return { instancePath, reason: "bigint" };
  if (type === "undefined") return { instancePath, reason: "undefined" };
  if (type === "function" || type === "symbol") return { instancePath, reason: type };
  if (type !== "object") return { instancePath, reason: type };
  const isArray = Array.isArray(value);
  if (!isArray) {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      return {
        instancePath,
        reason: `non-plain object (${Object.prototype.toString.call(value)})`,
      };
    }
  }
  if (ancestors.has(value)) return { instancePath, reason: "circular reference" };
  ancestors.add(value);
  const issue = probeObjectMembers(value, instancePath, ancestors);
  ancestors.delete(value);
  return issue;
}

/**
 * Deep JSON-safety probe for candidate documents and caller-owned values.
 * Pure JSON data is null, booleans, finite numbers, strings, arrays, and
 * plain objects. Anything else (bigint, undefined, function, symbol,
 * non-finite number, non-plain object, circular reference) is reported as
 * { instancePath, reason } at the first offending location, instead of
 * surviving into structuredClone, digestDocument, or JSON.stringify where it
 * would throw or silently drift. Own properties JSON would ignore or execute
 * are refused the same way: symbol-keyed and non-enumerable properties are
 * dropped by serialization and accessors would be executed, so the probe
 * rejects them through descriptors without invoking any accessor. Repeated
 * references to the same JSON-safe object stay accepted when acyclic; only
 * true cycles fail closed. Returns null when the value is pure JSON.
 */
export function findNonJsonValue(value) {
  return probeJsonValue(value, "", new Set());
}
export { normalizeErrors as normalizeValidationError };
