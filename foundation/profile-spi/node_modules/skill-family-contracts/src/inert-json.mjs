/**
 * Private, side-effect-free preflight copier for caller-owned JSON data.
 * Accessors, hidden properties, symbols, unusual prototypes, cycles, sparse
 * arrays, named array properties, and non-JSON scalar values are rejected
 * before any value is read. The caller supplies the public error identity so
 * this helper remains private and does not create a second contract surface.
 */
function semanticFailure(message, instancePath, { keyword, schemaId, params = {} }) {
  return {
    valid: false,
    errorCode: "SFC1001",
    errors: [{
      keyword,
      instancePath,
      schemaPath: `${schemaId}#semantic`,
      message,
      params,
    }],
    data: undefined,
  };
}

function pointerSegment(value) {
  return String(value).replaceAll("~", "~0").replaceAll("/", "~1");
}

function copyInertJsonData(value, instancePath, ancestors, context) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return { valid: true, data: value };
  }
  if (typeof value === "number") {
    return Number.isFinite(value)
      ? { valid: true, data: value }
      : semanticFailure(`${context.label} input numbers must be finite`, instancePath, context);
  }
  if (typeof value !== "object") {
    return semanticFailure(`${context.label} input must contain JSON data only`, instancePath, {
      ...context,
      params: { valueType: typeof value },
    });
  }
  if (ancestors.has(value)) {
    return semanticFailure(`${context.label} input must not contain cycles`, instancePath, context);
  }

  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    return semanticFailure(`${context.label} input must use plain object and array prototypes`, instancePath, context);
  }

  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key === "symbol")) {
    return semanticFailure(`${context.label} input must not contain symbol keys`, instancePath, context);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  ancestors.add(value);
  try {
    if (array) {
      const length = descriptors.length?.value;
      if (!Number.isSafeInteger(length) || length < 0) {
        return semanticFailure(`${context.label} arrays must have a valid length`, instancePath, context);
      }
      for (const key of ownKeys) {
        if (key === "length") continue;
        const index = Number(key);
        if (!Number.isSafeInteger(index) || index < 0 || index >= length || String(index) !== key) {
          return semanticFailure(`${context.label} arrays must not contain named properties`, `${instancePath}/${pointerSegment(key)}`, context);
        }
      }
      const copy = new Array(length);
      for (let index = 0; index < length; index += 1) {
        const descriptor = descriptors[String(index)];
        const itemPath = `${instancePath}/${index}`;
        if (!descriptor) {
          return semanticFailure(`${context.label} arrays must not contain sparse entries`, itemPath, context);
        }
        if (!descriptor.enumerable || !("value" in descriptor)) {
          return semanticFailure(`${context.label} input properties must be enumerable data properties`, itemPath, context);
        }
        const item = copyInertJsonData(descriptor.value, itemPath, ancestors, context);
        if (!item.valid) return item;
        Object.defineProperty(copy, String(index), {
          value: item.data,
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
      return { valid: true, data: copy };
    }

    const copy = Object.create(null);
    for (const key of ownKeys) {
      const descriptor = descriptors[key];
      const propertyPath = `${instancePath}/${pointerSegment(key)}`;
      if (!descriptor.enumerable || !("value" in descriptor)) {
        return semanticFailure(`${context.label} input properties must be enumerable data properties`, propertyPath, context);
      }
      const property = copyInertJsonData(descriptor.value, propertyPath, ancestors, context);
      if (!property.valid) return property;
      Object.defineProperty(copy, key, {
        value: property.data,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return { valid: true, data: copy };
  } finally {
    ancestors.delete(value);
  }
}

export function preflightJsonData(value, instancePath, options) {
  const context = {
    keyword: options.keyword,
    schemaId: options.schemaId,
    label: options.label,
    params: {},
  };
  try {
    return copyInertJsonData(value, instancePath, new Set(), context);
  } catch (error) {
    return semanticFailure(`${context.label} input could not be inspected as inert JSON data`, instancePath, {
      ...context,
      params: { errorName: typeof error?.name === "string" ? error.name : "Error" },
    });
  }
}
