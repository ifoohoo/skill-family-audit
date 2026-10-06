import { validateDocument } from "./validator.mjs";
import { preflightJsonData } from "./inert-json.mjs";

export const SOURCE_AUTHORITY_RECEIPT_SCHEMA_ID =
  "https://contracts.skill-family.example/v1/source-authority-receipt.json";

const SUBJECT_KEYS = Object.freeze(["filename", "packageName", "sha256", "version"]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function comparePackageName(left, right) {
  return left.packageName < right.packageName
    ? -1
    : left.packageName > right.packageName
      ? 1
      : 0;
}

function semanticFailure(message, instancePath, params = {}) {
  return {
    valid: false,
    errorCode: "SFC1001",
    errors: [{
      keyword: "sourceAuthority",
      instancePath,
      schemaPath: `${SOURCE_AUTHORITY_RECEIPT_SCHEMA_ID}#semantic`,
      message,
      params,
    }],
    data: undefined,
  };
}

function validateCanonicalSubjects(subjects) {
  for (let index = 1; index < subjects.length; index += 1) {
    const previous = subjects[index - 1].packageName;
    const current = subjects[index].packageName;
    if (previous === current) {
      return semanticFailure("subjects must have unique packageName values", `/subjects/${index}/packageName`, {
        packageName: current,
      });
    }
    if (previous > current) {
      return semanticFailure("subjects must be sorted by packageName", `/subjects/${index}/packageName`, {
        previous,
        current,
      });
    }
  }
  return null;
}

/**
 * Validates one source-authority receipt without mutating caller input.
 * Schema failures and non-canonical subjects use the existing Contracts
 * validation result and SFC1001 error code.
 */
export function validateSourceAuthorityReceipt(receipt) {
  const preflight = preflightJsonData(receipt, "", {
    keyword: "sourceAuthority",
    schemaId: SOURCE_AUTHORITY_RECEIPT_SCHEMA_ID,
    label: "source authority",
  });
  if (!preflight.valid) return preflight;
  const result = validateDocument(preflight.data, {
    schemaId: SOURCE_AUTHORITY_RECEIPT_SCHEMA_ID,
    dialect: "2020-12",
    policy: "strict",
  });
  if (!result.valid) return result;
  return validateCanonicalSubjects(result.data.subjects) ?? result;
}

function validateActualSubjects(actualSubjects) {
  const preflight = preflightJsonData(actualSubjects, "/actualSubjects", {
    keyword: "sourceAuthority",
    schemaId: SOURCE_AUTHORITY_RECEIPT_SCHEMA_ID,
    label: "source authority",
  });
  if (!preflight.valid) return preflight;
  const safeSubjects = preflight.data;
  if (!Array.isArray(safeSubjects) || safeSubjects.length === 0) {
    return semanticFailure("actual subjects must be a non-empty array", "/actualSubjects");
  }
  const copy = [];
  for (let index = 0; index < safeSubjects.length; index += 1) {
    const subject = safeSubjects[index];
    if (subject === null || typeof subject !== "object" || Array.isArray(subject)) {
      return semanticFailure("actual subject must be an object", `/actualSubjects/${index}`);
    }
    const ownKeys = Reflect.ownKeys(subject);
    if (ownKeys.some((key) => typeof key !== "string")) {
      return semanticFailure("actual subject keys must be strings", `/actualSubjects/${index}`);
    }
    const keys = ownKeys.sort();
    if (keys.length !== SUBJECT_KEYS.length || keys.some((key, keyIndex) => key !== SUBJECT_KEYS[keyIndex])) {
      return semanticFailure("actual subject must contain exactly packageName, version, filename, and sha256", `/actualSubjects/${index}`);
    }
    const descriptors = Object.getOwnPropertyDescriptors(subject);
    const values = {};
    for (const key of ["packageName", "version", "filename"]) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !("value" in descriptor)) {
        return semanticFailure(`actual subject ${key} must be an enumerable data property`, `/actualSubjects/${index}/${key}`);
      }
      values[key] = descriptor.value;
      if (typeof values[key] !== "string" || values[key].length === 0) {
        return semanticFailure(`actual subject ${key} must be a non-empty string`, `/actualSubjects/${index}/${key}`);
      }
    }
    const shaDescriptor = descriptors.sha256;
    if (!shaDescriptor.enumerable || !("value" in shaDescriptor)) {
      return semanticFailure("actual subject sha256 must be an enumerable data property", `/actualSubjects/${index}/sha256`);
    }
    values.sha256 = shaDescriptor.value;
    if (typeof values.sha256 !== "string" || !SHA256_PATTERN.test(values.sha256)) {
      return semanticFailure("actual subject sha256 must be 64 lowercase hexadecimal characters", `/actualSubjects/${index}/sha256`);
    }
    copy.push({
      packageName: values.packageName,
      version: values.version,
      filename: values.filename,
      sha256: values.sha256,
    });
  }
  copy.sort(comparePackageName);
  const canonicalFailure = validateCanonicalSubjects(copy);
  return canonicalFailure ?? { valid: true, data: copy };
}

/**
 * Parses one validated receipt only when caller-observed subjects match it
 * exactly. Actual subjects may arrive in any order; comparison uses a cloned,
 * packageName-sorted array. Success exposes only the two existing source
 * authority coordinates, not receipt internals or a new lifecycle state.
 */
export function parseSourceAuthorityReceipt(receipt, actualSubjects) {
  const receiptResult = validateSourceAuthorityReceipt(receipt);
  if (!receiptResult.valid) return receiptResult;

  const actualResult = validateActualSubjects(actualSubjects);
  if (!actualResult.valid) return actualResult;

  const expected = receiptResult.data.subjects;
  const actual = actualResult.data;
  if (expected.length !== actual.length) {
    return semanticFailure("actual subjects do not match receipt subjects", "/actualSubjects", {
      expectedCount: expected.length,
      actualCount: actual.length,
    });
  }
  for (let index = 0; index < expected.length; index += 1) {
    for (const field of ["packageName", "version", "filename", "sha256"]) {
      if (expected[index][field] !== actual[index][field]) {
        return semanticFailure("actual subjects do not match receipt subjects", `/actualSubjects/${index}/${field}`, {
          field,
          packageName: expected[index].packageName,
        });
      }
    }
  }

  return {
    valid: true,
    errorCode: null,
    errors: [],
    data: {
      sourceRepository: receiptResult.data.sourceRepository,
      sourceBaseCommit: receiptResult.data.sourceBaseCommit,
    },
  };
}
