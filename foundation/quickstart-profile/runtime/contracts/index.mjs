// Fixed bundle surface: the exact stable contracts exports consumed by the
// projected quickstart harness, re-exported from mechanically projected sources.
export {
  ContractsError,
  ERROR_CODES,
  errorCodeRegistry,
  errorCodeInfo,
  isRegisteredErrorCode,
  assertRegisteredErrorCode,
  stableError,
} from "./errors.mjs";
export { canonicalJson, digestDocument } from "./canonical.mjs";
