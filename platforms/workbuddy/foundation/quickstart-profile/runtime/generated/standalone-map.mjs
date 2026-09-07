// Fixed dispatch: every registered schema $id mapped to its generated
// standalone validator function.
import * as validate202012 from "./validate-2020-12.mjs";

const STANDALONE_VALIDATORS = Object.freeze({
  "https://contracts.skill-family.example/candidate/foundation-mechanisms/v1/schema-validation-batch-request.json": validate202012.__skillFamilyFoundationValidator_00000,
  "https://contracts.skill-family.example/candidate/foundation-mechanisms/v1/schema-validation-batch-result.json": validate202012.__skillFamilyFoundationValidator_00001,
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/consumer-schema-inventory.json": validate202012.__skillFamilyFoundationValidator_00002,
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/harness-surface-detectors.json": validate202012.__skillFamilyFoundationValidator_00003,
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/harness-surface-inventory.json": validate202012.__skillFamilyFoundationValidator_00004,
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/resource.json": validate202012.__skillFamilyFoundationValidator_00005,
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/result.json": validate202012.__skillFamilyFoundationValidator_00006,
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/task.json": validate202012.__skillFamilyFoundationValidator_00007,
  "https://contracts.skill-family.example/foundation-mechanisms/v1/schema-validation-batch-request.json": validate202012.__skillFamilyFoundationValidator_00000,
  "https://contracts.skill-family.example/foundation-mechanisms/v1/schema-validation-batch-result.json": validate202012.__skillFamilyFoundationValidator_00001,
  "https://contracts.skill-family.example/quickstart-profile/v2/consumer-schema-inventory.json": validate202012.__skillFamilyFoundationValidator_00002,
  "https://contracts.skill-family.example/quickstart-profile/v2/harness-surface-detectors.json": validate202012.__skillFamilyFoundationValidator_00003,
  "https://contracts.skill-family.example/quickstart-profile/v2/harness-surface-inventory.json": validate202012.__skillFamilyFoundationValidator_00004,
  "https://contracts.skill-family.example/quickstart-profile/v2/resource.json": validate202012.__skillFamilyFoundationValidator_00005,
  "https://contracts.skill-family.example/quickstart-profile/v2/result.json": validate202012.__skillFamilyFoundationValidator_00006,
  "https://contracts.skill-family.example/quickstart-profile/v2/task.json": validate202012.__skillFamilyFoundationValidator_00007,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/foundation-adoption-exemption.json": validate202012.__skillFamilyFoundationValidator_00008,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/foundation-consumption-classification.json": validate202012.__skillFamilyFoundationValidator_00009,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/governance-gate-run-evidence.json": validate202012.__skillFamilyFoundationValidator_00010,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/conformance/parameters.json": validate202012.__skillFamilyFoundationValidator_00011,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/conformance/result.json": validate202012.__skillFamilyFoundationValidator_00012,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/release/parameters.json": validate202012.__skillFamilyFoundationValidator_00013,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/release/result.json": validate202012.__skillFamilyFoundationValidator_00014,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/source-truth-declaration.json": validate202012.__skillFamilyFoundationValidator_00015,
  "https://contracts.skill-family.example/v1/filesystem-root-binding.json": validate202012.__skillFamilyFoundationValidator_00016,
  "https://contracts.skill-family.example/v1/fixed-set-publication-manifest.json": validate202012.__skillFamilyFoundationValidator_00017,
  "https://contracts.skill-family.example/v1/fixed-set-publication-receipt.json": validate202012.__skillFamilyFoundationValidator_00018,
  "https://contracts.skill-family.example/v1/migration-manifest.json": validate202012.__skillFamilyFoundationValidator_00019,
  "https://contracts.skill-family.example/v1/operation-request.json": validate202012.__skillFamilyFoundationValidator_00020,
  "https://contracts.skill-family.example/v1/operation-result.json": validate202012.__skillFamilyFoundationValidator_00021,
  "skill-family-audit:semantic-review-result": validate202012.__skillFamilyFoundationValidator_00022,
  "spec/packages/skill-development/schemas/skill_rule_exception.schema.json": validate202012.__skillFamilyFoundationValidator_00023,
});

export default STANDALONE_VALIDATORS;
