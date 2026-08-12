// Fixed dispatch: every registered schema $id mapped to its generated
// standalone validator function.
import * as validate202012 from "./validate-2020-12.mjs";

const STANDALONE_VALIDATORS = Object.freeze({
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/resource.json": validate202012.validate0,
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/result.json": validate202012.validate1,
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/task.json": validate202012.validate2,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/behavior/parameters.json": validate202012.validate3,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/behavior/result.json": validate202012.validate4,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/conformance/parameters.json": validate202012.validate5,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/conformance/result.json": validate202012.validate6,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/release/parameters.json": validate202012.validate7,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/release/result.json": validate202012.validate8,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/runtime/parameters.json": validate202012.validate9,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/methods/runtime/result.json": validate202012.validate10,
  "https://contracts.skill-family.example/skill-family-audit/candidate/v2/plugin-project-observation.json": validate202012.validate11,
  "https://contracts.skill-family.example/v1/operation-request.json": validate202012.validate12,
  "https://contracts.skill-family.example/v1/operation-result.json": validate202012.validate13,
});

export default STANDALONE_VALIDATORS;
