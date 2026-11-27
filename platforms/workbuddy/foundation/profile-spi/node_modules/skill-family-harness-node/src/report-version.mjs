// @feature FND-FR-004
// @decision FND-ADR-005
// @design FND-DES-004
import harnessPackage from "../package.json" with { type: "json" };

// The Harness package manifest is the report renderer version authority.
// Bundlers inline this static JSON import, so a single-file host adapter keeps
// the Harness version instead of resolving package.json beside the host file.
export const REPORT_RENDERER_VERSION = harnessPackage.version;
