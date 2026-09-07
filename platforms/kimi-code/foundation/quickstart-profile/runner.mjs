// Quickstart Profile v2 offline runner: the projected Foundation harness
// mechanisms and the standalone-backed candidate validation entry.
export * from "./runtime/harness/quickstart-profile.mjs";
export { validateQuickstartProfileDocument } from "./runtime/contracts-candidate/index.mjs";
export { validateBySchemaId } from "./validators.mjs";
export { createFilesystemRootBinding, readFileBound } from "./runtime/harness/bound-read.mjs";
export { createFixedSetPublicationManifest, publishFixedSet } from "./runtime/harness/fixed-set-publication.mjs";
export { publishFileExclusive, publishFileOrReplace, replaceFileAtomic } from "./runtime/harness/atomic.mjs";
export { acquireFilesystemLock, inspectFilesystemLock, releaseFilesystemLock, recoverFilesystemLock } from "./runtime/harness/token-lock.mjs";
import { invokeFoundationMechanism as invokeHarnessMechanism } from "./runtime/harness/quickstart-profile.mjs";
import { validateBySchemaId } from "./validators.mjs";
import { listValidatableSchemaIds } from "./validators.mjs";
export function invokeFoundationMechanism(request) {
  return invokeHarnessMechanism(request, { validateBySchemaId, listValidatableSchemaIds });
}
