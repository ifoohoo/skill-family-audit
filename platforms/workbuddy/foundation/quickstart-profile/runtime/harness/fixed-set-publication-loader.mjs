// @feature FND-FR-017
// @feature FND-FR-027
// @decision FND-ADR-026
// @decision FND-ADR-034
// @design FND-DES-021
// @design FND-DES-037
import { loadNativeBoundReadAddon, loadWindowsNativeAddon, stableNativePlatformKey } from "./native/loader.mjs";

export async function loadNativeAddon() {
  return loadNativeBoundReadAddon();
}

export { loadWindowsNativeAddon, stableNativePlatformKey };
