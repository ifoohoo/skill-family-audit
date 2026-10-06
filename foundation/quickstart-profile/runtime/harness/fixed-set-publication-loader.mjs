import { loadNativeBoundReadAddon, stableNativePlatformKey } from "./native/loader.mjs";

export async function loadNativeAddon() {
  return loadNativeBoundReadAddon();
}

export { stableNativePlatformKey };
