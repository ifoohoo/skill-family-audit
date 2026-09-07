import { loadNativeBoundReadAddon } from "./native/loader.mjs";

export async function loadNativeAddon() {
  return loadNativeBoundReadAddon();
}
