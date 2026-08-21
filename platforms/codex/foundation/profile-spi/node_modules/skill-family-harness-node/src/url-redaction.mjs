/**
 * Generic URL credential redaction (FG-2).
 *
 * Values that may embed userinfo credentials (registry URLs, git remotes,
 * webhook endpoints) must pass through redactUrlCredentials before they are
 * written to disk or logs.
 *
 * Contract:
 *  - Parsing is delegated to the standard WHATWG URL; no bespoke parser.
 *  - Parseable input (string or URL instance) is re-serialized WITHOUT its
 *    username/password. The output is the canonical WHATWG serialization, so
 *    byte-level normalization (scheme/host casing, default ports) may differ
 *    from the input; only the credential surface is semantically removed.
 *  - Anything that cannot be parsed as an absolute URL degrades to the fixed
 *    opaque REDACTED_URL_PLACEHOLDER. The original input is NEVER returned
 *    on the degraded path, because an unparseable string cannot be proven
 *    credential-free. The placeholder contains no '@', ':' or '/' so it can
 *    never be mistaken for an authority-bearing URL.
 *  - The function is pure and total: no IO, no throws for non-URL input.
 */

export const REDACTED_URL_PLACEHOLDER = "[redacted-url]";

/**
 * Removes userinfo credentials from one URL value.
 *
 * @param {string|URL|*} value  a URL string or URL instance; any other
 *                              input degrades to the opaque placeholder.
 * @returns {string} the credential-free URL serialization, or
 *                   REDACTED_URL_PLACEHOLDER when the input cannot be
 *                   proven credential-free.
 */
export function redactUrlCredentials(value) {
  let url;
  if (value instanceof URL) {
    // Copy first: the caller's instance is never mutated.
    url = new URL(value.href);
  } else if (typeof value === "string") {
    try {
      url = new URL(value);
    } catch {
      // Unparseable: cannot be proven credential-free. Safe degradation is a
      // fixed opaque placeholder, never the original string.
      return REDACTED_URL_PLACEHOLDER;
    }
  } else {
    return REDACTED_URL_PLACEHOLDER;
  }
  // WHATWG setters remove the userinfo components; for URL states that
  // cannot carry userinfo they are no-ops, and the serialization cannot
  // contain credentials either way.
  url.username = "";
  url.password = "";
  return url.href;
}
