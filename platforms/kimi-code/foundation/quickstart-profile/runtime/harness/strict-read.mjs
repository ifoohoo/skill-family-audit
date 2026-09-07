import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { resolveContained } from "./paths.mjs";

/**
 * Strict contained read (FG-1).
 *
 * readFileStrict is the read-side twin of the strict write path: it reads one
 * existing authority file through the containment layer and proves, in order,
 *
 *   1. containment       — resolveContained rejects traversal and escape
 *                          classes before any read;
 *   2. no-follow         — a symbolic-link target is refused outright (even
 *                          when it resolves inside the root), and the file is
 *                          opened with O_NOFOLLOW so a link swapped in after
 *                          the identity check can never be followed;
 *   3. regular identity  — the target must be one ordinary file; the handle
 *                          opened for reading is re-statted and compared
 *                          against the pre-open identity (dev/ino);
 *   4. digest receipt    — the returned receipt carries the sha256 of the
 *                          exact bytes that were read, so a consumer can
 *                          recompute and bind the read without trusting the
 *                          transport.
 *
 * When the consumer already holds a frozen digest (an approval authority, a
 * frozen plan), pass expectedSha256: any difference fails closed with the
 * stable content-guard-rejected kind and the content is not delivered.
 */

const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

/**
 * Strictly reads one contained regular file.
 *
 * @param {string} root     workspace root directory.
 * @param {string} relPath  contained relative path.
 * @param {object} [options]
 * @param {"utf8"} [options.encoding]        decode content as a utf8 string;
 *                                           Buffer content when omitted. No
 *                                           other encoding is accepted.
 * @param {string} [options.expectedSha256]  frozen lowercase sha256 hex digest
 *                                           the read bytes must match.
 * @returns {Promise<{path: string, content: Buffer|string, sha256: string, bytes: number, mode: number}>}
 *          frozen receipt emitted after the read; `sha256` is the digest of
 *          exactly the bytes returned in `content`.
 */
export async function readFileStrict(root, relPath, { encoding, expectedSha256 } = {}) {
  if (encoding !== undefined && encoding !== "utf8") {
    throw new TypeError('readFileStrict: encoding must be "utf8" or undefined');
  }
  if (expectedSha256 !== undefined && (typeof expectedSha256 !== "string" || !SHA256_HEX_PATTERN.test(expectedSha256))) {
    throw new TypeError("readFileStrict: expectedSha256 must be a lowercase sha256 hex digest");
  }

  const target = await resolveContained(root, relPath);

  let before;
  try {
    before = await lstat(target);
  } catch (cause) {
    if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.MISSING_RESOURCE,
        "strict read target does not exist",
        { input: relPath },
      );
    }
    throw mechanismError(
      HARNESS_ERROR_KINDS.READ_FAILED,
      `strict read cannot inspect the target: ${cause?.code ?? "unknown"}`,
      { input: relPath },
    );
  }
  if (before.isSymbolicLink()) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      "strict read refuses a symbolic-link target (no-follow)",
      { input: relPath },
    );
  }
  if (!before.isFile()) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.READ_FAILED,
      "strict read requires one ordinary file",
      { input: relPath, actual: before.isDirectory() ? "directory" : "special" },
    );
  }

  const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  let handle;
  try {
    handle = await open(target, FS_CONSTANTS.O_RDONLY | noFollow);
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.MISSING_RESOURCE,
        "strict read target disappeared before open",
        { input: relPath },
      );
    }
    if (cause?.code === "ELOOP") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
        "strict read target became a symbolic link before open (no-follow)",
        { input: relPath },
      );
    }
    throw mechanismError(
      HARNESS_ERROR_KINDS.READ_FAILED,
      `strict read failed to open the target: ${cause?.code ?? "unknown"}`,
      { input: relPath },
    );
  }
  try {
    const opened = await handle.stat();
    if (!sameIdentity(before, opened) || !opened.isFile()) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
        "strict read target identity changed during inspection",
        { input: relPath },
      );
    }
    const bytes = await handle.readFile();
    const sha256 = digestBytes(bytes);
    if (expectedSha256 !== undefined && sha256 !== expectedSha256) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.CONTENT_GUARD_REJECTED,
        "strict read digest differs from the expected frozen digest",
        { input: relPath, expectedSha256, actualSha256: sha256 },
      );
    }
    return Object.freeze({
      path: target,
      content: encoding === "utf8" ? bytes.toString("utf8") : bytes,
      sha256,
      bytes: bytes.length,
      mode: opened.mode & 0o7777,
    });
  } finally {
    await handle.close();
  }
}
