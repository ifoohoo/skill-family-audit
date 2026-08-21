import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import {
  acquireFilesystemLock,
  releaseFilesystemLock,
} from "./token-lock.mjs";
import {
  appendEvent,
  closeStateStore,
  openStateStore,
  readEvents,
} from "./state-store.mjs";

/**
 * Generic usage ledger with a consumer-configured upper bound.
 *
 * The guard reuses the durable state-store (append-only event ledger, hash
 * chain, snapshot mechanism) and the non-blocking token-lock (explicit
 * occupancy marker). The consumer injects everything semantic: the event
 * payload schemas, a pure reducer mapping events to a non-negative usage
 * total, and the upper bound. Foundation validates ordering, digests and
 * schemas through the state-store and fails closed when the projected total
 * would exceed the consumer's bound — the over-limit event is never
 * written.
 *
 * Boundary: this module embeds no consumer cost vocabulary and no fixed
 * amount anywhere — upperBound, the reducer and the payload schemas are all
 * consumer parameters.
 */

function assertGuard(guard) {
  if (!guard || guard.__usageGuard !== true) {
    throw new TypeError("expected a usage guard handle");
  }
}

function assertTotal(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("usage reducer must return a non-negative safe integer total");
  }
}

function fold(records, reducer, initial) {
  let total = initial;
  for (const record of records) {
    total = reducer(total, record);
    assertTotal(total);
  }
  return total;
}

/**
 * Opens a usage guard. Acquires the explicit token-lock first (fail-closed:
 * an already-held lock surfaces as STORE_LOCKED and no state store is
 * created), then opens the event ledger. lockRoot/lockPath address the
 * occupancy marker and must be chosen by the consumer outside the state
 * store root.
 */
export async function openUsageGuard({
  stateRoot,
  owner,
  payloadSchemas,
  reducer,
  initial = 0,
  upperBound,
  lockRoot,
  lockPath,
  clock,
} = {}) {
  if (typeof reducer !== "function") {
    throw new TypeError("openUsageGuard: reducer must be a pure function mapping events to a usage total");
  }
  assertTotal(initial);
  if (!Number.isSafeInteger(upperBound) || upperBound < 0) {
    throw new TypeError("openUsageGuard: upperBound must be a non-negative safe integer");
  }
  const lock = await acquireFilesystemLock(lockRoot, lockPath, { owner });
  let store;
  try {
    store = await openStateStore(stateRoot, { owner, payloadSchemas, clock });
  } catch (cause) {
    await releaseFilesystemLock(lock).catch(() => {});
    throw cause;
  }
  return Object.freeze({ __usageGuard: true, store, lock, reducer, initial, upperBound });
}

/**
 * Appends one usage event. Ordering, digest-chain and envelope-schema
 * validation run first (state-store), then the guard folds the prospective
 * record through the consumer reducer and refuses the append when the
 * projected total exceeds the consumer's upper bound. The over-limit event
 * is not written.
 */
export async function appendUsageEvent(guard, event, { beforeCommit } = {}) {
  assertGuard(guard);
  if (beforeCommit !== undefined && typeof beforeCommit !== "function") {
    throw new TypeError("appendUsageEvent: beforeCommit must be a function or undefined");
  }
  return appendEvent(guard.store, event, {
    beforeCommit: async ({ record, events }) => {
      const projected = fold([...events, record], guard.reducer, guard.initial);
      if (projected > guard.upperBound) {
        throw mechanismError(
          HARNESS_ERROR_KINDS.UPPER_BOUND_EXCEEDED,
          "usage would exceed the consumer-configured upper bound",
          {
            upperBound: guard.upperBound,
            projected,
            eventType: record.eventType,
            sequence: record.sequence,
          },
        );
      }
      if (beforeCommit !== undefined) {
        await beforeCommit({ record, events, projected });
      }
    },
  });
}

/** Read-only current usage total derived from the authoritative event ledger. */
export async function readUsage(guard) {
  assertGuard(guard);
  const events = await readEvents(guard.store);
  return fold(events, guard.reducer, guard.initial);
}

/** Closes the ledger, then releases the explicit occupancy lock. */
export async function closeUsageGuard(guard) {
  assertGuard(guard);
  await closeStateStore(guard.store);
  await releaseFilesystemLock(guard.lock);
  return Object.freeze({ closed: true });
}
