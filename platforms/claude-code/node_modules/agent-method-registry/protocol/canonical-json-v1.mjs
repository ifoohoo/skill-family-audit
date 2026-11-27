// Canonical JSON v1 — authoritative, dependency-free protocol implementation.
// Consumers may import this public subpath or ship an exact generated snapshot.
import { runInNewContext } from 'node:vm';
import { types as utilTypes } from 'node:util';

const primordials = runInNewContext(`({
  getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
  getPrototypeOf: Object.getPrototypeOf,
  ownKeys: Reflect.ownKeys,
  isArray: Array.isArray,
  isFinite: Number.isFinite,
  isInteger: Number.isInteger
})`);
const objectPrototype = primordials.getPrototypeOf({});
const arrayPrototype = primordials.getPrototypeOf([]);
const bannedPrototypes = new Map([
  [Date.prototype, 'Date'],
  [RegExp.prototype, 'RegExp'],
  [Map.prototype, 'Map'],
  [Set.prototype, 'Set'],
  [WeakMap.prototype, 'WeakMap'],
  [WeakSet.prototype, 'WeakSet'],
  [Promise.prototype, 'Promise'],
  [Error.prototype, 'Error'],
]);

function nextAncestors(ancestors, value) {
  const next = new Array(ancestors.length + 1);
  for (let index = 0; index < ancestors.length; index += 1) next[index] = ancestors[index];
  next[ancestors.length] = value;
  return next;
}

function isArrayIndex(key, length) {
  if (key === '') return false;
  const numeric = Number(key);
  return primordials.isInteger(numeric) && numeric >= 0 && numeric < length && String(numeric) === key;
}

export function cloneStrictJsonData(value, ancestors = []) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!primordials.isFinite(value)) throw new TypeError(`Canonical JSON rejects ${String(value)}`);
    return value;
  }
  if (typeof value !== 'object') {
    const label = typeof value === 'bigint' ? 'BigInt'
      : typeof value === 'symbol' ? 'Symbol'
        : typeof value === 'function' ? 'function'
          : 'undefined';
    throw new TypeError(`Canonical JSON rejects ${label}`);
  }

  if (utilTypes.isProxy(value)) throw new TypeError('Proxy value rejected');
  for (let index = 0; index < ancestors.length; index += 1) {
    if (ancestors[index] === value) throw new TypeError('circular reference rejected');
  }

  const isArray = primordials.isArray(value);
  const prototype = primordials.getPrototypeOf(value);
  if (prototype !== (isArray ? arrayPrototype : objectPrototype) && !(prototype === null && !isArray)) {
    const banned = bannedPrototypes.get(prototype);
    if (banned) throw new TypeError(`Canonical JSON rejects ${banned}`);
    throw new TypeError('custom prototype rejected');
  }

  const keys = primordials.ownKeys(value);
  for (const key of keys) {
    if (typeof key === 'symbol') throw new TypeError('symbol-keyed property rejected');
  }

  const next = nextAncestors(ancestors, value);
  if (isArray) {
    const lengthDescriptor = primordials.getOwnPropertyDescriptor(value, 'length');
    if (!lengthDescriptor || !('value' in lengthDescriptor) || !primordials.isInteger(lengthDescriptor.value)) {
      throw new TypeError('invalid array length rejected');
    }
    const length = lengthDescriptor.value;
    const output = new Array(length);
    for (let index = 0; index < length; index += 1) {
      const descriptor = primordials.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) {
        throw new TypeError('sparse array or accessor element rejected');
      }
      output[index] = cloneStrictJsonData(descriptor.value, next);
    }
    for (const key of keys) {
      if (key !== 'length' && !isArrayIndex(key, length)) {
        throw new TypeError('extra array property rejected');
      }
    }
    return output;
  }

  const output = Object.create(null);
  for (const key of keys) {
    const descriptor = primordials.getOwnPropertyDescriptor(value, key);
    if (!descriptor) throw new TypeError(`missing property descriptor "${key}" rejected`);
    if (!('value' in descriptor)) {
      throw new TypeError(`accessor property "${key}" rejected`);
    }
    if (descriptor.enumerable !== true) {
      throw new TypeError(`non-enumerable field "${key}" rejected`);
    }
    output[key] = cloneStrictJsonData(descriptor.value, next);
  }
  return output;
}

export function validateJsonSafe(value) {
  cloneStrictJsonData(value);
}

function sortObjectKeys(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sortObjectKeys);
  const output = Object.create(null);
  for (const key of Object.keys(value).sort()) output[key] = sortObjectKeys(value[key]);
  return output;
}

export function canonicalizeJson(value) {
  return sortObjectKeys(cloneStrictJsonData(value));
}

export function canonicalStringify(value) {
  return JSON.stringify(canonicalizeJson(value));
}
