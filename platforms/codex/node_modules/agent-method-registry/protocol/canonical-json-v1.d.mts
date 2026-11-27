export function cloneStrictJsonData<T>(value: T, ancestors?: readonly object[]): T;
export function validateJsonSafe(value: unknown): void;
export function canonicalizeJson(value: unknown): unknown;
export function canonicalStringify(value: unknown): string;
