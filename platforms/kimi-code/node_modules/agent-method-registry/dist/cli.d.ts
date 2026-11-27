import { D as Diagnostic } from './codes-DJ-T-zoi.js';

interface ParsedArgs {
    command: string | undefined;
    positional: string[];
    flags: Record<string, string[]>;
}
declare function parseArgs(argv: string[]): ParsedArgs;
declare function hasFlag(parsed: ParsedArgs, name: string): boolean;
declare function getFlag(parsed: ParsedArgs, name: string): string | undefined;
declare function getAllFlags(parsed: ParsedArgs, name: string): string[];
interface Envelope {
    ok: boolean;
    data?: unknown;
    diagnostics: Diagnostic[];
}
declare class ExitError extends Error {
    readonly exitCode: number;
    constructor(exitCode: number);
}
declare function emit(envelope: Envelope, exitCode: number): never;
declare function readInput(filePath: string): {
    ok: true;
    data: unknown;
} | {
    ok: false;
    diagnostics: Diagnostic[];
};
declare function writeOutput(filePath: string, data: unknown): {
    ok: true;
} | {
    ok: false;
    diagnostics: Diagnostic[];
};
declare function run(argv: string[]): void;

export { ExitError, type ParsedArgs, emit, getAllFlags, getFlag, hasFlag, parseArgs, readInput, run, writeOutput };
