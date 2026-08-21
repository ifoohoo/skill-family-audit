"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createShortHash = createShortHash;
exports.createHexHash = createHexHash;
exports.createHash = createHash;
exports.createHashFromMultipleFiles = createHashFromMultipleFiles;
exports.createHashFromFile = createHashFromFile;
exports.createHexHashFromFile = createHexHashFromFile;
exports.getTarballIntegrity = getTarballIntegrity;
const crypto = __importStar(require("@pnpm/crypto.polyfill"));
const fs_1 = __importDefault(require("fs"));
const graceful_fs_1 = __importDefault(require("@pnpm/graceful-fs"));
const ssri_1 = __importDefault(require("ssri"));
function createShortHash(input) {
    return createHexHash(input).substring(0, 32);
}
function createHexHash(input) {
    return crypto.hash('sha256', input, 'hex');
}
function createHash(input) {
    return `sha256-${crypto.hash('sha256', input, 'base64')}`;
}
async function createHashFromMultipleFiles(files) {
    if (files.length === 1) {
        return createHashFromFile(files[0]);
    }
    const hashes = await Promise.all(files.map(createHashFromFile));
    return createHash(hashes.join(','));
}
async function createHashFromFile(file) {
    return createHash(await readNormalizedFile(file));
}
async function createHexHashFromFile(file) {
    return createHexHash(await readNormalizedFile(file));
}
async function readNormalizedFile(file) {
    const content = await fs_1.default.promises.readFile(file, 'utf8');
    return content.split('\r\n').join('\n');
}
async function getTarballIntegrity(filename) {
    return (await ssri_1.default.fromStream(graceful_fs_1.default.createReadStream(filename))).toString();
}
//# sourceMappingURL=index.js.map