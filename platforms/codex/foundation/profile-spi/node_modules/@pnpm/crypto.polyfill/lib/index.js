"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hash = void 0;
const crypto_1 = __importDefault(require("crypto"));
exports.hash = 
// @ts-expect-error -- crypto.hash is supported in Node 21.7.0+, 20.12.0+
crypto_1.default.hash ??
    ((algorithm, data, outputEncoding) => crypto_1.default.createHash(algorithm).update(data).digest(outputEncoding));
//# sourceMappingURL=index.js.map