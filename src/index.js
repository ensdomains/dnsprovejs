"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
exports.__esModule = true;
exports.SignedSet = exports.ResponseCodeError = exports.NoValidDnskeyError = exports.NoValidDsError = exports.DNSProver = exports.dohQuery = exports.DEFAULT_TRUST_ANCHORS = exports.DEFAULT_DIGESTS = exports.DEFAULT_ALGORITHMS = void 0;
var prove_1 = require("./prove");
__createBinding(exports, prove_1, "DEFAULT_ALGORITHMS");
__createBinding(exports, prove_1, "DEFAULT_DIGESTS");
__createBinding(exports, prove_1, "DEFAULT_TRUST_ANCHORS");
__createBinding(exports, prove_1, "dohQuery");
__createBinding(exports, prove_1, "DNSProver");
__createBinding(exports, prove_1, "NoValidDsError");
__createBinding(exports, prove_1, "NoValidDnskeyError");
__createBinding(exports, prove_1, "ResponseCodeError");
__createBinding(exports, prove_1, "SignedSet");
