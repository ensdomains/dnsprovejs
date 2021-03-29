"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.DNSProver = exports.DEFAULT_ALGORITHMS = exports.DEFAULT_DIGESTS = exports.NoValidDnskeyError = exports.NoValidDsError = exports.ResponseCodeError = exports.SignedSet = exports.dohQuery = exports.answersToString = exports.getKeyTag = exports.DEFAULT_TRUST_ANCHORS = void 0;
var packet = require("dns-packet");
var packet_types = require("dns-packet/types");
var ethereumjs_util_1 = require("ethereumjs-util");
var log_1 = require("./log");
var node_fetch_1 = require("node-fetch");
exports.DEFAULT_TRUST_ANCHORS = [
    {
        name: '.',
        type: 'DS',
        "class": 'IN',
        data: {
            keyTag: 19036,
            algorithm: 8,
            digestType: 2,
            digest: Buffer.from('49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5', 'hex')
        }
    },
    {
        name: '.',
        type: 'DS',
        "class": 'IN',
        data: {
            keyTag: 20326,
            algorithm: 8,
            digestType: 2,
            digest: Buffer.from('E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D', 'hex')
        }
    },
];
function encodeURLParams(p) {
    return Object.entries(p).map(function (kv) { return kv.map(encodeURIComponent).join("="); }).join("&");
}
function getKeyTag(key) {
    var data = packet.dnskey.encode(key.data).slice(2);
    var keytag = 0;
    for (var i = 0; i < data.length; i++) {
        var v = data[i];
        if ((i & 1) !== 0) {
            keytag += v;
        }
        else {
            keytag += v << 8;
        }
    }
    keytag += (keytag >> 16) & 0xffff;
    keytag &= 0xffff;
    return keytag;
}
exports.getKeyTag = getKeyTag;
function answersToString(a) {
    var s = a.map(function (a) {
        var prefix = a.name + " " + a.ttl + " " + a["class"] + " " + a.type;
        var d = a.data;
        switch (a.type) {
            case 'A':
                return prefix + " " + d;
            case 'DNSKEY':
                return prefix + " " + d.flags + " 3 " + d.algorithm + " " + d.key.toString('base64') + "; keyTag=" + getKeyTag(a);
            case 'DS':
                return prefix + " " + d.keyTag + " " + d.algorithm + " " + d.digestType + " " + d.digest.toString('hex');
            case 'OPT':
                return "" + prefix;
            case 'RRSIG':
                return prefix + " " + d.typeCovered + " " + d.algorithm + " " + d.labels + " " + d.originalTTL + " " + d.expiration + " " + d.inception + " " + d.keyTag + " " + d.signersName + " " + d.signature.toString('base64');
            case 'TXT':
                var texts = d.map(function (t) { return "\"" + t + "\""; });
                return prefix + " " + texts.join(' ');
        }
    });
    return s.join('\n');
}
exports.answersToString = answersToString;
function dohQuery(url) {
    return function getDNS(q) {
        return __awaiter(this, void 0, void 0, function () {
            var buf, response, _a, _b, _c, _d;
            return __generator(this, function (_e) {
                switch (_e.label) {
                    case 0:
                        buf = packet.encode(q);
                        return [4 /*yield*/, node_fetch_1["default"](url + "?" + encodeURLParams({
                                ct: "application/dns-udpwireformat",
                                dns: buf.toString('base64'),
                                ts: Date.now().toString()
                            }))];
                    case 1:
                        response = _e.sent();
                        _b = (_a = packet).decode;
                        _d = (_c = Buffer).from;
                        return [4 /*yield*/, response.arrayBuffer()];
                    case 2: return [2 /*return*/, _b.apply(_a, [_d.apply(_c, [_e.sent()])])];
                }
            });
        });
    };
}
exports.dohQuery = dohQuery;
var SignedSet = /** @class */ (function () {
    function SignedSet(records, signature) {
        this.records = records;
        this.signature = signature;
    }
    SignedSet.fromWire = function (data, signatureData) {
        var rdata = this.readRrsigRdata(data);
        rdata.signature = signatureData;
        var rrs = [];
        var off = packet.rrsig.decode.bytes;
        while (off < data.length) {
            rrs.push(packet.answer.decode(data, off));
            off += packet.answer.decode.bytes;
        }
        return new SignedSet(rrs, {
            name: rrs[0].name,
            type: 'RRSIG',
            "class": rrs[0]["class"],
            data: rdata
        });
    };
    SignedSet.readRrsigRdata = function (data) {
        var offset = 0;
        return {
            typeCovered: packet_types.toString(data.readUInt16BE(0)),
            algorithm: data.readUInt8(2),
            labels: data.readUInt8(3),
            originalTTL: data.readUInt32BE(4),
            expiration: data.readUInt32BE(8),
            inception: data.readUInt32BE(12),
            keyTag: data.readUInt16BE(16),
            signersName: packet.name.decode(data, 18),
            signature: Buffer.of()
        };
    };
    SignedSet.prototype.toWire = function (withRrsig) {
        var _this = this;
        if (withRrsig === void 0) { withRrsig = true; }
        var rrset = Buffer.concat(this.records
            // https://tools.ietf.org/html/rfc4034#section-6
            .map(function (r) { return packet.answer.encode(Object.assign(r, {
            name: r.name.toLowerCase(),
            ttl: _this.signature.data.originalTTL // (5)
        })); })
            .sort(function (a, b) { return a.compare(b); }));
        if (withRrsig) {
            var rrsig = packet.rrsig.encode(Object.assign({}, this.signature.data, { signature: Buffer.of() })).slice(2);
            return Buffer.concat([rrsig, rrset]);
        }
        else {
            return rrset;
        }
    };
    return SignedSet;
}());
exports.SignedSet = SignedSet;
var ResponseCodeError = /** @class */ (function (_super) {
    __extends(ResponseCodeError, _super);
    function ResponseCodeError(query, response) {
        var _this = _super.call(this, "DNS server responded with " + response.rcode) || this;
        _this.name = 'ResponseError';
        _this.query = query;
        _this.response = response;
        return _this;
    }
    return ResponseCodeError;
}(Error));
exports.ResponseCodeError = ResponseCodeError;
var NoValidDsError = /** @class */ (function (_super) {
    __extends(NoValidDsError, _super);
    function NoValidDsError(keys) {
        var _this = _super.call(this, "Could not find a DS record to validate any RRSIG on DNSKEY records for " + keys[0].name) || this;
        _this.keys = keys;
        _this.name = 'NoValidDsError';
        return _this;
    }
    return NoValidDsError;
}(Error));
exports.NoValidDsError = NoValidDsError;
var NoValidDnskeyError = /** @class */ (function (_super) {
    __extends(NoValidDnskeyError, _super);
    function NoValidDnskeyError(result) {
        var _this = _super.call(this, "Could not find a DNSKEY record to validate any RRSIG on " + result[0].type + " records for " + result[0].name) || this;
        _this.result = result;
        _this.name = 'NoValidDnskeyError';
        return _this;
    }
    return NoValidDnskeyError;
}(Error));
exports.NoValidDnskeyError = NoValidDnskeyError;
exports.DEFAULT_DIGESTS = {
    // SHA256
    2: {
        name: 'SHA256',
        f: function (data, digest) {
            return ethereumjs_util_1.sha256(data).equals(digest);
        }
    }
};
exports.DEFAULT_ALGORITHMS = {
    // RSASHA256
    8: {
        name: 'RSASHA256',
        f: function (key, data, sig) {
            return true;
        }
    }
};
function isTypedArray(array) {
    return array.every(function (a) { return a.type == 'DNSKEY'; });
}
function makeIndex(values, fn) {
    var ret = {};
    for (var _i = 0, values_1 = values; _i < values_1.length; _i++) {
        var value = values_1[_i];
        var key = fn(value);
        var list = ret[key];
        if (list === undefined) {
            list = ret[key] = [];
        }
        list.push(value);
    }
    return ret;
}
var DNSProver = /** @class */ (function () {
    function DNSProver(sendQuery, digests, algorithms, anchors) {
        if (digests === void 0) { digests = exports.DEFAULT_DIGESTS; }
        if (algorithms === void 0) { algorithms = exports.DEFAULT_ALGORITHMS; }
        if (anchors === void 0) { anchors = exports.DEFAULT_TRUST_ANCHORS; }
        this.sendQuery = sendQuery;
        this.digests = digests;
        this.algorithms = algorithms;
        this.anchors = anchors;
    }
    DNSProver.create = function (url) {
        return new DNSProver(dohQuery(url));
    };
    DNSProver.prototype.queryWithProof = function (qtype, qname) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, (new DNSQuery(this)).queryWithProof(qtype, qname)];
            });
        });
    };
    return DNSProver;
}());
exports.DNSProver = DNSProver;
var DNSQuery = /** @class */ (function () {
    function DNSQuery(prover) {
        this.cache = {};
        this.prover = prover;
    }
    DNSQuery.prototype.queryWithProof = function (qtype, qname) {
        return __awaiter(this, void 0, void 0, function () {
            var response, answers, sigs;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.dnsQuery(qtype.toString(), qname)];
                    case 1:
                        response = _a.sent();
                        answers = response.answers.filter(function (r) { return r.type === qtype && r.name === qname; });
                        log_1.logger.info("Found " + answers.length + " " + qtype + " records for " + qname);
                        if (answers.length === 0) {
                            return [2 /*return*/, null];
                        }
                        sigs = response.answers.filter(function (r) { return r.type === 'RRSIG' && r.name === qname && r.data.typeCovered === qtype; });
                        log_1.logger.info("Found " + sigs.length + " RRSIGs over " + qtype + " RRSET");
                        // If the records are self-signed, verify with DS records
                        if (isTypedArray(answers) && sigs.some(function (sig) { return sig.name === sig.data.signersName; })) {
                            log_1.logger.info("DNSKEY RRSET on " + answers[0].name + " is self-signed; attempting to verify with a DS in parent zone");
                            return [2 /*return*/, this.verifyWithDS(answers, sigs)];
                        }
                        else {
                            return [2 /*return*/, this.verifyRRSet(answers, sigs)];
                        }
                        return [2 /*return*/];
                }
            });
        });
    };
    DNSQuery.prototype.verifyRRSet = function (answers, sigs) {
        var _a;
        return __awaiter(this, void 0, void 0, function () {
            var _i, sigs_1, sig, algorithms, ss, result, answer, proofs, _b, _c, key;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        _i = 0, sigs_1 = sigs;
                        _d.label = 1;
                    case 1:
                        if (!(_i < sigs_1.length)) return [3 /*break*/, 4];
                        sig = sigs_1[_i];
                        algorithms = this.prover.algorithms;
                        log_1.logger.info("Attempting to verify the " + answers[0].type + " RRSET on " + answers[0].name + " with RRSIG=" + sig.data.keyTag + "/" + (((_a = algorithms[sig.data.algorithm]) === null || _a === void 0 ? void 0 : _a.name) || sig.data.algorithm));
                        ss = new SignedSet(answers, sig);
                        if (!(sig.data.algorithm in algorithms)) {
                            log_1.logger.info("Skipping RRSIG=" + sig.data.keyTag + "/" + sig.data.algorithm + " on " + answers[0].type + " RRSET for " + answers[0].name + ": Unknown algorithm");
                            return [3 /*break*/, 3];
                        }
                        return [4 /*yield*/, this.queryWithProof('DNSKEY', sig.data.signersName)];
                    case 2:
                        result = _d.sent();
                        if (result === null) {
                            throw new NoValidDnskeyError(answers);
                        }
                        answer = result.answer, proofs = result.proofs;
                        for (_b = 0, _c = answer.records; _b < _c.length; _b++) {
                            key = _c[_b];
                            if (this.verifySignature(ss, key)) {
                                log_1.logger.info("RRSIG=" + sig.data.keyTag + "/" + algorithms[sig.data.algorithm].name + " verifies the " + answers[0].type + " RRSET on " + answers[0].name);
                                proofs.push(answer);
                                return [2 /*return*/, { answer: ss, proofs: proofs }];
                            }
                        }
                        _d.label = 3;
                    case 3:
                        _i++;
                        return [3 /*break*/, 1];
                    case 4:
                        log_1.logger.warn("Could not verify the " + answers[0].type + " RRSET on " + answers[0].name + " with any RRSIGs");
                        throw new NoValidDnskeyError(answers);
                }
            });
        });
    };
    DNSQuery.prototype.verifyWithDS = function (keys, sigs) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function () {
            var keyname, answer, proofs, response, keysByTag, sigsByTag, algorithms, digests, _i, answer_1, ds, _c, _d, key, _e, _f, sig, ss;
            var _g;
            return __generator(this, function (_h) {
                switch (_h.label) {
                    case 0:
                        keyname = keys[0].name;
                        if (!(keyname === '.')) return [3 /*break*/, 1];
                        _g = [this.prover.anchors, []], answer = _g[0], proofs = _g[1];
                        return [3 /*break*/, 3];
                    case 1: return [4 /*yield*/, this.queryWithProof('DS', keyname)];
                    case 2:
                        response = _h.sent();
                        if (response === null) {
                            throw new NoValidDsError(keys);
                        }
                        answer = response.answer.records;
                        proofs = response.proofs;
                        proofs.push(response.answer);
                        _h.label = 3;
                    case 3:
                        keysByTag = makeIndex(keys, getKeyTag);
                        sigsByTag = makeIndex(sigs, function (sig) { return sig.data.keyTag; });
                        algorithms = this.prover.algorithms;
                        digests = this.prover.digests;
                        for (_i = 0, answer_1 = answer; _i < answer_1.length; _i++) {
                            ds = answer_1[_i];
                            for (_c = 0, _d = keysByTag[ds.data.keyTag] || []; _c < _d.length; _c++) {
                                key = _d[_c];
                                if (this.checkDs(ds, key)) {
                                    log_1.logger.info("DS=" + ds.data.keyTag + "/" + (((_a = algorithms[ds.data.algorithm]) === null || _a === void 0 ? void 0 : _a.name) || ds.data.algorithm) + "/" + digests[ds.data.digestType].name + " verifies DNSKEY=" + ds.data.keyTag + "/" + (((_b = algorithms[key.data.algorithm]) === null || _b === void 0 ? void 0 : _b.name) || key.data.algorithm) + " on " + key.name);
                                    for (_e = 0, _f = sigsByTag[ds.data.keyTag] || []; _e < _f.length; _e++) {
                                        sig = _f[_e];
                                        ss = new SignedSet(keys, sig);
                                        if (this.verifySignature(ss, key)) {
                                            log_1.logger.info("RRSIG=" + sig.data.keyTag + "/" + algorithms[sig.data.algorithm].name + " verifies the DNSKEY RRSET on " + keys[0].name);
                                            return [2 /*return*/, { answer: ss, proofs: proofs }];
                                        }
                                    }
                                }
                            }
                        }
                        log_1.logger.warn("Could not find any DS records to verify the DNSKEY RRSET on " + keys[0].name);
                        throw new NoValidDsError(keys);
                }
            });
        });
    };
    DNSQuery.prototype.verifySignature = function (answer, key) {
        var keyTag = getKeyTag(key);
        if (key.data.algorithm != answer.signature.data.algorithm || keyTag != answer.signature.data.keyTag || key.name != answer.signature.data.signersName) {
            return false;
        }
        var signatureAlgorithm = this.prover.algorithms[key.data.algorithm];
        if (signatureAlgorithm === undefined) {
            log_1.logger.warn("Unrecognised signature algorithm for DNSKEY=" + keyTag + "/" + key.data.algorithm + " on " + key.name);
            return false;
        }
        return signatureAlgorithm.f(key.data.key, answer.toWire(), answer.signature.data.signature);
    };
    DNSQuery.prototype.checkDs = function (ds, key) {
        var _a;
        if (key.data.algorithm != ds.data.algorithm || key.name != ds.name) {
            return false;
        }
        var data = Buffer.concat([
            packet.name.encode(ds.name),
            packet.dnskey.encode(key.data).slice(2)
        ]);
        var digestAlgorithm = this.prover.digests[ds.data.digestType];
        if (digestAlgorithm === undefined) {
            log_1.logger.warn("Unrecognised digest type for DS=" + ds.data.keyTag + "/" + ds.data.digestType + "/" + (((_a = this.prover.algorithms[ds.data.algorithm]) === null || _a === void 0 ? void 0 : _a.name) || ds.data.algorithm) + " on " + ds.name);
            return false;
        }
        return digestAlgorithm.f(data, ds.data.digest);
    };
    DNSQuery.prototype.dnsQuery = function (qtype, qname) {
        var _a;
        return __awaiter(this, void 0, void 0, function () {
            var query, _b, _c, response;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        query = {
                            type: 'query',
                            id: 1,
                            flags: packet.RECURSION_DESIRED,
                            questions: [
                                {
                                    type: qtype,
                                    "class": 'IN',
                                    name: qname
                                },
                            ],
                            additionals: [
                                {
                                    type: 'OPT',
                                    "class": 'IN',
                                    name: '.',
                                    udpPayloadSize: 4096,
                                    flags: packet.DNSSEC_OK
                                },
                            ],
                            answers: []
                        };
                        if (!(((_a = this.cache[qname]) === null || _a === void 0 ? void 0 : _a[qtype]) === undefined)) return [3 /*break*/, 2];
                        if (this.cache[qname] === undefined) {
                            this.cache[qname] = {};
                        }
                        _b = this.cache[qname];
                        _c = qtype;
                        return [4 /*yield*/, this.prover.sendQuery(query)];
                    case 1:
                        _b[_c] = _d.sent();
                        _d.label = 2;
                    case 2:
                        response = this.cache[qname][qtype];
                        log_1.logger.info("Query[" + qname + " " + qtype + "]:\n" + answersToString(response.answers));
                        if (response.rcode !== 'NOERROR') {
                            throw new ResponseCodeError(query, response);
                        }
                        return [2 /*return*/, response];
                }
            });
        });
    };
    return DNSQuery;
}());
