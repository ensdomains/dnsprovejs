import * as packet from 'dns-packet'
import * as packet_types from 'dns-packet/types'
import {sha256} from 'ethereumjs-util'
import {logger} from './log'
import fetch from 'node-fetch';

export const DEFAULT_TRUST_ANCHORS: packet.Ds[] = [
    {
        name: '.',
        type: 'DS',
        class: 'IN',
        data: {
          keyTag: 19036,
          algorithm: 8,
          digestType: 2,
          digest: Buffer.from(
            '49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5',
            'hex'
          )
        }
      },
      {
        name: '.',
        type: 'DS',
        class: 'IN',
        data: {
          keyTag: 20326,
          algorithm: 8,
          digestType: 2,
          digest: Buffer.from(
            'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
            'hex'
          )
        }
      },
];

function encodeURLParams(p: {[key:string]:string}): string {
    return Object.entries(p).map(kv => kv.map(encodeURIComponent).join("=")).join("&");
}

export function getKeyTag(key: packet.Dnskey): number {
  const data = packet.dnskey.encode(key.data).slice(2);
  let keytag = 0;
  for (var i = 0; i < data.length; i++) {
    var v = data[i];
    if((i & 1) !== 0) {
      keytag += v;
    } else {
      keytag += v << 8;
    }
  }
  keytag += (keytag >> 16) & 0xffff;
  keytag &= 0xffff;
  return keytag;
}

export function answersToString(a: packet.Answer[]): string {
    const s = a.map((a) => {
        const prefix = `${a.name} ${a.ttl} ${a.class} ${a.type}`
        const d = a.data;
        switch(a.type) {
            case 'A':
                return `${prefix} ${d}`;
            case 'DNSKEY':
                return `${prefix} ${d.flags} 3 ${d.algorithm} ${d.key.toString('base64')}; keyTag=${getKeyTag(a)}`;
            case 'DS':
                return `${prefix} ${d.keyTag} ${d.algorithm} ${d.digestType} ${d.digest.toString('hex')}`;
            case 'OPT':
                return `${prefix}`;
            case 'RRSIG':
                return `${prefix} ${d.typeCovered} ${d.algorithm} ${d.labels} ${d.originalTTL} ${d.expiration} ${d.inception} ${d.keyTag} ${d.signersName} ${d.signature.toString('base64')}`;
            case 'TXT':
                const texts = d.map((t: string) => `"${t}"`);
                return `${prefix} ${texts.join(' ')}`;
        }
    });
    return s.join('\n');
}

export function dohQuery(url: string) {
    return async function getDNS(q: packet.Packet): Promise<packet.Packet> {
        const buf = packet.encode(q);
        const response = await fetch(url + "?" + encodeURLParams({
            ct: "application/dns-udpwireformat",
            dns: buf.toString('base64'),
            ts: Date.now().toString(),
        }));
        return packet.decode(Buffer.from(await response.arrayBuffer()));
    }
}

export class SignedSet<T extends packet.Answer> {
    records: T[];
    signature: packet.Rrsig;

    constructor(records: T[], signature: packet.Rrsig) {
        this.records = records;
        this.signature = signature;
    }

    static fromWire<T extends packet.Answer>(data: Buffer, signatureData: Buffer): SignedSet<T> {
        const {rdata, length} = this.readRrsigRdata(data);
        rdata.signature = signatureData;

        const rrs = [];
        let off = length;
        while(off < data.length) {
            rrs.push(packet.answer.decode(data, off));
            off += packet.answer.decode.bytes;
        }

        return new SignedSet<T>(rrs, {
            name: rrs[0].name,
            type: 'RRSIG',
            class: rrs[0].class,
            data: rdata
        });
    }

    private static readRrsigRdata(data: Buffer): {rdata: packet.Rrsig['data'], length: number} {
        let offset = 0;
        return {
            rdata: {
                typeCovered: packet_types.toString(data.readUInt16BE(0)),
                algorithm: data.readUInt8(2),
                labels: data.readUInt8(3),
                originalTTL: data.readUInt32BE(4),
                expiration: data.readUInt32BE(8),
                inception: data.readUInt32BE(12),
                keyTag: data.readUInt16BE(16),
                signersName: packet.name.decode(data, 18),
                signature: Buffer.of(),
            },
            length: 18 + packet.name.decode.bytes,
        };
    }

    toWire(withRrsig: boolean = true): Buffer {
        let rrset = Buffer.concat(this.records
            // https://tools.ietf.org/html/rfc4034#section-6
            .sort((a, b) => {
                const aenc = packet.record(a.type).encode(a.data).slice(2);
                const benc = packet.record(b.type).encode(b.data).slice(2);
                return aenc.compare(benc);
            })
            .map(r => packet.answer.encode(Object.assign(r, {
                name: r.name.toLowerCase(), // (2)
                ttl: this.signature.data.originalTTL // (5)
            }))));
        if(withRrsig) {
            let rrsig = packet.rrsig.encode(Object.assign({}, this.signature.data, { signature: Buffer.of()})).slice(2);
            return Buffer.concat([rrsig, rrset]);
        } else {
            return rrset;
        }
    }
}

export interface ProvableAnswer<T extends packet.Answer> {
    answer: SignedSet<T>;
    proofs: SignedSet<packet.Dnskey|packet.Ds>[];
}

export class ResponseCodeError extends Error {
    query: packet.Packet;
    response: packet.Packet;

    constructor(query: packet.Packet, response: packet.Packet) {
        super("DNS server responded with " + response.rcode);
        this.name = 'ResponseError';
        this.query = query;
        this.response = response;
    }
}

export class NoValidDsError extends Error {
    keys: packet.Dnskey[];

    constructor(keys: packet.Dnskey[]) {
        super(`Could not find a DS record to validate any RRSIG on DNSKEY records for ${keys[0].name}`);
        this.keys = keys;
        this.name = 'NoValidDsError';
    }
}

export class NoValidDnskeyError<T extends packet.Answer> extends Error {
    result: T[];

    constructor(result: T[]) {
        super(`Could not find a DNSKEY record to validate any RRSIG on ${result[0].type} records for ${result[0].name}`)
        this.result = result;
        this.name = 'NoValidDnskeyError';
    }
}

export const DEFAULT_DIGESTS = {
    // SHA256
    1: {
        name: 'SHA1',
        f: (data: Buffer, digest: Buffer) => {
            return true;
        },
    },
    2: {
        name: 'SHA256',
        f: (data: Buffer, digest: Buffer) => {
            return sha256(data).equals(digest);
        },
    },
};

export const DEFAULT_ALGORITHMS = {
    5: {
        name: 'RSASHA1Algorithm',
        f: (key: Buffer, data: Buffer, sig: Buffer) => {
            return true;
        },
    },
    7: {
        name: 'RSASHA1Algorithm',
        f: (key: Buffer, data: Buffer, sig: Buffer) => {
            return true;
        },
    },
    8: {
        name: 'RSASHA256',
        f: (key: Buffer, data: Buffer, sig: Buffer) => {
            return true;
        },
    },
    13: {
        name: 'P256SHA256',
        f: (key: Buffer, data: Buffer, sig: Buffer) => {
            return true;
        },
    },
};

function isTypedArray<T extends packet.Answer['type']>(array: packet.Answer[]): array is Extract<packet.Answer, {type: T}>[] {
    return array.every((a) => a.type == 'DNSKEY');
}

function makeIndex<T>(values: T[], fn: (value: T)=>number): {[key: number]: T[]} {
    const ret: {[key: number]: T[]} = {};
    for(const value of values) {
        const key = fn(value);
        let list = ret[key];
        if(list === undefined) {
            list = ret[key] = [];
        }
        list.push(value);
    }
    return ret;
}

export class DNSProver {
    sendQuery: (q: packet.Packet) => Promise<packet.Packet>;
    digests: {[key: number]: {name: string, f: (data: Buffer, digest: Buffer) => boolean}};
    algorithms: {[key: number]: {name: string, f: (key: Buffer, data: Buffer, sig: Buffer) => boolean}};
    anchors: packet.Ds[];

    static create(url: string) {
        return new DNSProver(dohQuery(url));
    }

    constructor(sendQuery: (q: packet.Packet) => Promise<packet.Packet>, digests = DEFAULT_DIGESTS, algorithms = DEFAULT_ALGORITHMS, anchors = DEFAULT_TRUST_ANCHORS) {
        this.sendQuery = sendQuery;
        this.digests = digests;
        this.algorithms = algorithms;
        this.anchors = anchors;
    }

    async queryWithProof<T extends packet.Answer['type']>(qtype: T, qname: string): Promise<ProvableAnswer<Extract<packet.Answer,{type: T}>|null>> {
        return (new DNSQuery(this)).queryWithProof(qtype, qname);
    }
}

type AnswerSet = {[T in packet.Answer['type']]: ProvableAnswer<Extract<packet.Answer, {type: T}>>};

class DNSQuery {
    prover: DNSProver;
    cache: {[key: string]: {[key: string]: packet.Packet}} = {};

    constructor(prover: DNSProver) {
        this.prover = prover;
    }

    async queryWithProof<T extends packet.Answer['type']>(qtype: T, qname: string): Promise<ProvableAnswer<Extract<packet.Answer,{type: T}>|null>> {
        const response = await this.dnsQuery(qtype.toString(), qname);
        const answers = response.answers.filter(
            (r): r is Extract<packet.Answer,{type: T}> => r.type === qtype && r.name === qname);
        logger.info(`Found ${answers.length} ${qtype} records for ${qname}`);
        if(answers.length === 0) {
            return null;
        }

        const sigs = response.answers.filter((r): r is packet.Rrsig => r.type === 'RRSIG' && r.name === qname && r.data.typeCovered === qtype);
        logger.info(`Found ${sigs.length} RRSIGs over ${qtype} RRSET`);

        // If the records are self-signed, verify with DS records
        if(isTypedArray<'DNSKEY'>(answers) && sigs.some((sig) => sig.name === sig.data.signersName)) {
            logger.info(`DNSKEY RRSET on ${answers[0].name} is self-signed; attempting to verify with a DS in parent zone`);
            return this.verifyWithDS(answers, sigs) as any;
        } else {
            return this.verifyRRSet(answers, sigs);
        }
    }

    async verifyRRSet<T extends packet.Answer>(answers: T[], sigs: packet.Rrsig[]): Promise<ProvableAnswer<T>> {
        for(const sig of sigs) {
            const algorithms = this.prover.algorithms;
            logger.info(`Attempting to verify the ${answers[0].type} RRSET on ${answers[0].name} with RRSIG=${sig.data.keyTag}/${algorithms[sig.data.algorithm]?.name || sig.data.algorithm}`)
            const ss = new SignedSet(answers, sig);

            if(!(sig.data.algorithm in algorithms)) {
                logger.info(`Skipping RRSIG=${sig.data.keyTag}/${sig.data.algorithm} on ${answers[0].type} RRSET for ${answers[0].name}: Unknown algorithm`);
                continue;
            }

            const result = await this.queryWithProof('DNSKEY', sig.data.signersName);
            if(result === null) {
                throw new NoValidDnskeyError(answers);
            }
            const {answer, proofs} = result;
            for(const key of answer.records) {
                if(this.verifySignature(ss, key)) {
                    logger.info(`RRSIG=${sig.data.keyTag}/${algorithms[sig.data.algorithm].name} verifies the ${answers[0].type} RRSET on ${answers[0].name}`);
                    proofs.push(answer);
                    return {answer: ss, proofs: proofs};
                }
            }
        }
        logger.warn(`Could not verify the ${answers[0].type} RRSET on ${answers[0].name} with any RRSIGs`);
        throw new NoValidDnskeyError(answers);
    }

    async verifyWithDS(keys: packet.Dnskey[], sigs: packet.Rrsig[]): Promise<ProvableAnswer<packet.Dnskey>> {
        const keyname = keys[0].name;

        // Fetch the DS records to use
        let answer: packet.Ds[];
        let proofs: SignedSet<packet.Dnskey|packet.Ds>[];
        if(keyname === '.') {
            [answer, proofs] = [this.prover.anchors, []];
        } else {
            const response = await this.queryWithProof('DS', keyname);
            if(response === null) {
                throw new NoValidDsError(keys);
            }
            answer = response.answer.records;
            proofs = response.proofs;
            proofs.push(response.answer);
        }

        // Index the passed in keys by key tag
        const keysByTag = makeIndex(keys, getKeyTag);
        const sigsByTag = makeIndex(sigs, (sig) => sig.data.keyTag);

        // Iterate over the DS records looking for keys we can verify
        const algorithms = this.prover.algorithms;
        const digests = this.prover.digests;
        for(let ds of answer) {
            for(let key of keysByTag[ds.data.keyTag] || []) {
                if(this.checkDs(ds, key)) {
                    logger.info(`DS=${ds.data.keyTag}/${algorithms[ds.data.algorithm]?.name || ds.data.algorithm}/${digests[ds.data.digestType].name} verifies DNSKEY=${ds.data.keyTag}/${algorithms[key.data.algorithm]?.name || key.data.algorithm} on ${key.name}`);
                    for(let sig of sigsByTag[ds.data.keyTag] || []) {
                        const ss = new SignedSet(keys, sig);
                        if(this.verifySignature(ss, key)) {
                            logger.info(`RRSIG=${sig.data.keyTag}/${algorithms[sig.data.algorithm].name} verifies the DNSKEY RRSET on ${keys[0].name}`);
                            return {answer: ss, proofs: proofs};
                        }
                    }
                }
            }
        }

        logger.warn(`Could not find any DS records to verify the DNSKEY RRSET on ${keys[0].name}`);
        throw new NoValidDsError(keys);
    }

    verifySignature<T extends packet.Answer>(answer: SignedSet<T>, key: packet.Dnskey): boolean {
        const keyTag = getKeyTag(key);
        if(key.data.algorithm != answer.signature.data.algorithm || keyTag != answer.signature.data.keyTag || key.name != answer.signature.data.signersName) {
            return false;
        }
        const signatureAlgorithm = this.prover.algorithms[key.data.algorithm];
        if(signatureAlgorithm === undefined) {
            logger.warn(`Unrecognised signature algorithm for DNSKEY=${keyTag}/${key.data.algorithm} on ${key.name}`);
            return false;
        }
        return signatureAlgorithm.f(key.data.key, answer.toWire(), answer.signature.data.signature);
    }

    checkDs(ds: packet.Ds, key: packet.Dnskey): boolean {
        if(key.data.algorithm != ds.data.algorithm || key.name != ds.name) {
            return false;
        }
        const data = Buffer.concat([
            packet.name.encode(ds.name),
            packet.dnskey.encode(key.data).slice(2)
        ]);
        const digestAlgorithm = this.prover.digests[ds.data.digestType];
        if(digestAlgorithm === undefined) {
            logger.warn(`Unrecognised digest type for DS=${ds.data.keyTag}/${ds.data.digestType}/${this.prover.algorithms[ds.data.algorithm]?.name || ds.data.algorithm} on ${ds.name}`)
            return false;
        }
        return digestAlgorithm.f(data, ds.data.digest);
    }

    async dnsQuery(qtype: string, qname: string): Promise<packet.Packet> {
        const query: packet.Packet = {
            type: 'query',
            id: 1,
            flags: packet.RECURSION_DESIRED,
            questions: [
                {
                    type: qtype,
                    class: 'IN',
                    name: qname,
                },
            ],
            additionals: [
                {
                    type: 'OPT',
                    class: 'IN',
                    name: '.',
                    udpPayloadSize: 4096,
                    flags: packet.DNSSEC_OK,
                },
            ],
            answers: [],
        };
        if(this.cache[qname]?.[qtype] === undefined) {
            if(this.cache[qname] === undefined) {
                this.cache[qname] = {};
            }
            this.cache[qname][qtype] = await this.prover.sendQuery(query);
        }
        const response = this.cache[qname][qtype];
        logger.info(`Query[${qname} ${qtype}]:\n` + answersToString(response.answers));
        if(response.rcode !== 'NOERROR') {
            throw new ResponseCodeError(query, response);
        }
        return response;
    }
}
