import * as packet from 'dns-packet'
import {sha256} from 'ethereumjs-util'
import {logger} from './log'

export const DEFAULT_TRUST_ANCHORS: packet.Ds[] = [];

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

function getDNS(url: string) {
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

class SignedSet<T extends packet.Answer> {
    records: T[];
    signature: packet.Rrsig;

    constructor(records: T[], signature: packet.Rrsig) {
        this.records = records;
        this.signature = signature;
    }

    toWire(): Buffer {
        let rrsig = packet.rrsig.encode(Object.assign({}, this.signature.data, { signature: Buffer.of()}));
        let rrset = Buffer.concat(this.records
            // https://tools.ietf.org/html/rfc4034#section-6
            .map(r => packet.answer.encode(Object.assign(r, {
                name: r.name.toLowerCase(), // (2)
                ttl: this.signature.data.originalTTL // (5)
            })))
            .sort((a, b) => a.compare(b)));
        return Buffer.concat([rrsig, rrset]);
    }
}

interface ProvableAnswer<T extends packet.Answer> {
    answer: SignedSet<T>;
    proofs: SignedSet<packet.Dnskey|packet.Ds>[];
}

export class DNSError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'DNSError';
    }
}

export class ResponseCodeError extends DNSError {
    query: packet.Packet;
    response: packet.Packet;

    constructor(query: packet.Packet, response: packet.Packet) {
        super("DNS server responded with " + response.rcode);
        this.name = 'ResponseError';
        this.query = query;
        this.response = response;
    }
}

export const DEFAULT_DIGESTS = {
    // SHA256
    8: {
        name: 'SHA256',
        f: (data: Buffer, digest: Buffer) => {
            return sha256(data).equals(digest);
        },
    },
};

export const DEFAULT_ALGORITHMS = {
    // RSASHA256
    8: {
        name: 'RSASHA256',
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
        return new DNSProver(getDNS(url));
    }

    constructor(sendQuery: (q: packet.Packet) => Promise<packet.Packet>, digests = DEFAULT_DIGESTS, algorithms = DEFAULT_ALGORITHMS, anchors = DEFAULT_TRUST_ANCHORS) {
        this.sendQuery = sendQuery;
        this.digests = digests;
        this.algorithms = algorithms;
        this.anchors = anchors;
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

    async verifyRRSet<T extends packet.Answer>(answers: T[], sigs: packet.Rrsig[]): Promise<ProvableAnswer<T>|null> {
        for(const sig of sigs) {
            logger.info(`Attempting to verify the ${answers[0].type} RRSET on ${answers[0].name} with RRSIG=${sig.data.keyTag}/${this.algorithms[sig.data.algorithm]?.name || sig.data.algorithm}`)
            const ss = new SignedSet(answers, sig);

            if(!(sig.data.algorithm in this.algorithms)) {
                logger.info(`Skipping RRSIG=${sig.data.keyTag}/${sig.data.algorithm} on ${answers[0].type} RRSET for ${answers[0].name}: Unknown algorithm`);
                continue;
            }

            const {answer, proofs} = await this.queryWithProof('DNSKEY', sig.data.signersName);
            for(const key of answer.records) {
                if(this.verifySignature(ss, key)) {
                    logger.info(`RRSIG=${sig.data.keyTag}/${this.algorithms[sig.data.algorithm].name} verifies the ${answers[0].type} RRSET on ${answers[0].name}`);
                    proofs.push(answer);
                    return {answer: ss, proofs: proofs};
                }
            }
        }
        logger.warn(`Could not verify the ${answers[0].type} RRSET on ${answers[0].name} with any RRSIGs`);
        return null;
    }

    async verifyWithDS(keys: packet.Dnskey[], sigs: packet.Rrsig[]): Promise<ProvableAnswer<packet.Dnskey>|null> {
        const keyname = keys[0].name;

        // Fetch the DS records to use
        let answer: packet.Ds[];
        let proofs: SignedSet<packet.Dnskey|packet.Ds>[];
        if(keyname === '.') {
            [answer, proofs] = [this.anchors, []];
        } else {
            const response = await this.queryWithProof('DS', keyname);
            answer = response.answer.records;
            proofs = response.proofs;
            proofs.push(response.answer);
        }

        // Index the passed in keys by key tag
        const keysByTag = makeIndex(keys, getKeyTag);
        const sigsByTag = makeIndex(sigs, (sig) => sig.data.keyTag);

        // Iterate over the DS records looking for keys we can verify
        for(let ds of answer) {
            for(let key of keysByTag[ds.data.keyTag]) {
                if(this.checkDs(ds, key)) {
                    logger.info(`DS=${ds.data.keyTag}/${this.algorithms[ds.data.algorithm].name}/${this.digests[ds.data.digestType].name} verifies DNSKEY=${ds.data.keyTag}/${this.algorithms[key.data.algorithm].name} on ${key.name}`);
                    for(let sig of sigsByTag[ds.data.keyTag]) {
                        const ss = new SignedSet(keys, sig);
                        if(this.verifySignature(ss, key)) {
                            logger.info(`RRSIG=${sig.data.keyTag}/${this.algorithms[sig.data.algorithm].name} verifies the DNSKEY RRSET on ${keys[0].name}`);
                            return {answer: ss, proofs: proofs};
                        }
                    }
                }
            }
        }

        return null;
    }

    verifySignature<T extends packet.Answer>(answer: SignedSet<T>, key: packet.Dnskey): boolean {
        const keyTag = getKeyTag(key);
        if(key.data.algorithm != answer.signature.data.algorithm || keyTag != answer.signature.data.keyTag || key.name != answer.signature.data.signersName) {
            return false;
        }
        const signatureAlgorithm = this.algorithms[key.data.algorithm];
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
        const digestAlgorithm = this.digests[ds.data.digestType];
        if(digestAlgorithm === undefined) {
            logger.warn(`Unrecognised digest type for DS=${ds.data.keyTag}/${ds.data.digestType} on ${ds.name}`)
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
        const response = await this.sendQuery(query);
        logger.info(`Query[${qname} ${qtype}]:\n` + answersToString(response.answers));
        if(response.rcode !== 'NOERROR') {
            throw new ResponseCodeError(query, response);
        }
        return response;
    }
}