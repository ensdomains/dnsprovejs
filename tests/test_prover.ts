import * as packet from 'dns-packet';
import { dohQuery, DNSProver, DEFAULT_ALGORITHMS, DEFAULT_DIGESTS, DEFAULT_TRUST_ANCHORS, getKeyTag } from '../src/prove';
import { expect } from 'chai';
import {logger} from '../src/log';


function makeProver(responses: {[qname: string]: {[qtype: string]: packet.Packet[]}}, rootKey: packet.Dnskey) {
    const sendQuery = function(q: packet.Packet): Promise<packet.Packet> {
        if(q.questions.length !== 1) {
            throw new Error("Queries must have exactly one question"); 
        };
        const question = q.questions[0];
        const response = responses[question.name]?.[question.type];
        if(response === undefined) {
            throw new Error("Unexpected query for " + question.name + " " + question.type);
        }
        return Promise.resolve(Object.assign(response, {questions: q.questions, id: q.id}));
    };
    const digests = Object.assign(DEFAULT_DIGESTS, {
        253: {
            name: 'DUMMY',
            f: (data: Buffer) => true,
        },
    });
    const algorithms = Object.assign(DEFAULT_ALGORITHMS, {
        253: {
            name: 'DUMMY',
            f: (key: Buffer, data: Buffer, sig: Buffer) => true,
        },
    });
    const anchors = DEFAULT_TRUST_ANCHORS.slice();
    anchors.push(makeDs(rootKey));
    return new DNSProver(sendQuery, digests, algorithms, anchors);
}

function makeSignedResponse(a: packet.Answer[], keys: packet.Dnskey[]): packet.Packet {
    a = a.map((ans) => Object.assign(ans, {class: 'IN', ttl: 3600}));
    const now = Math.floor(Date.now() / 1000);
    for(const key of keys) {
        a.push({
            name: a[0].name,
            type: 'RRSIG',
            class: 'IN',
            ttl: 3600,
            data: {
                typeCovered: a[0].type,
                algorithm: key.data.algorithm,
                labels: a[0].name.split('.').length - 1,
                originalTTL: a[0].ttl || 3600,
                expiration: now + 3600,
                inception: now - 3600,
                keyTag: getKeyTag(key),
                signersName: key.name,
                signature: Buffer.from(a[0].name),
            }
        });
    }
    return {
        type: 'response',
        rcode: 'NOERROR',
        answers: a
    };
}

function makeKey(name: string): packet.Dnskey {
    return {
        name: name,
        type: 'DNSKEY',
        data: {
            flags: 256, // ZSK
            algorithm: 253,
            key: Buffer.from(name),
        }
    };
}

function makeDs(signedKey: packet.Dnskey): packet.Ds {
    return {
        name: signedKey.name,
        type: 'DS',
        data: {
            keyTag: getKeyTag(signedKey),
            algorithm: signedKey.data.algorithm,
            digestType: 253,
            digest: Buffer.from(signedKey.name),
        }
    };
}

function makeDsResponse(signedKey: packet.Dnskey, signingKeys: packet.Dnskey[]): packet.Packet {
    return makeSignedResponse([makeDs(signedKey)], signingKeys);
}

describe('dnsprovejs', () => {
    it('correctly constructs a set of proofs', async () => {
        const now = Date.now() / 1000;
        const rootKey = makeKey('.');
        const tldKey = makeKey('tld.');
        const testKey = makeKey('test.tld.');
        const prover = makeProver({
            'test.tld.': {
                'TXT': makeSignedResponse([
                    {
                        name: 'test.tld.',
                        type: 'TXT',
                        data: [Buffer.from('Hello, world!')],
                    }], [testKey]),
                'DNSKEY': makeSignedResponse([testKey], [testKey]),
                'DS': makeDsResponse(testKey, [tldKey]),
            },
            'tld.': {
                'DNSKEY': makeSignedResponse([tldKey], [tldKey]),
                'DS': makeDsResponse(tldKey, [rootKey]),
            },
            '.': {
                'DNSKEY': makeSignedResponse([rootKey], [rootKey]),
            },
        }, rootKey);
        const result = await prover.queryWithProof('TXT', 'test.tld.');
        expect(result).to.deep.nested.include({
            'answer.records[0].name': 'test.tld.',
            'answer.records[0].type': 'TXT',
            'answer.records[0].data[0]': Buffer.from('Hello, world!'),
            'answer.signature.name': 'test.tld.',
            'answer.signature.type': 'RRSIG',
            'answer.signature.data.signersName': 'test.tld.',
            'answer.signature.data.typeCovered': 'TXT',
            'answer.signature.data.labels': 2,
            'answer.signature.data.keyTag': getKeyTag(testKey),

            'proofs.length': 5,

            'proofs[0].records[0].name': '.',
            'proofs[0].records[0].type': 'DNSKEY',
            'proofs[0].signature.name': '.',
            'proofs[0].signature.data.signersName': '.',
            'proofs[0].signature.data.keyTag': getKeyTag(rootKey),

            'proofs[1].records[0].name': 'tld.',
            'proofs[1].records[0].type': 'DS',
            'proofs[1].records[0].data.keyTag': getKeyTag(tldKey),
            'proofs[1].signature.name': 'tld.',
            'proofs[1].signature.data.signersName': '.',
            'proofs[1].signature.data.keyTag': getKeyTag(rootKey),

            'proofs[2].records[0].name': 'tld.',
            'proofs[2].records[0].type': 'DNSKEY',
            'proofs[2].signature.name': 'tld.',
            'proofs[2].signature.data.signersName': 'tld.',
            'proofs[2].signature.data.keyTag': getKeyTag(tldKey),

            'proofs[3].records[0].name': 'test.tld.',
            'proofs[3].records[0].type': 'DS',
            'proofs[3].records[0].data.keyTag': getKeyTag(testKey),
            'proofs[3].signature.name': 'test.tld.',
            'proofs[3].signature.data.signersName': 'tld.',
            'proofs[3].signature.data.keyTag': getKeyTag(tldKey),

            'proofs[4].records[0].name': 'test.tld.',
            'proofs[4].records[0].type': 'DNSKEY',
            'proofs[4].signature.name': 'test.tld.',
            'proofs[4].signature.data.signersName': 'test.tld.',
            'proofs[4].signature.data.keyTag': getKeyTag(testKey),
        });
    });

    it('ignores RRSIGs with unknown algorithms', async () => {
        const now = Date.now() / 1000;
        const rootKey = makeKey('.');
        const alternateRootKey = makeKey('.');
        alternateRootKey.data.algorithm = 252;

        const prover = makeProver({
            '.': {
                'DNSKEY': makeSignedResponse([alternateRootKey, rootKey], [alternateRootKey, rootKey]),
            },
        }, rootKey);
        const result = await prover.queryWithProof('DNSKEY', '.');
        expect(result).to.deep.nested.include({
            'answer.signature.data.algorithm': 253,
            'answer.records.length': 2,
            'proofs': [],
        });
    });

    it('ignores DSes with unknown digest types', async () => {

    });

    it('requires that the DNSKEY be in the chain of trust', async () => {
        // In the situation that a self-signed DNSKEY RRSET has multiple keys and
        // multiple signatures, but only one of those keys has a DS record in the
        // parent zone, we should only accept the signature with the DNSKEY that
        // is validated by the DS record. This test checks that situation. 
    });

    it('rejects expired RRSIGs', async () => {

    });

    it('rejects not-yet-valid RRSIGs', async () => {

    });

    it('correctly validates a real chain of records', async () => {

    });
});
