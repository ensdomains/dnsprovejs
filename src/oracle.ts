import * as types from 'dns-packet/types';
import * as wireFormat from 'dns-packet';

import { SignedRRset } from '.';

export function encode({ signedData, signature }: SignedRRset): Buffer {
  const buf = Buffer.alloc(2 + signedData.length + 2 + signature.length);
  buf.writeUInt16BE(signedData.length, 0);
  buf.set(signedData, 2);
  buf.writeUInt16BE(signature.length, 2 + signedData.length);
  buf.set(signature, 2 + signedData.length + 2);
  return buf;
}

export interface OracleResult {
  hash: string;
  inserted: number;
  inception: number;
}

export class Oracle {
  contract: any;

  async anchors(): Promise<Buffer> {
    const anchors = await this.contract.methods.anchors.call();
    return Buffer.from(anchors.slice(2), 'hex');
  }

  async lookup(name: string, rdtype: string | number): Promise<OracleResult> {
    rdtype = types.toType(rdtype);
    const [inception, inserted, hash] = Object.values(
      await this.contract.methods
        .rdata(rdtype, wireFormat.name.encode(name))
        .call()
    );
    return {
      hash,
      inserted,
      inception
    };
  }

  update(chain: readonly SignedRRset[], proof: Buffer, options?: any): void {
    this.contract.methods
      .submitRRSets(Buffer.concat(chain.map(encode)), proof)
      .send(options);
  }
}
