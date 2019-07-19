import { SignedRRset } from '..';

export interface Algorithm {
  verify({ signedData, signature }: SignedRRset, publicKey: Buffer): boolean;
}
