import { RR } from '..';

export interface Response {
  answers: RR[];
}

export interface Resolver {
  lookup(name: string, rdtype: string | number): Promise<Response>;
}
