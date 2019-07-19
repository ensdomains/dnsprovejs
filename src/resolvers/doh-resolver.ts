// https://github.com/DefinitelyTyped/DefinitelyTyped/issues/34960
import { URL } from 'url';
import * as http from 'http';
import * as https from 'https';

import * as wireFormat from 'dns-packet';

import { Resolver, Response } from '.';

export class DoHResolver implements Resolver {
  url: string;

  constructor(url = 'https://cloudflare-dns.com/dns-query') {
    this.url = url;
  }

  async lookup(name: string, rdtype: string | number): Promise<Response> {
    const url = new URL(this.url);
    const query = wireFormat.encode({
      flags: wireFormat.RECURSION_DESIRED,
      questions: [
        {
          name,
          type: rdtype
        }
      ],
      // RFC 3225
      additionals: [
        {
          name: '.',
          type: 'OPT',
          flags: wireFormat.DNSSEC_OK
        }
      ]
    });
    url.searchParams.append('dns', query.toString('base64'));
    const res: http.IncomingMessage = await new Promise((resolve, reject) => {
      const req = https.request(url, resolve);
      req.on('error', reject);
      req.end();
    });
    if (
      res.statusCode === undefined ||
      res.statusCode < 200 ||
      res.statusCode > 299
    ) {
      throw new Error();
    }
    // https://github.com/tc39/proposal-async-iteration/issues/103
    let response = Buffer.alloc(0);
    for await (const chunk of res) {
      response = Buffer.concat([response, chunk]);
    }
    return wireFormat.decode(response);
  }
}
