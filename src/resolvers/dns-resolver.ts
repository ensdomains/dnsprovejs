import * as dgram from 'dgram';
import * as dns from 'dns';

import * as wireFormat from 'dns-packet';

import { Resolver, Response } from '.';

export class DNSResolver implements Resolver {
  nameservers: readonly string[];

  constructor(nameservers = dns.getServers()) {
    this.nameservers = nameservers;
  }

  async lookup(name: string, rdtype: string | number): Promise<Response> {
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
    const [nameserver] = this.nameservers;
    const response = await new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4', resolve);
      socket.on('error', reject);
      socket.send(query, 0, query.length, 53, nameserver);
    });
    return wireFormat.decode(response);
  }
}
