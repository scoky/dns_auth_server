#!/usr/bin/python

from __future__ import print_function

import sys
import os
import logging
import argparse
import traceback
from circuits import handler,Debugger
from circuits.net.sockets import UDPServer
import dnslib as dl

class AServer(UDPServer):
    @handler("read")
    def on_read(self, addr, data):
        request = dl.DNSRecord.parse(data)
        qid = request.header.id
        qname = request.q.qname
        
        print("Request for qname({0:s})".format(str(qname)), file=sys.stderr)
        
        reply = dl.DNSRecord(dl.DNSHeader(id=qid, qr=1, aa=1, ra=1), q=request.q)
        reply.add_answer(dl.RR(qname, dl.QTYPE.A, rdata=dl.A("1.1.1.1")))
        
        self.write(addr, reply.pack())

if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='A simple authoritative DNS server implementation')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help='only print errors')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='print debug info. --quiet wins if both are present')
    args = parser.parse_args()

    # set up logging
    if args.quiet:
        level = logging.WARNING
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno) -7s %(message)s",
        level = level
    )

    server = AServer(9000)
    Debugger().register(server)
    server.run()
