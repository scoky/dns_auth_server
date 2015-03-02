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
from collections import defaultdict
from datetime import datetime

def parseQueryString(qnm):
    tokens = qnm.split('.')
    res = defaultdict(bool)
    for token in tokens:
        t = token.split('-', 1)
        if len(t) == 2:
            res[t[0]] = t[1]
        else:
            res[t[0]] = True
    return res

class AServer(UDPServer):
    @handler("read")
    def on_read(self, addr, data):
        request = dl.DNSRecord.parse(data)
        qid = request.header.id
        qname = request.q.qname
        qnm = str(qname).lower()
        qclass = dl.CLASS[request.q.qclass]
        qtype = dl.QTYPE[request.q.qtype]
        
        logging.info("Request from (%s) for (%s %s %s)", addr, qnm, qclass, qtype)

        reply = dl.DNSRecord(dl.DNSHeader(id=qid, qr=1, aa=1, ra=1), q=request.q)        
        
        # Lookup to see if this name is in records
        key = qnm+qclass+qtype
        if key in self.records:
            reply.add_answer(dl.RR(qname, rclass=request.q.qclass, rtype=request.q.qtype,\
                rdata=self.records[key].rdata, ttl=self.records[key].ttl))
        elif not qnm.endswith('exp.schomp.info.'):
            reply.header.rcode = dl.RCODE.REFUSED
        elif request.q.qtype == dl.QTYPE.TXT:
            reply.add_answer(dl.RR(qname, rclass=request.q.qclass, rtype=request.q.qtype,\
                rdata=dl.TXT(("RESOLVER=%s | PORT=%s | QUERY=%s | TRANSACTION=%s | TIME=%s" % (addr[0],\
                addr[1], qname, qid, datetime.utcnow()))), ttl=10)) # A negligable TTL
        else:
            # Error
            reply.header.rcode = dl.RCODE.NXDOMAIN
        
        self.write(addr, reply.pack())

    def refresh_records(self):        
        records = {}
        if args.mapping != None:
            try:
                for line in open(args.mapping, 'r'):
                    if line.startswith('#'):
                        continue
                    qname,qclass,qtype,ttl,ans = line.split()
                    records[qname.lower()+qclass+qtype] = dl.RR(qname, rclass=dl.CLASS.reverse[qclass],\
                        rtype=dl.QTYPE.reverse[qtype], rdata=getattr(dl, qtype)(ans), ttl=int(ttl))
            except Exception as e:
               logging.error('Error in mapping file: %s\n%s', e, traceback.format_exc())
        self.records = records

if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='A simple authoritative DNS server implementation')
    parser.add_argument('-a', '--address', default='0.0.0.0:53', help='Address to bind upon')                                     
    parser.add_argument('-m', '--mapping', default=None, type=str, help='File containing name to address mappings')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help='only print errors')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='print debug info. --quiet wins if both are present')
    args = parser.parse_args()
    
    addr,port = args.address.split(':', 1)
    server = AServer((addr, int(port)))
    server.refresh_records()

    # set up logging
    if args.quiet:
        level = logging.WARNING
    elif args.verbose:
        level = logging.DEBUG
        Debugger().register(server)
    else:
        level = logging.INFO
    logging.basicConfig(
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno) -7s %(message)s",
        level = level
    )

    server.run()
