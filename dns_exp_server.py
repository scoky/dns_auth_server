#!/usr/bin/python

import sys
import os
import logging
import argparse
import traceback
import dnslib as dl
from collections import defaultdict
from datetime import datetime
#import mysql.connector
import dpkt
import socket, random

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
    
add_query_db = ("INSERT INTO queries "
               "(exp_id, src_ip, src_port, query, trans_id, ip_id) "
               "VALUES (%s, %s, %s, %s, %s, %s)")
               
class RawUdpServer(object):
    def __init__(self, addr):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.sock.bind(addr)
        self.running = False
        self.addr = socket.inet_aton(addr[0])
        self.port = addr[1]
        
    def run(self):
        self.running = True
        while self.running:
            try:
                data = self.sock.recv(4096)
                ippkt = dpkt.ip.IP(data)
                udppkt = ippkt.data
                
                # Ignore packets not destined for us
                if udppkt.dport != self.port: # or ippkt.dst != self.addr:
                    continue

                # Process the packet
                self.read(ippkt, udppkt, (socket.inet_ntoa(ippkt.src), udppkt.sport), udppkt.data)
            except Exception as e:
                logging.error('Error on recv: %s\n%s', e, traceback.format_exc())
        self.running = False
        
    def read(self, ip_header, udp_header, saddr, data):
        print "RECV:", socket.inet_ntoa(ip_header.src), udp_header.sport
        self.write(data, (socket.inet_ntoa(ip_header.src), udp_header.sport))
        pass
        
    def terminate(self):
        self.running = False
        # Wait for run to return
        self.sock.close()
        
    def write(self, daddr, data):
        udpdata = dpkt.udp.UDP(sport = self.port, dport = daddr[1], data = data)
        udpdata.ulen = len(udpdata)
        # Cannot generate own IP header (i.e., no spoofing)
        #ipdata = dpkt.ip.IP(src = self.addr, dst = socket.inet_aton(daddr[0]), data = udpdata)
        self.sock.sendto(str(udpdata), daddr)

class AServer(RawUdpServer):
    def read(self, ip_header, udp_header, addr, data):
        request = dl.DNSRecord.parse(data)
        qid = request.header.id
        qname = request.q.qname
        qnm = str(qname).lower()
        qclass = dl.CLASS[request.q.qclass]
        qtype = dl.QTYPE[request.q.qtype]
        
        logging.info("Request ip_id:%s tx_id:%s from %s for (%s %s %s)", ip_header.id, qid, addr, str(qname), qclass, qtype)

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
                rdata=dl.TXT(("RESOLVER=%s | PORT=%s | QUERY=%s | TRANSACTION=%s | IPID=%s | TIME=%s" % (addr[0],\
                addr[1], qname, qid, ip_header.id, datetime.utcnow()))), ttl=10)) # A negligable TTL
        elif request.q.qtype == dl.QTYPE.A and qnm.endswith('dnstool.exp.schomp.info.'):
            # Validate the query
            exp_id = parseQueryString(qnm)['exp_id']
            if exp_id:
                # Insert into the database
                cnx = mysql.connector.connect(user=args.username, password=args.password, host='localhost', database='dnstool')
                data = (exp_id, addr[0], addr[1], str(qname), qid, ip_header.id)
                try:
                    cursor = cnx.cursor()
                    cursor.execute(add_query_db, data)
                    qid = cursor.lastrowid
                    cnx.commit()
                    cursor.close()
                finally:
                    cnx.close()
                
            # Return a cname to the website
            reply.add_answer(dl.RR(qname, rclass=request.q.qclass, rtype=dl.QTYPE.CNAME,\
                rdata=dl.CNAME("schomp.info"), ttl=10))
        # TODO: Add other tools HERE!
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
    parser.add_argument('-u', '--username', default='root')
    parser.add_argument('-p', '--password', default=None)
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
    else:
        level = logging.INFO
    logging.basicConfig(
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno) -7s %(message)s",
        level = level
    )

    server.run()
