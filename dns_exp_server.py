#!/usr/bin/python

import os
import sys
import time
import Queue
import logging
import argparse
import traceback
import dnslib as dl
import mysql.connector
from threading import Thread,Timer
from raw_server import RawUdpServer
from collections import defaultdict
from datetime import datetime,timedelta

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

# Authoritative DNS server for experiments
class AServer(RawUdpServer):
    def __init__(self, *args):
        super(AServer, self).__init__(*args)
        self.inserter = DatabaseInserter()
        self.resolvers = defaultdict(list)

    def run(self):
        self.inserter.start()
        try:
            super(AServer, self).run()
        finally:
            self.inserter.terminate()

    def read(self, ip_header, udp_header, addr, data):
        packet = dl.DNSRecord.parse(data)
        if packet.header.qr:
            self.read_response(ip_header, udp_header, addr, packet)
        else:
            self.read_request(ip_header, udp_header, addr, packet)

    def read_response(self, ip_header, udp_header, addr, response):
        qid = response.header.id
        qname = response.q.qname
        qclass = dl.CLASS[response.q.qclass]
        qtype = dl.QTYPE[response.q.qtype]

        ropen = (response.header.rcode == dl.RCODE.NOERROR and response.header.a > 0 and addr[0] in self.resolvers)
        logging.info("Response ip_id:%s tx_id:%s from %s for (%s %s %s) ans:%s", ip_header.id, qid, addr, str(qname), qclass, qtype, (str(response.a.rdata) if ropen else 'closed'))

        if ropen:
            for data in self.resolvers[addr[0]]:
                data.open = True
            del self.resolvers[addr[0]]
        
    def read_request(self, ip_header, udp_header, addr, request):
        qid = request.header.id
        qname = request.q.qname
        qnm = str(qname).lower()
        qclass = dl.CLASS[request.q.qclass]
        qtype = dl.QTYPE[request.q.qtype]
        
        logging.info("Request ip_id:%s tx_id:%s from %s for (%s %s %s)", ip_header.id, qid, addr, str(qname), qclass, qtype)

        reply = dl.DNSRecord(dl.DNSHeader(id=qid, qr=1, aa=1, ra=0, rd=0, tc=0), q=request.q)
        
        # Lookup to see if this name is in records
        key = qnm+qclass+qtype
        if key in self.records:
            reply.add_answer(dl.RR(qname, rclass=self.records[key].rclass, rtype=self.records[key].rtype,\
                rdata=self.records[key].rdata, ttl=self.records[key].ttl))
        elif not qnm.endswith('exp.schomp.info.'):
            reply.header.rcode = dl.RCODE.REFUSED

        # NS record for the domain
        elif qnm == 'exp.schomp.info.' and request.q.qtype == dl.QTYPE.NS:
            reply.add_answer(dl.RR(qname, rclass=dl.CLASS.IN, rtype=dl.QTYPE.NS,\
                rdata=dl.NS('ns1.exp.schomp.info.'), ttl=3600))
            reply.add_ar(dl.RR('ns1.exp.schomp.info.', rclass=dl.CLASS.IN, rtype=dl.QTYPE.A,\
                rdata=dl.A(args.external), ttl=3600))

        # SOA record for the domain
        elif qnm == 'exp.schomp.info.' and request.q.qtype == dl.QTYPE.SOA:
            reply.add_answer(dl.RR(qname, rclass=dl.CLASS.IN, rtype=dl.QTYPE.SOA,\
                rdata=dl.SOA("ns1.exp.schomp.info.", "admin.exp.schomp.info.", (20160320,3600,3600,3600,3600)), ttl=3600))

        # Nameserver or website address
        elif request.q.qtype == dl.QTYPE.A and (qnm == 'ns1.exp.schomp.info.' or qnm == 'exp.schomp.info.'):
            reply.add_answer(dl.RR(qname, rclass=dl.CLASS.IN, rtype=dl.QTYPE.A,\
                rdata=dl.A(args.external), ttl=3600))

        # Recursion test
        elif qnm == 'recurse.exp.schomp.info.':
            reply.add_auth(dl.RR('exp.schomp.info.', rclass=dl.CLASS.IN, rtype=dl.QTYPE.NS,\
                rdata=dl.NS('ns1.exp.schomp.info.'), ttl=3600))
            reply.add_ar(dl.RR('ns1.exp.schomp.info.', rclass=dl.CLASS.IN, rtype=dl.QTYPE.A,\
                rdata=dl.A(args.external), ttl=3600))

        # TXT record request
        elif request.q.qtype == dl.QTYPE.TXT:
            reply.add_answer(dl.RR(qname, rclass=dl.CLASS.IN, rtype=dl.QTYPE.TXT,\
                rdata=dl.TXT(("RESOLVER=%s | PORT=%s | QUERY=%s | TRANSACTION=%s | IPID=%s | TIME=%s" % (addr[0],\
                addr[1], qname, qid, ip_header.id, datetime.utcnow()))), ttl=3600)) # A negligable TTL

        # DNS Web Tool
        elif request.q.qtype == dl.QTYPE.A and qnm.endswith('dnstool.exp.schomp.info.'):
            # Validate the query
            parsed = parseQueryString(qnm)
            exp_id = parsed['exp_id']
            step = parsed['step']
            if exp_id and step and not parsed['cname']:
                data = QueryData(exp_id, addr[0], addr[1], str(qname), qid, ip_header.id)
                self.inserter.addItem(data)
                self.check_resolver(data)
                
                # Return a cname from another random record
                reply.add_answer(dl.RR(qname, rclass=dl.CLASS.IN, rtype=dl.QTYPE.CNAME,\
                    rdata=dl.CNAME("exp_id-%s.step-%s.cname.dnstool.exp.schomp.info." % (exp_id, step)), ttl=3600))

            elif exp_id and step and parsed['cname']:
                data = QueryData(exp_id, addr[0], addr[1], str(qname), qid, ip_header.id)
                self.inserter.addItem(data)
                self.check_resolver(data)

                # Return NXDOMAIN to stop the webpage fetch
                reply.header.rcode = dl.RCODE.NXDOMAIN
            else:
                # Return the website
                reply.add_answer(dl.RR(qname, rclass=dl.CLASS.IN, rtype=dl.QTYPE.A,\
                    rdata=dl.A(args.external), ttl=3600))

        # Return no answer, no error for the AAAA record
        elif request.q.qtype == dl.QTYPE.AAAA and qnm.endswith('dnstool.exp.schomp.info.'):
            pass

        # TODO: Add other tools HERE!
        else:
            # Error
            reply.header.rcode = dl.RCODE.NXDOMAIN
        
        self.write(addr, reply.pack())
        
    def check_resolver(self, data):
        lst = self.resolvers[data.src_ip]
        lst.append(data)
        # Limit the number of probes that we send
        if len(lst) % 4 == 1:
            query = dl.DNSRecord.question("google.com") # Arbitrary domain name
            logging.info('Testing if %s is an open resolver tx_id:%s', data.src_ip, query.header.id)
            self.write((data.src_ip, 53), query.pack()) 
        # Insure lists do not grow too large
        while len(lst) > 0 and lst[0].time < datetime.utcnow():
            del lst[0]

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
                    if dl.QTYPE.reverse[qtype] == dl.QTYPE.CNAME:
                        records[qname.lower()+qclass+'A'] = dl.RR(qname, rclass=dl.CLASS.reverse[qclass],\
                            rtype=dl.QTYPE.reverse[qtype], rdata=getattr(dl, qtype)(ans), ttl=int(ttl))
            except Exception as e:
               logging.error('Error in mapping file: %s\n%s', e, traceback.format_exc())
        self.records = records


add_query_db = ("INSERT INTO queries "
               "(exp_id, src_ip, src_port, query, trans_id, ip_id, open, time) "
               "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
               
class QueryData(object):
    def __init__(self, exp_id, src_ip, src_port, query, trans_id, ip_id):
        self.exp_id = exp_id.lower()
        self.src_ip = src_ip
        self.src_port = src_port
        self.query = query
        self.trans_id = trans_id
        self.ip_id = ip_id
        self.open = False
        self.dbtime = datetime.utcnow()
        self.time = datetime.utcnow() + timedelta(seconds=1)
        
    def insert_tuple(self):
        return (self.exp_id, self.src_ip, self.src_port, self.query, self.trans_id, self.ip_id, int(self.open), self.dbtime)
               
class DatabaseInserter(Thread):
    def __init__(self, *args):
        super(DatabaseInserter, self).__init__(*args)
        self.que = Queue.Queue()
        self.running = False
        
    def wait_item(self, item):
        while item.time > datetime.utcnow():
            time.sleep(1)
            
    def addItem(self, item):
        self.que.put(item)

    def run(self):
        self.running = True
        while self.running:
            data = []
            # Get an item
            data.append(self.que.get(block=True))
            # Wait for item time
            self.wait_item(data[0])
            # Collect all other items waiting in the queue
            while not self.que.empty():
                try:
                    data.append(self.que.get(block=False))
                except Queue.Empty:
                    break
            # Wait until the last item time
            self.wait_item(data[-1])
            # Convert to database format
            data = [i.insert_tuple() for i in data]
            
            #logging.info('Performing database insert of %s', data)
            
            cnx = mysql.connector.connect(user=args.username, password=args.password, host='localhost', database='dnstool')
            try:
                cursor = cnx.cursor()
                cursor.executemany(add_query_db, data)
                cnx.commit()
                cursor.close()
            except Exception as e:
                logging.error('Error on database: %s\n%s', e, traceback.format_exc())
            finally:
                cnx.close()
        self.running = False
                
    def terminate(self):
        logging.info('Inserter terminating')
        self.running = False
        self.addItem(None)
        self.join()
        
if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='A simple authoritative DNS server implementation for experiments')
    parser.add_argument('-a', '--address', default='0.0.0.0:53', help='Address to bind upon')                                     
    parser.add_argument('-m', '--mapping', default=None, type=str, help='File containing name to address mappings')
    parser.add_argument('-e', '--external', default='54.210.32.38')
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

    try:
        server.run()
    finally:
        server.terminate()
