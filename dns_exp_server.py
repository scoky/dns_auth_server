#!/usr/bin/python

import os
import sys
import time
import Queue
import logging
import argparse
import traceback
from threading import Thread,Timer
from raw_server import RawUdpServer
from collections import defaultdict
from datetime import datetime,timedelta

try:
    import mysql.connector
except:
    print >>sys.stderr, 'Could not load mysql.connector. Will not be able to interface with the database'

try:
    import dns.zone as zone
    import dns.rdatatype as rtype
    import dns.rdataclass as rclass
    import dns.flags as flags
    import dns.rrset as rrset
    import dns.rcode  as rcode
    from dns import message
except:
    raise Exception('Is dnspython installed?')

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
        self.zones = []

    def run(self):
        self.inserter.start()
        try:
            super(AServer, self).run()
        finally:
            self.inserter.terminate()

    def read(self, ip_header, udp_header, addr, data):
        packet = message.from_wire(data)
        if packet.flags & flags.QR:
            self.read_response(ip_header, udp_header, addr, packet)
        else:
            self.read_request(ip_header, udp_header, addr, packet)

    def read_response(self, ip_header, udp_header, addr, response):
        qid = response.id
        qname = response.question[0].name
        qclass = rclass.to_text(response.question[0].rdclass)
        qtype = rtype.to_text(response.question[0].rdtype)

        ropen = (response.rcode() == rcode.NOERROR and len(response.answer) > 0 and addr[0] in self.resolvers)
        logging.info("Response ip_id:%s tx_id:%s from %s for (%s %s %s) ans:%s", ip_header.id, qid, addr, str(qname), \
                    qclass, qtype, (str(response.answer[0][0]) if ropen else 'closed'))

        if ropen:
            for data in self.resolvers[addr[0]]:
                data.open = True
            del self.resolvers[addr[0]]

    def read_request(self, ip_header, udp_header, addr, request):
        qid = request.id
        qname = request.question[0].name
        qnm = str(qname).lower()
        qclass = request.question[0].rdclass
        qtype = request.question[0].rdtype

        logging.info("Request ip_id:%s tx_id:%s from %s for (%s %s %s)", ip_header.id, qid, addr, \
                    str(qname), rclass.to_text(qclass), rtype.to_text(qtype))

        reply = message.make_response(request)
        # reply.flags |= flags.QR | flags.AA
        # reply.flags = (reply.flags | flags.RA | flags.TC) ^ (flags.RA | flags.TC)

        # Recursion test - keep referring the resolver back to self
        if qnm == 'recurse.exp.schomp.info.':
            reply.answer.append(rrset.from_text('exp.schomp.info.', 0, rclass.IN, rtype.NS, 'ns1.exp.schomp.info.'))

        # TXT record request
        elif qtype == rtype.TXT and qnm.endswith('stat.exp.schomp.info.'):
                reply.answer.append(rrset.from_text(qname, 1, rclass.IN, rtype.TXT, \
                    "RESOLVER=%s | PORT=%s | QUERY=%s | TRANSACTION=%s | IPID=%s | TIME=%s" % (addr[0],\
                    addr[1], qname, qid, ip_header.id, datetime.utcnow())))

        # DNS Web Tool
        elif qtype == rtype.A and qnm.endswith('dnstool.exp.schomp.info.'):
            # Validate the query
            parsed = parseQueryString(qnm)
            exp_id = parsed['exp_id']
            step = parsed['step']
            if exp_id and step and not parsed['cname']:
                data = QueryData(exp_id, addr[0], addr[1], str(qname), qid, ip_header.id)
                self.inserter.addItem(data)
                self.check_resolver(data)

                # Return a cname from another random record
                reply.answer.append(rrset.from_text(qname, 10, rclass.IN, rtype.CNAME, \
                    "exp_id-%s.step-%s.cname.dnstool.exp.schomp.info." % (exp_id, step)))

            elif exp_id and step and parsed['cname']:
                data = QueryData(exp_id, addr[0], addr[1], str(qname), qid, ip_header.id)
                self.inserter.addItem(data)
                self.check_resolver(data)

                # Return NXDOMAIN to stop the webpage fetch
                reply.rcode = rcode.NXDOMAIN
            else:
                # Return the website
                reply.answer.append(rrset.from_text(qname, 3600, rclass.IN, rtype.A, args.external))

        elif qtype == rtype.A and qnm.ednswith('chain.exp.schomp.info.'):
            reply.answer.append(rrset.from_text(qname, 3600, rclass.IN, rtype.NS, 'cname1.{0}'.format(qname)))
            reply.answer.append(rrset.from_text('cname1.{0}'.format(qname), 3600, rclass.IN, rtype.NS, 'cname2.{0}'.format(qname)))
            reply.answer.append(rrset.from_text('cname2.{0}'.format(qname), 3600, rclass.IN, rtype.A, '1.2.3.4'))

        # TODO: Add other tools HERE!
        else:
            # Lookup to see if this name is in one of our zone files
            for z in self.zones:
                if qname.is_subdomain(z.origin):
                    try:
                        rr = z.find_rrset(qname, qtype)
                        reply.answer.append(rr)
                        break
                    except KeyError:
                        continue
        
        self.write(addr, reply.to_wire())
        
    def check_resolver(self, data):
        lst = self.resolvers[data.src_ip]
        lst.append(data)
        # Limit the number of probes that we send
        if len(lst) % 4 == 1:
            query = message.make_query('google.com.') # Arbitrary domain name
            logging.info('Testing if %s is an open resolver tx_id:%s', data.src_ip, query.id)
            self.write((data.src_ip, 53), query.to_wire()) 
        # Insure lists do not grow too large
        while len(lst) > 0 and lst[0].time < datetime.utcnow():
            del lst[0]

    def refresh_records(self):
        zones = []
        if args.mapping != None:
            try:
                z = zone.from_file(args.mapping, relativize = False)
                zones.append(z)
            except Exception as e:
               logging.error('Error in mapping file: %s\n%s', e, traceback.format_exc())
        self.zones = zones


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
    
    addr,port = args.address.split(':', 1)
    server = AServer((addr, int(port)))
    logging.info('listening on {0}:{1}'.format(addr, port))
    server.refresh_records()
    logging.info('loaded zone files')

    try:
        server.run()
    finally:
        server.terminate()
