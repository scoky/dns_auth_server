#!/usr/bin/python

import os
import sys
import time
import Queue
import logging
import argparse
import traceback
from raw_server import RawUdpServer
from collections import defaultdict
from datetime import datetime,timedelta
from threading import Thread,Timer
import base64

try:
    import dns.zone as zone
    import dns.rdatatype as rtype
    import dns.rdataclass as rclass
    import dns.flags as flags
    import dns.rrset as rrset
    import dns.rcode  as rcode
    from dns import message
except ImportError:
    raise Exception('Is dnspython installed?')

from dns_tree import dns_tree,dns_tree_node
from experiments import load_experiments

try:
    import mysql.connector
except:
    print >>sys.stderr, 'Could not load mysql.connector. Will not be able to interface with the database'

add_query_db = ("INSERT INTO queries "
               "(exp_id, src_ip, src_port, query, trans_id, ip_id, open, time) "
               "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
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
            
            cnx = None
            try:
                cnx = mysql.connector.connect(user=args.username, password=args.password, host='localhost', database='dnstool')
                cursor = cnx.cursor()
                cursor.executemany(add_query_db, data)
                cnx.commit()
                cursor.close()
            except Exception as e:
                logging.error('Error on database: %s\n%s', e, traceback.format_exc())
            finally:
                if cnx is not None:
                    cnx.close()
        self.running = False
                
    def terminate(self):
        logging.info('Inserter terminating')
        self.running = False
        self.addItem(None)
        self.join()
        
# Authoritative DNS server for experiments
class AServer(RawUdpServer):
    def __init__(self, *args):
        super(AServer, self).__init__(*args)
        self.inserter = DatabaseInserter()
        self.resolvers = defaultdict(list)
        self.tree = dns_tree()

    def run(self):
        self.inserter.start()
        try:
            super(AServer, self).run()
        finally:
            self.inserter.terminate()

    def read(self, pkt):
        logging.info("Packet: %s", base64.b64encode(pkt.raw))
        pkt.dns_packet = message.from_wire(pkt.data)
        if pkt.dns_packet.flags & flags.QR:
            self.read_response(pkt)
        else:
            self.read_request(pkt)

    def read_response(self, pkt):
        qid = pkt.dns_packet.id
        qname = pkt.dns_packet.question[0].name
        qclass = rclass.to_text(pkt.dns_packet.question[0].rdclass)
        qtype = rtype.to_text(pkt.dns_packet.question[0].rdtype)

        ropen = (pkt.dns_packet.rcode() == rcode.NOERROR and len(pkt.dns_packet.answer) > 0 and pkt.src_addr[0] in self.resolvers)
        logging.info("Response ip_id:%s tx_id:%s from %s for (%s %s %s) ans:%s", pkt.ip_header.id, qid, pkt.src_addr, str(qname), \
                    qclass, qtype, (str(pkt.dns_packet.answer[0][0]) if ropen else 'closed'))

        if ropen:
            for data in self.resolvers[pkt.src_addr[0]]:
                data.open = True
            del self.resolvers[pkt.src_addr[0]]

    def read_request(self, pkt):
        qid = pkt.dns_packet.id
        qname = pkt.dns_packet.question[0].name
        qnm = str(qname).lower()
        qclass = pkt.dns_packet.question[0].rdclass
        qtype = pkt.dns_packet.question[0].rdtype

        logging.info("Request ip_id:%s tx_id:%s from %s for (%s %s %s)", pkt.ip_header.id, qid, pkt.src_addr, \
                    str(qname), rclass.to_text(qclass), rtype.to_text(qtype))

        reply = message.make_response(pkt.dns_packet)
        # Lookup to see if this name is in one of our zone files
        self.tree.respond(pkt, reply)
        
        self.write(pkt.src_addr, reply.to_wire())
        
    def check_resolver(self, data):
        lst = self.resolvers[data.src_ip]
        lst.append(data)
        # Limit the number of probes that we send
        if len(lst) % 4 == 1:
            query = message.make_query('google.com.', rtype.A) # Arbitrary domain name
            logging.info('Testing if %s is an open resolver tx_id:%s', data.src_ip, query.id)
            self.write((data.src_ip, 53), query.to_wire()) 
        # Insure lists do not grow too large
        while len(lst) > 0 and lst[0].time < datetime.utcnow():
            del lst[0]

    def refresh_records(self):
        tree = dns_tree()
        for mapping in args.mapping:
            try:
                z = zone.from_file(mapping, relativize = False)
                for n in z:
                    node = dns_tree_node(n)
                    for rdataset in z[n].rdatasets:
                        node.rrsets.append(rrset.from_rdata_list(n, rdataset.ttl, rdataset))
                    tree.add(node)
            except Exception as e:
               logging.error('Error in mapping file %s: %s\n%s', mapping, e, traceback.format_exc())
        load_experiments(tree, self)
        self.tree = tree
        
if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='A simple authoritative DNS server implementation for experiments')
    parser.add_argument('-a', '--address', default='0.0.0.0:53', help='Address to bind upon')
    parser.add_argument('-m', '--mapping', nargs='+', default=[], help='File containing name to address mappings')
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
