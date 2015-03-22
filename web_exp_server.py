#!/usr/bin/python

import sys
import os
import logging
import argparse
import traceback
import mysql.connector
import dnslib as dl
from collections import defaultdict
from datetime import datetime,timedelta
from json import dumps as json_dump
from circuits.web import Server, Controller
from raw_server import RawUdpServer
import socket
import random
import time

status = dl.Bimap('status', {0:'closed', 1:'refused', 2:'open'})
series = dl.Bimap('series', {0:'unknown', 1:'incremental', 2:'decremental', 3:'repetitive', 4:'constant'})

# Heuristics for determining series type
def define_series(lst):
    # Too few data points
    if len(lst) <= 5:
        return series.unknown
    # Sorted in increasing order
    elif all(lst[i] <= lst[i+1] for i in xrange(len(lst)-1)):
        return series.incremental
    elif all(lst[i] >= lst[i+1] for i in xrange(len(lst)-1)):
        return series.decremental
    elif len(set(lst)) == 1:
        return series.constant
    elif len(set(lst)) <= len(lst) / 2: # At least have the data points are duplicates
        return series.repetitive

class QueryData(object):
    def __init__(self):
        self.ports = []
        self.queries = []
        self.trans_ids = []
        self.ip_ids = []
        self.open = False

    def insert(self, src_port, query, trans_id, ip_id, isopen):
        self.ports.append(src_port)
        self.queries.append(query)
        self.trans_ids.append(trans_id)
        self.ip_ids.append(ip_id)
        self.open |= isopen

    def is_0x20(self):
        ret = False
        for r in (q != q.lower() for q in self.queries):
            ret |= r
        return ret

    def compute(self):
        return { 'port_seq' : series[define_series(self.ports)],\
                 '0x20_encode' : self.is_0x20(),\
                 'transid_seq' : series[define_series(self.trans_ids)],\
                 'ipid_seq' : series[define_series(self.ip_ids)],\
                 'open' : bool(self.open) }

get_queries_db = ("SELECT src_ip, src_port, query, trans_id, ip_id, open "
               "FROM queries WHERE exp_id = %s AND time > %s ORDER BY qid ")
get_fdns_db = ("SELECT src_ip, open, preplay "
               "FROM fdns WHERE exp_id = %s AND time > %s ")
add_fdns_db = ("INSERT INTO fdns "
               "(exp_id, src_ip, open, preplay) "
               "VALUES (%s, %s, %s, %s)")

class WebRoot(Controller):
    def result(self, exp_id=None):
        if not exp_id:
            return ''

        data = { }
        data['rdns'] = defaultdict(QueryData)
        cnx = None
        try:
            cnx = mysql.connector.connect(user=args.username, password=args.password, host='localhost', database='dnstool')
            cursor = cnx.cursor()

            cursor.execute(get_queries_db, (exp_id, datetime.utcnow - timedelta(day=1)))
            for src_ip, src_port, query, trans_id, ip_id, isopen in cursor:
                data['rdns'][src_ip].insert(src_port, query, trans_id, ip_id, isopen)

            for src_ip in data['rdns']:
                data['rdns'][src_ip] = data['rdns'][src_ip].compute()

            cursor.execute(get_fdns_db, (exp_id, datetime.utcnow - timedelta(day=1)))
            for src_ip, isopen, preplay in cursor:
                data['fdns'] = {'ip':src_ip, 'open':bool(isopen), 'preplay':status[preplay]}

            cursor.close()
        except Exception as e:
            logging.error('Error on database: %s\n%s', e, traceback.format_exc())
        finally:
            if cnx:
                cnx.close()
        return json_dump(data)

    def scan(self, exp_id=None, ip=None):
        if not exp_id:
            return 'FAIL'
        if not ip:
            ip = self.request.remote.ip
        
        # Create a UDP socket to use in the experiment
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.bind(('0.0.0.0', 0))
        
        # Test if the remote IP address is an open resolver
        isopen = testOpenResolver(ip, sock)
        if isopen == status.open:
            vulnerable = testPreplay(exp_id, ip, sock)
        else:
            vulnerable = False
            # Expend the time that would have otherwise been used to test for preplay
            time.sleep(2.0)
            
        cnx = None
        try:
            cnx = mysql.connector.connect(user=args.username, password=args.password, host='localhost', database='dnstool')
            cursor = cnx.cursor()
            cursor.execute(add_fdns_db, (exp_id, ip, isopen, int(vulnerable)))
            cnx.commit()
            cursor.close()
        except Exception as e:
            logging.error('Error on database: %s\n%s', e, traceback.format_exc())
        finally:
            if cnx:
                cnx.close()
            
        sock.close()
        return 'DONE'
        
        
def testOpenResolver(ip, sock):
    try:
        # Try 2 times
        for step in range(2):
            query = dl.DNSRecord.question("google.com") # Arbitrary domain name
            sock.sendto(query.pack(), (ip, 53))
            time.sleep(0.001)

        sock.settimeout(2.0)
        data, saddr = sock.recvfrom(4096)
        if saddr[0] == ip:
            ans = dl.DNSRecord.parse(data)
            if ans.header.rcode == dl.RCODE.NOERROR and len(ans.rr) > 0:
                return status.open
            else:
                return status.refused
    except socket.timeout:
        pass
    except Exception as e:
        logging.error('Error on open test: %s\n%s', e, traceback.format_exc())
    return status.closed
    
def testPreplay(exp_id, ip, sock):
    raw_sock = RawUdpServer(('0.0.0.0', 53))
    try:
        # Try 2 times
        for step in range(2):
            qname = "exp_id-%s.preplay-%s.dnstool.exp.schomp.info" % (exp_id, step)
            adata = '.'.join(map(str, [random.randint(0,255) for i in range(4)]))
            
            # Send a query to the fdns
            query = dl.DNSRecord.question(qname)
            sock.sendto(query.pack(), (ip, 53))
            
            time.sleep(0.001)
            
            # Send a fake answer
            ans = dl.DNSRecord(dl.DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q, a=dl.RR(query.q.qname, ttl=60, rdata=dl.A(adata)))
            raw_sock.write((ip, 53), ans.pack())
            
            time.sleep(0.001)
            
            # Send a second query for the same qname
            query = dl.DNSRecord.question(qname)
            sock.sendto(query.pack(), (ip, 53))
            
            # Receive an answer from the fdns
            sock.settimeout(2.0)
            # Expecting no more than 2 packets
            while True:
                try:
                    data, saddr = sock.recvfrom(4096)
                    ans = dl.DNSRecord.parse(data)
                    if saddr[0] == ip and ans.header.id == query.header.id and str(ans.a.rdata) == adata:
                        return True
                except socket.timeout:
                    break
    except Exception as e:
        logging.error('Error on preplay test: %s\n%s', e, traceback.format_exc())
    finally:
        raw_sock.terminate()
    return False

if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='A simple web server implementation for experiment')
    parser.add_argument('-a', '--address', default='127.0.0.1:8053', help='Address to bind upon')                                     
    parser.add_argument('-u', '--username', default='root')
    parser.add_argument('-p', '--password', default=None)
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help='only print errors')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='print debug info. --quiet wins if both are present')
    args = parser.parse_args()
    
    addr,port = args.address.split(':', 1)
    webserver = Server((addr, int(port)))
    WebRoot().register(webserver)

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

    webserver.run()
