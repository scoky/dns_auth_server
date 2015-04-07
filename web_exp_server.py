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
from json import dumps as json_dump, loads as json_load
from circuits.web import Server, Controller
from raw_server import RawUdpServer
import socket
import random
import time

status = dl.Bimap('status', {0:'closed', 1:'refused', 2:'open'})
series = dl.Bimap('series', {0:'unknown', 1:'incremental', 2:'decremental', 3:'repetitive', 4:'constant'})

SAMPLE_THRESHOLD=5
# Heuristics for determining series type
def define_series(lst):
    # Sorted in increasing order
    if len(lst) >= SAMPLE_THRESHOLD and all(lst[i] <= lst[i+1] for i in xrange(len(lst)-1)): # All values increment
        return series.incremental
    elif len(lst) >= SAMPLE_THRESHOLD and all(lst[i] >= lst[i+1] for i in xrange(len(lst)-1)): # All values decrement
        return series.decremental
    elif len(lst) >= SAMPLE_THRESHOLD and len(set(lst)) == 1:
        return series.constant
    elif len(lst) >= SAMPLE_THRESHOLD and len(set(lst)) <= len(lst) / 2: # At least half the data points are duplicates
        return series.repetitive
    elif any(all(0 <= s[i+1] - s[i] < 1000 for i in xrange(len(s)-1)) for s in sublists(lst, SAMPLE_THRESHOLD)): # Sequence of incrementing values
        return series.incremental
    elif any(all(0 <= s[i] - s[i+1] < 1000 for i in xrange(len(s)-1)) for s in sublists(lst, SAMPLE_THRESHOLD)): # Sequence of decrementing values
        return series.decremental
    return series.unknown
    
def sublists(lst, n):
    return (lst[i:i+n] for i in range(len(lst) - n + 1))

class QueryData(object):
    def __init__(self):
        self.src_ip = None
        self.ports = []
        self.queries = []
        self.trans_ids = []
        self.ip_ids = []
        self.open = False
        self.tx_times = []

    def insert(self, src_ip, src_port, query, trans_id, ip_id, isopen, txtime):
        self.src_ip = src_ip
        self.ports.append(src_port)
        self.queries.append(query)
        self.trans_ids.append(trans_id)
        self.ip_ids.append(ip_id)
        self.open |= isopen
        self.tx_times.append(txtime)

    def is_0x20(self):
        ret = False
        for r in (q != q.lower() for q in self.queries):
            ret |= r
        return ret
        
    def get_times(self):
        if len(self.tx_times) > 0:
            return [(t-self.tx_times[0]).total_seconds() for t in self.tx_times]
        else:
            return []

    def compute(self):
        return { 'ip' : self.src_ip,\
                 'port_seq' : series[define_series(self.ports)],\
                 'ports' : self.ports,\
                 '0x20_encode' : self.is_0x20(),\
                 'transid_seq' : series[define_series(self.trans_ids)],\
                 'transids' : self.trans_ids,\
                 'ipid_seq' : series[define_series(self.ip_ids)],\
                 'ipids' : self.ip_ids,\
                 'open' : bool(self.open),\
                 'txtimes' : self.get_times() }

get_queries_db = ("SELECT src_ip, src_port, query, trans_id, ip_id, open, time "
               "FROM queries WHERE exp_id = %s AND time > %s ORDER BY qid ")
get_fdns_db = ("SELECT src_ip, open, preplay "
               "FROM fdns WHERE exp_id = %s AND time > %s ")
add_fdns_db = ("INSERT INTO fdns "
               "(exp_id, src_ip, open, preplay) "
               "VALUES (%s, %s, %s, %s)")

class WebRoot(Controller):
    def timing(self, exp_id=None, ip=None):
        if not exp_id:
            return 'FAIL'
        if not ip:
            ip = self.request.remote.ip

        data = ' '.join(self.request.body.readlines())
        logging.info('Timing post for %s, %s data: %s', exp_id, ip, data)

        data = json_load(data)
        return 'DONE'

    def result(self, exp_id=None):
        if not exp_id:
            return ''

        logging.info('Result request for %s', exp_id)

        data = { }
        data['rdns'] = defaultdict(QueryData)
        cnx = None
        try:
            cnx = mysql.connector.connect(user=args.username, password=args.password, host='localhost', database='dnstool')
            cursor = cnx.cursor()

            cursor.execute(get_queries_db, (exp_id, datetime.utcnow() - timedelta(days=1)))
            for src_ip, src_port, query, trans_id, ip_id, isopen, txtime in cursor:
                data['rdns'][src_ip].insert(src_ip, src_port, query, trans_id, ip_id, isopen, txtime)

            data['rdns'] = [v.compute() for v in sorted(data['rdns'].values(), key = lambda va: va.src_ip)]
            
            cursor.execute(get_fdns_db, (exp_id, datetime.utcnow() - timedelta(days=1)))
            for src_ip, isopen, preplay in cursor:
                data['fdns'] = {'ip':src_ip, 'open':isopen == status.open, 'preplay_vuln':bool(preplay)}

            cursor.close()
        except Exception as e:
            logging.error('Error on database: %s\n%s', e, traceback.format_exc())
        finally:
            if cnx:
                cnx.close()

        # Report back whether this is a complete experiment
        if 'fdns' in data and 'rdns' in data and len(data['rdns']) > 0:
            data['success'] = True
        else:
            data['success'] = False
        return json_dump(data, sort_keys=True, indent=4, separators=(',', ': '))

    def scan(self, exp_id=None, ip=None):
        if not exp_id:
            return 'FAIL'
        if not ip:
            ip = self.request.remote.ip
        
        start = datetime.utcnow()
        logging.info('Scan request for %s, %s', exp_id, ip)
        
        # Create a UDP socket to use in the experiment
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.bind(('0.0.0.0', 0))
        # Test if the remote IP address is an open resolver
        isopen = testOpenResolver(ip, sock)
        if isopen == status.open:
            vulnerable = testPreplay(exp_id, ip, sock)
        else:
            vulnerable = False
        # Cleanup
        sock.close()
            
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

        # Insure that the scan takes at least 5 seconds to allow enough time for the client to send many DNS requests
        remaining = timedelta(seconds=5) - (datetime.utcnow() - start)
        if remaining > datetime.timedelta(0):
            time.sleep(float(str(remaining.seconds)+'.'+str(remaining.microseconds)))
        return 'DONE'
        
        
def testOpenResolver(ip, sock):
    try:
        # Try 2 times
        for step in range(3):
            query = dl.DNSRecord.question("google.com") # Arbitrary domain name
            sock.sendto(query.pack(), (ip, 53))
            time.sleep(0.001)

        sock.settimeout(3.0)
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
        for step in range(3):
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
            sock.settimeout(3.0)
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
    parser.add_argument('-a', '--address', default='0.0.0.0:8053', help='Address to bind upon')
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
