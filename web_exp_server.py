#!/usr/bin/python

import sys
import os
import logging
import argparse
import traceback
import mysql.connector
import dnslib as dl
from collections import defaultdict
from datetime import datetime
from json import dumps as json_dump
from circuits.web import Server, Controller
from raw_server import RawUdpServer
    
get_queries_db = ("SELECT src_ip, src_port, query, trans_id, ip_id "
               "FROM queries WHERE exp_id = %s AND time GREATER %s ")

class WebRoot(Controller):
    def result(self, exp_id=None):
        return json_dump([{ 'exp_id':exp_id, 'test':True }])

    def scan(self, exp_id=None):
        return str(exp_id)
        
        
def testOpenResolver(addr):
    

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
