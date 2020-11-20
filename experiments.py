#!/usr/bin/python

import os, sys
from datetime import datetime
from collections import defaultdict

import dns.zone as zone
import dns.rdatatype as rtype
import dns.rdataclass as rclass
import dns.flags as flags
import dns.rrset as rrset
import dns.rcode  as rcode
from dns import message
import dns.name as dnsname
from dns_tree import dns_tree,dns_tree_node
from datetime import datetime,timedelta

def load_experiments(tree, server):
    tree.add(recursion_tree_node())
    tree.add(dnstool_tree_node(server))
    tree.add(stat_tree_node())
    tree.add(examine_tree_node())
    tree.add(chain_tree_node())
    # TODO: Add other tools HERE!

class recursion_tree_node(dns_tree_node):
    DEFAULT_NAME = 'recurse.exp.schomp.info.'
    def __init__(self):
        super(recursion_tree_node, self).__init__(dnsname.from_text(self.DEFAULT_NAME))
    
    def respond(self, query, reply):
        reply.authority.append(rrset.from_text(query.dns_packet.question[0].name, 0, rclass.IN, rtype.NS, 'ns1.schomp.info.'))

class dnstool_tree_node(dns_tree_node):
    DEFAULT_NAME = '*.dnstool.exp.schomp.info.'
    def __init__(self, server):
        super(dnstool_tree_node, self).__init__(dnsname.from_text(self.DEFAULT_NAME))
        self.server = server
    
    def respond(self, query, reply):
        qnm = str(query.dns_packet.question[0].name).lower()
        if query.dns_packet.question[0].rdtype == rtype.A:
            reply.flags |= flags.AA
            # Validate the query
            parsed = self.parseQueryString(qnm)
            exp_id = parsed['exp_id']
            step = parsed['step']
            if exp_id and step and not parsed['cname']:
                data = QueryData(exp_id, query.src_addr[0], query.src_addr[1], str(query.dns_packet.question[0].name), query.dns_packet.id, query.ip_header.id)
                self.server.inserter.addItem(data)
                self.server.check_resolver(data)

                # Return a cname from another random record
                reply.answer.append(rrset.from_text(query.dns_packet.question[0].name, 10, rclass.IN, rtype.CNAME, \
                    "exp_id-%s.step-%s.cname.dnstool.exp.schomp.info." % (exp_id, step)))

            elif exp_id and step and parsed['cname']:
                data = QueryData(exp_id, query.src_addr[0], query.src_addr[1], str(query.dns_packet.question[0].name), query.dns_packet.id, query.ip_header.id)
                self.server.inserter.addItem(data)
                self.server.check_resolver(data)

                # Return NXDOMAIN to stop the webpage fetch
                reply.set_rcode(rcode.NXDOMAIN)
    
    def parseQueryString(self, qnm):
        tokens = qnm.split('.')
        res = defaultdict(bool)
        for token in tokens:
            t = token.split('-', 1)
            if len(t) == 2:
                res[t[0]] = t[1]
            else:
                res[t[0]] = True
        return res
               
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

class stat_tree_node(dns_tree_node):
    DEFAULT_NAME = '*.stat.exp.schomp.info.'
    def __init__(self):
        super(stat_tree_node, self).__init__(dnsname.from_text(self.DEFAULT_NAME))
    
    def respond(self, query, reply):
        # Need addresses and ip_header
        if query.dns_packet.question[0].rdtype == rtype.TXT:
            reply.flags |= flags.AA
            reply.answer.append(rrset.from_text(query.dns_packet.question[0].name, 1, rclass.IN, rtype.TXT, \
                "RESOLVER=%s PORT=%s QUERY=%s TRANSACTION=%s IPID=%s TIME=%s" % (query.src_addr[0], \
                query.src_addr[1], query.dns_packet.question[0].name, query.dns_packet.id, query.ip_header.id, \
                datetime.utcnow())))

class examine_tree_node(dns_tree_node):
    DEFAULT_NAME = '*.examine.exp.schomp.info.'
    def __init__(self):
        super(examine_tree_node, self).__init__(dnsname.from_text(self.DEFAULT_NAME))
    
    def respond(self, query, reply):
        # Need addresses and ip_header
        if query.dns_packet.question[0].rdtype == rtype.TXT:
            txt = {
                'time' : str(datetime.utcnow()),
                'ip' : {
                    'tos' : query.ip_header.tos,
                    'len' : query.ip_header.len,
                    'src_ip' : query.src_addr[0],
                    'id' : query.ip_header.id,
                    'off' : query.ip_header.off,
                    'ttl' : query.ip_header.ttl,
                    'proto' : query.ip_header.p,
                    'cs' : query.ip_header.sum,
                    
                },
                'udp' : {
                    'src_port' : query.src_addr[1],
                    'len' : query.udp_header.ulen,
                    'cs' : query.udp_header.sum
                },
                'dns': {
                    'id' : query.dns_packet.id,
                    'flags' : "{0:b}".format(query.dns_packet.flags),
                    'edns' : query.dns_packet.edns,
                    'ednsflags' : query.dns_packet.ednsflags,
                    'payload' : query.dns_packet.payload,
                    'options' : [{'type' : option.otype, 'data' : option.data} for option in query.dns_packet.options]
                }
            }
            import json
            txt = json.dumps(txt).replace('"', '\\"')
            n = 255
            reply.flags |= flags.AA
            reply.answer.append(rrset.from_text_list(query.dns_packet.question[0].name, 1, rclass.IN, rtype.TXT, [txt[i:i+n] for i in range(0, len(txt), n)]))

class chain_tree_node(dns_tree_node):
    DEFAULT_NAME = '*.chain.exp.schomp.info.'
    def __init__(self):
        super(chain_tree_node, self).__init__(dnsname.from_text(self.DEFAULT_NAME))
    
    def respond(self, query, reply):
        if query.dns_packet.question[0].rdtype == rtype.A:
            qname = query.dns_packet.question[0].name
            reply.flags |= flags.AA
            reply.answer.append(rrset.from_text(qname, 3600, rclass.IN, rtype.NS, 'cname1.{0}'.format(qname)))
            reply.answer.append(rrset.from_text('cname1.{0}'.format(qname), 3600, rclass.IN, rtype.NS, 'cname2.{0}'.format(qname)))
            reply.answer.append(rrset.from_text('cname2.{0}'.format(qname), 3600, rclass.IN, rtype.A, '1.2.3.4'))
