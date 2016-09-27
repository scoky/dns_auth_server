#!/usr/bin/python

import os, sys
from datetime import datetime

import dns.zone as zone
import dns.rdatatype as rtype
import dns.rdataclass as rclass
import dns.flags as flags
import dns.rrset as rrset
import dns.rcode  as rcode
from dns import message
import dns.name as dnsname
from dns_tree import dns_tree,dns_tree_node

def load_experiments(tree, server):
    tree.add(recursion_tree_node())
    tree.add(dnstool_tree_node(server))
    tree.add(stat_tree_node())
    tree.add(chain_tree_node())
    # TODO: Add other tools HERE!

class recursion_tree_node(dns_tree_node):
    DEFAULT_NAME = 'recurse.exp.schomp.info.'
    def __init__(self):
        super(recursion_tree_node, self).__init__(dnsname.from_text(self.DEFAULT_NAME))
    
    def respond(self, query, reply):
        reply.answer.append(rrset.from_text('exp.schomp.info.', 0, rclass.IN, rtype.NS, 'ns1.schomp.info.'))

class dnstool_tree_node(dns_tree_node):
    DEFAULT_NAME = '*.dnstool.exp.schomp.info.'
    def __init__(self, server):
        super(dnstool_tree_node, self).__init__(dnsname.from_text(self.DEFAULT_NAME))
        self.server = server
    
    def respond(self, query, reply):
        qnm = str(query.dns_packet.question[0].name).tolower()
        if query.dns_packet.question[0].rdatatype == rtype.A:
            reply.flags |= flags.AA
            # Validate the query
            parsed = self.parseQueryString(qnm)
            exp_id = parsed['exp_id']
            step = parsed['step']
            if exp_id and step and not parsed['cname']:
                data = QueryData(exp_id, addr[0], addr[1], str(qname), qid, ip_header.id)
                self.server.inserter.addItem(data)
                self.server.check_resolver(data)

                # Return a cname from another random record
                reply.answer.append(rrset.from_text(qname, 10, rclass.IN, rtype.CNAME, \
                    "exp_id-%s.step-%s.cname.dnstool.exp.schomp.info." % (exp_id, step)))

            elif exp_id and step and parsed['cname']:
                data = QueryData(exp_id, addr[0], addr[1], str(qname), qid, ip_header.id)
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

class stat_tree_node(dns_tree_node):
    DEFAULT_NAME = '*.stat.exp.schomp.info.'
    def __init__(self):
        super(stat_tree_node, self).__init__(dnsname.from_text(self.DEFAULT_NAME))
    
    def respond(self, query, reply):
        # Need addresses and ip_header
        if query.dns_packet.question[0].rdatatype == rtype.TXT:
            reply.flags |= flags.AA
            reply.answer.append(rrset.from_text(query.dns_packet.question[0].name, 1, rclass.IN, rtype.TXT, \
                "RESOLVER=%s PORT=%s QUERY=%s TRANSACTION=%s IPID=%s TIME=%s" % (query.src_addr[0], \
                query.src_addr[1], query.dns_packet.question[0].name, query.dns_packet.id, query.ip_header.id, \
                datetime.utcnow())))

class chain_tree_node(dns_tree_node):
    DEFAULT_NAME = '*.chain.exp.schomp.info.'
    def __init__(self):
        super(chain_tree_node, self).__init__(dnsname.from_text(self.DEFAULT_NAME))
    
    def respond(self, query, reply):
        if query.question[0].rdatatype == rtype.A:
            qname = query.question[0].name
            reply.flags |= flags.AA
            reply.answer.append(rrset.from_text(qname, 3600, rclass.IN, rtype.NS, 'cname1.{0}'.format(qname)))
            reply.answer.append(rrset.from_text('cname1.{0}'.format(qname), 3600, rclass.IN, rtype.NS, 'cname2.{0}'.format(qname)))
            reply.answer.append(rrset.from_text('cname2.{0}'.format(qname), 3600, rclass.IN, rtype.A, '1.2.3.4'))
