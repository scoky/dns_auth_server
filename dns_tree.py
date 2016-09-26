#!/usr/bin/python

import os, sys

import dns.zone as zone
import dns.rdatatype as rtype
import dns.rdataclass as rclass
import dns.flags as flags
import dns.rrset as rrset
import dns.rcode  as rcode
from dns import message
import dns.name as dnsname

class dns_tree_node(object):
    def __init__(self, name):
        self.name = name
        self.parent = None
        self.children = []
        self.rrsets = []
        
    def respond(self, query, response):
        for rr in self.rrsets:
            if rr.rdclass == query.question[0].rdclass and rr.rdtype == query.question[0].rdtype:
                response.answer.append(rr)
                reply.flags |= flags.AA
                return
        # Not present, return NODATA

    def __repr__(self):
        return self.name.__repr__()
    
    def __str__(self):
        return self.name.__str__()

class dns_tree(object):
    def __init__(self):
        self.roots = []
        
    def add(self, node):
        self._add(node, self.roots, None)
        
    def _add(self, node, nodes, parent):
        for n in nodes:
            reln, _, labels = n.name.fullcompare(node.name)
            if reln == dnsname.NAMERELN_SUPERDOMAIN:
                return self._add(node, n.children, n)
        node.parent = parent
        if node.name.is_wild(): # Wilds go at the end so as not to override more specific names
            nodes.append(node)
        else:
            nodes.insert(0, node)
            
    def find(self, name):
        return self._find(name, self.roots)
        
    def _find(self, name, nodes):
        for n in nodes:
            if n.name == name:
                return n
            if n.name.is_superdomain(name):
                return self._find(name, n.children)
        return None
        
    def respond(self, query, response):
        print "find {0}".format(query.question[0].name)
        return self._find(query, response, self.roots)
        
    def _respond(self, query, response, nodes):
        print nodes
        for n in nodes:
            reln, _, labels = n.name.fullcompare(query.question[0].name)
            if reln == dnsname.NAMERELN_SUPERDOMAIN: # Recurse into children
                print "{0} is super".format(n)
                return self._find(query, response, n.children)
            elif reln == dnsname.NAMERELN_EQUAL or (labels == len(n.name.labels) - 1 and n.name.is_wild()): # Found the node
                print "{0} matches".format(n)
                n.respond(query, response)
                return True
            elif reln == dnsname.NAMERELN_SUBDOMAIN: # Falls into a gap in the tree
                print "{0} is sub".format(n)
                return False
        # Does not match any node
        return False
        
    def __repr__(self):
        array = []
        self._print(self.roots, 0, array)
        output = ''
        for a in array:
            output += a.__repr__() + '\n'
        return output
        
    def __str__(self):
        array = []
        self._print(self.roots, 0, array)
        output = ''
        for a in array:
            output += str(a) + '\n'
        return output
        
    def _print(self, nodes, depth, array):
        if len(array) <= depth:
            array.append([])
        for n in nodes:
            array[depth].append(n)
            self._print(n.children, depth + 1, array)

def unit_test():
    t = dns_tree()
    t.add(dns_tree_node(dnsname.from_text('a.foo.bar.')))
    t.add(dns_tree_node(dnsname.from_text('b.a.foo.bar.')))
    t.add(dns_tree_node(dnsname.from_text('*.a.foo.bar.')))
    t.add(dns_tree_node(dnsname.from_text('c.t.a.foo.bar.')))
    t.add(dns_tree_node(dnsname.from_text('x.b.a.foo.bar.')))
    t.add(dns_tree_node(dnsname.from_text('y.foo.bar.')))
    
    t.find(message.make_query('a.foo.bar.', rtype.A), None)
    t.find(message.make_query('b.a.foo.bar.', rtype.A), None)
    t.find(message.make_query('l.a.foo.bar.', rtype.A), None)
    t.find(message.make_query('z.z.a.foo.bar.', rtype.A), None)
    t.find(message.make_query('a.c.t.a.foo.bar.', rtype.A), None)
