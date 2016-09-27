#!/usr/bin/python

import sys
import os
import logging
import traceback
import dpkt
import socket

class RawPacket(object):
    def __init__(self, ippkt, udppkt, data):
        self.ip_header = ippkt
        self.udp_header = udppkt
        self.data = data
        self.src_addr = (socket.inet_ntoa(ippkt.src), udppkt.sport)

# Template for a raw socket udp server               
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
                self.read(RawPacket(ippkt, udppkt, udppkt.data))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                logging.error('Error on recv: %s\n%s', e, traceback.format_exc())
        self.running = False
        
    def read(self, pkt):
        pass
        
    def terminate(self):
        #logging.info('RawUdpServer terminating')
        self.running = False
        # Wait for run to return?
        self.sock.close()
        
    def write(self, daddr, data):
        udpdata = dpkt.udp.UDP(sport = self.port, dport = daddr[1], data = data)
        udpdata.ulen = len(udpdata)
        # Cannot generate own IP header (i.e., no spoofing?)
        #ipdata = dpkt.ip.IP(src = self.addr, dst = socket.inet_aton(daddr[0]), data = udpdata)
        self.sock.sendto(str(udpdata), daddr)
        
    def writefrom(self, daddr, saddr, data):
        udpdata = dpkt.udp.UDP(sport = saddr[1], dport = daddr[1], data = data)
        udpdata.ulen = len(udpdata)
        # Cannot generate own IP header (i.e., no spoofing?)
        #ipdata = dpkt.ip.IP(src = self.addr, dst = socket.inet_aton(daddr[0]), data = udpdata)
        self.sock.sendto(str(udpdata), daddr)
