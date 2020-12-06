#!/usr/bin/python

import sys
import os
import logging
import traceback
import dpkt
import socket
import struct
import array
from threading import Thread
import ipaddress

class RawPacket:
    def __init__(self, network_header, transport_header, payload, raw):
        self.network_header = network_header
        self.transport_header = transport_header
        self.payload = payload
        self.raw = raw

    @property
    def src_addr(self):
        return (ipaddress.ip_address(self.network_header.src), self.transport_header.sport)

    @property
    def dst_addr(self):
        return (ipaddress.ip_address(self.network_header.dst), self.transport_header.dport)

    def to_json(self):
        raise NotImplementedError()

class UdpIpv4Packet(RawPacket):
    def to_json(self):
        return None

class UdpIpv6Packet(RawPacket):
    def to_json(self):
        return None

class RawListener:
    def __init__(self, addr, queue):
        self._socket, self._socket_silent = self._create_sockets(addr)
        self._running = False
        self._addr = addr
        self._queue = queue
        self._thread = Thread(target=self._loop)

    def _create_socket(addr):
        raise NotImplementedError()

    def start(self):
        self._running = True
        self._thread.start()

    def _loop(self):
        while self._running:
            try:
                data = self._socket.recv(4096) # Max datagram size
                packet = self._parse(data)

                # Ignore packets not destined for this destination
                if packet.dest_addr != self._addr:
                    continue

                # Deliver the packet for processing
                self._queue.put_nowait(packet)
            except (KeyboardInterrupt, SystemExit):
                raise
            except queue.Full:
                logging.error('Packet discarded because queue is full')
            except Exception:
                logging.exception('Unknown error')
        self.running = False

    def _parse(self, data):
        raise NotImplementedError()

    def close(self):
        self._running = False
        self._socket.close()
        self._socket_silent.close()
        self._thread.join()

    def write(self, daddr, data):
        raise NotImplementedError()

if struct.pack("H",1) == "\x00\x01": # big endian system
    def Udp_Checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return s & 0xffff
else: # little endian system
    def Udp_Checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s>>8)&0xff)|s<<8) & 0xffff

class RawUdpIpv4Listener(RawListener):
    def _create_sockets(self, addr):
        socket_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        socket_raw.bind((str(addr[0]), addr[1]))
        socket_silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        socket_silent.bind((str(addr[0]), addr[1]))
        return socket_raw, socket_silent

    def _parse(self, data):
        ippkt = dpkt.ip.IP(data)
        return UdpIpv4Packet(ippkt, ippkt.data, ippkt.data.data, data)

    def write(self, daddr, data):
        udpdata = dpkt.udp.UDP(sport = self._addr[1], dport = daddr[1], data = data)
        udpdata.ulen = len(udpdata)
        udpdata.sum = Udp_Checksum(self._addr[0].packed + daddr[0].packed + struct.pack('!BBH', 0, 17, len(udpdata)) + udpdata.pack())
        # Cannot generate own IP header (i.e., no spoofing?)
        #ipdata = dpkt.ip.IP(src = self._addr, dst = socket.inet_aton(daddr[0]), data = udpdata)
        self._socket.sendto(udpdata.pack(), (str(daddr[0]), daddr[1]))

class RawUdpIpv6Listener(RawListener):
    def _create_sockets(self, addr):
        socket_raw = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
        socket_raw.bind((str(addr[0]), addr[1], 0, 0))
        socket_silent = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        socket_silent.bind((str(addr[0]), addr[1], 0, 0))
        return socket_raw, socket_silent

    def _parse(self, data):
        ippkt = dpkt.ip6.IP6(data)
        return UdpIpv6Packet(ippkt, ippkt.data, ippkt.data.data, data)

    def write(self, daddr, data):
        udpdata = dpkt.udp.UDP(sport = self._addr[1], dport = daddr[1], data = data)
        udpdata.ulen = len(udpdata)
        udpdata.sum = Udp_Checksum(self._addr[0].packed + daddr[0].packed + struct.pack('!LHBB', len(udpdata), 0, 0, 17) + udpdata.pack())
        # Cannot generate own IP header (i.e., no spoofing?)
        #ipdata = dpkt.ip.IP(src = self._addr, dst = socket.inet_aton(daddr[0]), data = udpdata)
        self._socket.sendto(udpdata.pack(), (str(daddr[0].packed), daddr[1]))