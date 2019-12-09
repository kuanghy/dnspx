# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import socket
import logging
import socketserver

import dns.message

from .resolve import


log = logging.getLogger(__name__)


class DNSHandler():

    def parse(self, message):
        response = ""

        try:
            qmsg = dns.message.from_wire(message)
        except Exception:
            log.error(f"{self.client_address[0]}: ERROR: invalid DNS request")
            return response

        DNSResolver()

        return response


class UDPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        (data, socket) = self.request
        response = self.parse(data)

        if response:
            socket.sendto(response, self.client_address)


class TCPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)

        # Remove the addition "length" parameter used in the
        # TCP DNS protocol
        data = data[2:]
        response = self.parse(data)

        if response:
            # Calculate and add the additional "length" parameter
            # used in TCP DNS protocol
            length = binascii.unhexlify("%04x" % len(response))
            self.request.sendall(length + response)


class SocketServer(socketserver.ThreadingMixIn):

    def __init__(self, server_address, RequestHandlerClass, nametodns, nameservers, ipv6, log):
        self.nametodns = nametodns
        self.nameservers = nameservers
        self.ipv6 = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.log = log

        super().__init__(server_address, RequestHandlerClass)


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):

    # Override default value
    allow_reuse_address = True

    # Override SocketServer.TCPServer to add extra parameters
    def __init__(self, server_address, RequestHandlerClass, nametodns, nameservers, ipv6, log):
        self.nametodns = nametodns
        self.nameservers = nameservers
        self.ipv6 = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.log = log

        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    pass


class DNSProxyServer(object):

    def run(object):
        nametodns = None
        nameservers = ["119.29.29.29"]
        ipv6 = True
        server = ThreadedUDPServer(("127.0.0.1", 53), UDPHandler, nametodns, nameservers, ipv6, log)
        server.serve_forever()
