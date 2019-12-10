# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import socket
import logging
import socketserver

import dns.message

from .resolve import DNSResolver


log = logging.getLogger(__name__)


class DNSHandler():

    def parse(self, message):
        response = b''
        client = self.client_address[0]
        try:
            qmsg = dns.message.from_wire(message)
            question = qmsg.question[-1]
            qmsg.qname = question.name
            qmsg.qname_str = question.name.to_text().strip('.')
            qmsg.qtype = question.rdtype
            qmsg.qclass = question.rdclass
        except Exception:
            log.error(f"{client} query error: invalid DNS request")
            return

        questions = "; ".join(str(q) for q in qmsg.question)
        log.info(f"Query from {client}, question: {questions}")
        try:
            amsg = self.server.dns_resolver.query(qmsg)
            response = amsg.to_wire()
        except Exception as e:
            log.error(f"DNS query error, query message: \n{qmsg}")
            log.exception(e)

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


class BaseSocketServer(socketserver.ThreadingMixIn):

    def __init__(self, server_address, RequestHandlerClass, nametodns, nameservers, ipv6, log):
        self.nametodns = nametodns
        self.nameservers = nameservers
        self.ipv6 = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.log = log

        self.dns_resolver = DNSResolver(nameservers)

        super().__init__(server_address, RequestHandlerClass)


class ThreadedUDPServer(BaseSocketServer, socketserver.UDPServer):

    pass


class ThreadedTCPServer(BaseSocketServer, socketserver.TCPServer):

    # Override default value
    allow_reuse_address = True


class DNSProxyServer(object):

    def run(object):
        nametodns = None
        nameservers = [("119.29.29.29", 53)]
        ipv6 = True
        server = ThreadedUDPServer(("127.0.0.1", 53), UDPHandler, nametodns, nameservers, ipv6, log)
        server.serve_forever()
