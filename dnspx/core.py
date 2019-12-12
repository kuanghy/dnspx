# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import os
import time
import socket
import signal
import logging
import binascii
import threading
import socketserver

import dns.message

from . import config
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
            qmsg.question_str = "; ".join(str(q) for q in qmsg.question)
            qmsg.qtype = question.rdtype
            qmsg.qclass = question.rdclass
            qmsg.qprotocol = self.server.server_type
        except Exception:
            log.error(f"{client} query error: invalid DNS request")
            return response

        log.info(f"Query from {client}, question: {qmsg.question_str}")
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

        # 在 TCP DNS 协议中，前两个字节用于存储响应的长度
        data = data[2:]
        response = self.parse(data)

        if response:
            # 计算响应的长度
            length = binascii.unhexlify("%04x" % len(response))
            self.request.sendall(length + response)


class BaseSocketServer(socketserver.ThreadingMixIn):

    def __init__(self, server_address, RequestHandlerClass, nameservers=None,
                 ipv6=False):
        super().__init__(server_address, RequestHandlerClass)

        self.nameservers = nameservers
        self.ipv6 = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.dns_resolver = DNSResolver(nameservers)


class ThreadedUDPServer(BaseSocketServer, socketserver.UDPServer):

    server_type = "udp"


class ThreadedTCPServer(BaseSocketServer, socketserver.TCPServer):

    server_type = "tcp"

    # 允许地址重用
    allow_reuse_address = True


class DNSProxyServer(object):

    def __init__(self, server_address, nameservers=None, enable_tcp=False, enable_ipv6=False):
        self.server_address = server_address
        self.nameservers = nameservers
        self.enable_tcp = enable_tcp
        self.enable_ipv6 = enable_ipv6
        self._udp_server = None
        self._tcp_server = None

    def set_priority(self):
        curr_priority = os.getpriority(os.PRIO_PROCESS, 0)
        priority = int(config.PROCESS_PRIORITY)
        if curr_priority == priority:
            return
        if not config.IS_UNIX:
            log.warning("Priority setting only supports Unix platform")
            return
        if priority > 19:
            priority = 19
        if priority < -20:
            priority = -20
        os.setpriority(os.RIO_PROCESS, 0, priority)
        log.info(f"Set process priority to {priority}")

    def register_signal_handler(self):

        def handle_signal(signum, frame):
            if self._udp_server:
                self._udp_server.shutdown()
            if self._tcp_server:
                self._tcp_server.shutdown()
            raise SystemExit(f"Received signal {signum}")

        signal.signal(signal.SIGHUP, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

    def run(self):
        self.set_priority()
        self.register_signal_handler()

        self._udp_server = ThreadedUDPServer(
            self.server_address,
            UDPHandler,
            self.nameservers,
            self.enable_ipv6,
        )
        threading.Thread(target=self._udp_server.serve_forever).start()
        if self.enable_tcp:
            log.info("DNSPX tcp server is enabled")
            self._tcp_server = ThreadedTCPServer(
                self.server_address,
                TCPHandler,
                self.nameservers,
                self.enable_ipv6
            )
            threading.Thread(target=self._tcp_server.serve_forever).start()
        log.info("DNSPX server started on address '%s:%s'",
                 *self.server_address)

        try:
            while True:
                time.sleep(60)
        except SystemExit as e:
            log.warning(e)
        log.info("DNSPX server is shutting down")
