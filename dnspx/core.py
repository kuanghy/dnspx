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
from dns.message import Message as DNSMessage

from . import config
from .utils import cached_property, thread_sync
from .resolve import DNSResolver
from .error import DNSTimeout, DNSUnreachableError


log = logging.getLogger(__name__)


class DNSHandler(object):

    DETECTED_NETWORK_ANOMALY = False

    def parse(self, message):
        response = b''
        client = self.client_address[0]
        try:
            qmsg = dns.message.from_wire(message)

            qmsg.qsocket_family = self.server.address_family  # IPv4 or IPv6
            qmsg.qsocket_type = self.server.socket_type       # UDP or TCP

            # 内置解析器只对有单个 question 的请求做特殊处理，如本地自定义域解析，缓存等
            # 对于有多个 question 的请求，内置解析器直接做转发处理
            question = qmsg.question[-1]
            qmsg.question_len = len(question)
            qmsg.qname = question.name
            qmsg.qname_str = question.name.to_text().strip('.')
            qmsg.question_str = " & ".join(str(q) for q in qmsg.question)
            qmsg.qtype = question.rdtype
            qmsg.qclass = question.rdclass
        except Exception:
            log.error(f"{client} query error: invalid DNS request")
            return response

        log.info(f"Query from {client}, question: {qmsg.id} "
                 f"{qmsg.question_str}")
        try:
            amsg = self.server.dns_resolver.query(qmsg)
            response = amsg.to_wire() if isinstance(amsg, DNSMessage) else amsg
        except Exception as e:
            _log = log.exception
            if isinstance(e, (DNSTimeout, DNSUnreachableError)):
                if not self.server.check_nameservers(self.server.socket_type):
                    with thread_sync():
                        self.__class__.DETECTED_NETWORK_ANOMALY = True
                _log = log.warning
            _log(f"DNS query failed, question: {qmsg.question_str}, msg: {e}")

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

    def __init__(self, server_address, RequestHandlerClass, dns_resolver,
                 address_family=socket.AF_INET):
        super().__init__(server_address, RequestHandlerClass)

        self.dns_resolver = dns_resolver
        self.address_family = address_family

        self.check_nameservers = dns_resolver.check_nameservers

    def process_request(self, request, client_address):
        if self.RequestHandlerClass.DETECTED_NETWORK_ANOMALY:
            if not self.check_nameservers():
                log.warning("Detected network anomaly, response to an empty data")
                self.socket.sendto(b'', client_address)
                return
            else:
                with thread_sync():
                    self.RequestHandlerClass.DETECTED_NETWORK_ANOMALY = False
                self.dns_resolver.clear_cache()
        super().process_request(request, client_address)


class ThreadedUDPServer(BaseSocketServer, socketserver.UDPServer):
    """多线程 UDP 服务器"""


class ThreadedTCPServer(BaseSocketServer, socketserver.TCPServer):
    """多线程 TCP 服务器"""

    # 允许地址重用
    allow_reuse_address = True


class DNSProxyServer(object):
    """DNS 代理服务器"""

    def __init__(self, server_address, nameservers=None, hosts_path=None,
                 enable_tcp=False, enable_ipv6=False):
        self.server_address = server_address
        self.nameservers = nameservers
        self.hosts_path = hosts_path
        self.enable_tcp = enable_tcp
        self.enable_ipv6 = enable_ipv6
        self._udp_server = None
        self._tcp_server = None

    @property
    def socket_family(self):
        return socket.AF_INET6 if self.enable_ipv6 else socket.AF_INET

    @cached_property
    def dns_resolver(self):
        timeout = config.QUERY_TIMEOUT
        log.info("Initializing resolver, timeout is %s seconds", timeout)
        resolver = DNSResolver(self.nameservers, timeout=timeout)
        pugins = resolver.plugins
        hosts_plugin = pugins.get("local_hosts")
        if hosts_plugin:
            if self.hosts_path:
                config_paths = hosts_plugin.fetch_config_files(self.hosts_path)
                hosts = {}
                for config_path in config_paths:
                    hosts.update(hosts_plugin.parse_hosts_file(config_path))
                hosts_plugin.hosts.update(hosts)
            log.debug("All local hosts size %s", len(hosts_plugin.hosts))
        return resolver

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
        os.setpriority(os.PRIO_PROCESS, 0, priority)
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
            self.dns_resolver,
            self.socket_family,
        )
        threading.Thread(target=self._udp_server.serve_forever).start()
        if self.enable_tcp:
            log.info("DNSPX tcp server is enabled")
            self._tcp_server = ThreadedTCPServer(
                self.server_address,
                TCPHandler,
                self.dns_resolver,
                self.socket_family
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
