# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import os
import time
import socket
import signal
import logging
import binascii
import platform
import threading
import socketserver
from importlib import import_module

import dns.message
from dns.message import Message as DNSMessage


from . import config
from .version import __version__
from .utils import cached_property, suppress, thread_sync, is_tty
from .utils import is_main_thread
from .resolve import DNSResolver, patch_qmsg_attrs, RCODE_NOERROR
from .error import DNSTimeout, DNSUnreachableError


log = logging.getLogger(__name__)


class DNSHandler(object):

    DETECTED_NETWORK_ANOMALY = False

    @classmethod
    def is_network_anomaly(cls):
        return cls.DETECTED_NETWORK_ANOMALY

    @classmethod
    def mark_network_anomaly(cls, state):
        cls.DETECTED_NETWORK_ANOMALY = state

    def setup(self):
        self.qmsg = None
        self.amsg = None

    def parse(self, message):
        response = b''
        client = self.client_address[0]
        try:
            qmsg = dns.message.from_wire(message)

            # NOTE:
            # 内置解析器只对有单个 question 的请求做特殊处理，如本地自定义域解析，缓存等
            # 对于有多个 question 的请求，内置解析器直接做转发处理
            patch_qmsg_attrs(qmsg)

            # XXX: 后续对这两个属性的依赖处理有问题，实际不需要，后续考虑去除
            qmsg.qsocket_family = self.server.address_family  # IPv4 or IPv6
            qmsg.qsocket_type = self.server.socket_type       # UDP or TCP
            self.qmsg = qmsg
        except Exception as ex:
            log.error(f"Invalid DNS request from {client}, msg: {ex}")
            return response

        log.info(f"[{qmsg.id} {qmsg.question_s}] from {client}")
        resolver = self.server.dns_resolver
        try:
            if self.is_network_anomaly():
                log.debug("Detected network anomaly, response using cache or "
                          "empty data")
                amsg = resolver.query_from_cache(qmsg, default=b'')
            else:
                amsg = resolver.query(qmsg)
            self.amsg = amsg
        except (DNSTimeout, DNSUnreachableError) as ex:
            if not self.server.check_nameservers(self.server.socket_type):
                with thread_sync():
                    self.mark_network_anomaly(True)
                log.warning("Network is marked as anomaly")
            amsg = resolver.query_from_cache(qmsg, default=b'')
            log.warning(f"[{qmsg.id} {qmsg.question_s}] query failed: {ex}")
        except Exception:
            amsg = b''
            log.exception(f"[{qmsg.id} {qmsg.question_s}] query failed")

        response = amsg.to_wire() if isinstance(amsg, DNSMessage) else amsg
        return response

    def finish(self):
        qmsg = self.qmsg
        amsg = self.amsg
        if isinstance(amsg, DNSMessage):
            rcode = amsg.rcode()
            is_no_error = rcode == RCODE_NOERROR
            if not is_no_error and not qmsg.is_qtype_ptr and not qmsg.is_dns_sd:
                log.debug("[%s %s] RCODE: %s", qmsg.id, qmsg.question_s, rcode)

            resolver = self.server.dns_resolver
            if (
                config.ENABLE_DNS_CACHE
                and qmsg.is_query_op
                and not resolver.has_cache(qmsg)
            ):
                resolver.set_cache(qmsg, amsg)


class UDPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        (data, socket) = self.request
        response = self.parse(data)

        if response:
            socket.sendto(response, self.client_address)


class TCPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        # 在 TCP DNS 协议中，前两个字节用于存储消息的长度
        length_data = self.request.recv(2)
        if len(length_data) < 2:
            log.warning("TCP request length data incomplete, received %d bytes",
                        len(length_data))

        msg_length = int.from_bytes(length_data, byteorder='big') if length_data else 0
        data = b''
        while len(data) < msg_length:
            chunk = self.request.recv(msg_length - len(data))
            if not chunk:
                break
            data += chunk

        if len(data) < msg_length:
            log.warning("TCP request data incomplete, expected %d bytes but "
                        "received %d bytes", msg_length, len(data))

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
        self.is_network_anomaly = RequestHandlerClass.is_network_anomaly
        self.mark_network_anomaly = RequestHandlerClass.mark_network_anomaly

    def process_request(self, request, client_address):
        thread_count = threading.active_count()
        if config.MAX_THREAD_NUM > 0 and thread_count >= config.MAX_THREAD_NUM:
            log.warning("Too many threads, current number of threads: %s",
                        thread_count)
            self.socket.sendto(b'', client_address)
            return
        if self.is_network_anomaly() and self.check_nameservers():
            with thread_sync():
                self.mark_network_anomaly(False)
            log.info("Network has been restored")
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

        self._udp_server_thread = None
        self._tcp_server_thread = None

        self._keep_running = True

    @property
    def socket_family(self):
        return socket.AF_INET6 if self.enable_ipv6 else socket.AF_INET

    @cached_property
    def dns_resolver(self):
        log.info("Initializing resolver")
        timeout = config.QUERY_TIMEOUT
        log.info("Query timeout: %s, foreign query timeout: %s",
                 timeout, config.FOREIGN_QUERY_TIMEOUT)
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
        log.debug("All nameservers: %s",
                  [str(item) for item in resolver.nameservers])
        return resolver

    def set_priority(self):
        if not hasattr(os, "getpriority") or not hasattr(os, "setpriority"):
            return
        try:
            curr_priority = os.getpriority(os.PRIO_PROCESS, 0)
        except Exception as ex:
            log.warning(f"Get process priority error: {ex}")
            return
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
        try:
            os.setpriority(os.PRIO_PROCESS, 0, priority)
        except Exception as ex:
            log.warning(f"Set process priority error: {ex}")
        else:
            log.info(f"Set process priority to {priority}")

    def set_proctitle(self):
        if is_tty():
            return
        try:
            spt = import_module("setproctitle")
        except ImportError as ex:
            log.debug(f"{ex}")
            return
        try:
            spt.setproctitle(config.PROCESS_TITLE)
        except Exception as ex:
            log.debug(f"Set process title error: {ex}")

    def stop(self):
        if self._udp_server:
            self._udp_server.shutdown()
        if self._tcp_server:
            self._tcp_server.shutdown()
        self._keep_running = False

    def register_signal_handler(self):
        if config.IS_WINDOWS and not is_main_thread():
            log.info("This is not main thread, skip register signal handler")
            return

        def handle_signal(signum, frame):
            self.stop()
            raise SystemExit(f"Received signal {signum}")

        for sig in ("SIGHUP", "SIGINT", "SIGTERM"):
            sig = getattr(signal, sig, None)
            if sig:
                signal.signal(sig, handle_signal)

    def run(self):
        self.register_signal_handler()
        self.set_priority()
        self.set_proctitle()
        log.debug("DNSPX version %s, Python version %s",
                  __version__, platform.python_version())

        if config.APP_PATH:
            log.debug("Change working directory to '%s'", config.APP_PATH)
            os.chdir(config.APP_PATH)
        if config.APP_BUNDLE_PATH:
            log.debug("Application bundle path: %s", config.APP_BUNDLE_PATH)

        self._udp_server = ThreadedUDPServer(
            self.server_address,
            UDPHandler,
            self.dns_resolver,
            self.socket_family,
        )
        self._udp_server_thread = threading.Thread(
            target=self._udp_server.serve_forever,
            name="UDPServerThread",
        )
        self._udp_server_thread.daemon = True
        self._udp_server_thread.start()
        if self.enable_tcp:
            log.info("DNSPX tcp server is enabled")
            self._tcp_server = ThreadedTCPServer(
                self.server_address,
                TCPHandler,
                self.dns_resolver,
                self.socket_family
            )
            self._tcp_server_thread = threading.Thread(
                target=self._tcp_server.serve_forever,
                name="TCPServerThread",
            )
            self._tcp_server_thread.daemon = True
            self._tcp_server_thread.start()
        log.info("DNSPX server started on address '%s:%s'",
                 *self.server_address)

        self._keep_running = True

        last_evict_cache_time = time.time()
        try:
            while True:
                if not self._keep_running:
                    log.info("keep_running is set to %s", self._keep_running)
                    break

                time.sleep(3)

                # 定时刷新缓存，并清理过期的缓存
                if time.time() - last_evict_cache_time >= 600:
                    with suppress(Exception, logger=log, loglevel="warning"):
                        if config.ENABLE_CACHE_REFRESH:
                            self.dns_resolver.refresh_cache()
                        evicted_count = self.dns_resolver.evict_cache()
                        remain_count = self.dns_resolver.query_cache.size()
                        log.debug("evict cache done, %s evicted, %s remained",
                                  evicted_count, remain_count)
                        __import__("gc").collect()
                        last_evict_cache_time = time.time()
        except (SystemExit, Exception) as ex:
            log.warning(ex)
        log.info("DNSPX server is shutting down")
