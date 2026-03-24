# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import os
import time
import socket
import signal
import struct
import logging
import platform
import threading
import socketserver
from importlib import import_module

import dns.rcode
import dns.message
from dns.message import Message as DNSMessage

from . import config
from .version import __version__
from .utils import cached_property, suppress, thread_sync, is_tty
from .utils import is_main_thread
from .resolve import DNSResolver, QueryContext
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
        self._start_time = None

    def parse(self, message):
        self._start_time = time.time()
        response = b''
        client = self.client_address[0]
        try:
            msg = dns.message.from_wire(message)
            qmsg = QueryContext(msg,
                                socket_family=self.server.address_family,
                                socket_type=self.server.socket_type)
            self.qmsg = qmsg
        except Exception as ex:
            log.error(f"Invalid DNS request from {client}, msg: {ex}")
            return response

        resolver = self.server.dns_resolver
        try:
            if self.is_network_anomaly():
                log.debug("Detected network anomaly, response using cache or "
                          "empty data")
                amsg = resolver.query_from_cache(qmsg, default=b'')
            else:
                amsg = resolver.query(qmsg)
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

        self.amsg = amsg
        response = amsg.to_wire() if isinstance(amsg, DNSMessage) else amsg
        return response

    def finish(self):
        qmsg = self.qmsg
        amsg = self.amsg

        cache_hit = False
        if isinstance(amsg, DNSMessage) and qmsg is not None:
            resolver = self.server.dns_resolver
            is_cache_enabled = config.ENABLE_DNS_CACHE and qmsg.is_query_op
            cached = resolver.has_cache(qmsg) if is_cache_enabled else False
            cache_hit = cached and not qmsg.is_multi_question
            if is_cache_enabled and not cached and not qmsg.is_multi_question:
                resolver.set_cache(qmsg, amsg)

        if self._start_time is not None and qmsg is not None:
            elapsed = (time.time() - self._start_time) * 1000
            rcode_s = (dns.rcode.to_text(amsg.rcode())
                       if isinstance(amsg, DNSMessage) else "-")
            cache_s = "cache:hit" if cache_hit else "cache:miss"
            log.info(
                f"[QUERY {self.client_address[0]}] [{qmsg.id} {qmsg.question_s}]"
                f" [{rcode_s} {elapsed:.3f}ms {cache_s}]"
            )


class UDPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        (data, sock) = self.request
        response = self.parse(data)

        if response:
            sock.sendto(response, self.client_address)


class TCPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        # 在 TCP DNS 协议中，前两个字节用于存储消息的长度
        length_data = self.request.recv(2)
        if len(length_data) < 2:
            log.warning("TCP request length data incomplete, received %d bytes",
                        len(length_data))
            return

        msg_length = int.from_bytes(length_data, byteorder='big')
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

        # 始终发送长度前缀：有响应时发长度+正文，无响应时发长度 0，避免客户端一直等待
        length = struct.pack('!H', len(response))
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
            # UDP 返回空响应，TCP 直接忽略（连接会被关闭）
            if self.socket_type == socket.SOCK_DGRAM:
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


class ControlServer(socketserver.TCPServer):
    """控制端口 TCP 服务器"""

    allow_reuse_address = True
    daemon_threads = True


class ControlHandler(socketserver.StreamRequestHandler):
    """控制端口请求处理器"""

    @property
    def dns_proxy(self):
        return self.server.dns_proxy

    def handle(self):
        try:
            line = self.rfile.readline().decode("utf-8").strip()
        except Exception:
            return
        if not line:
            return
        parts = line.split(None, 1)
        cmd = parts[0]
        args = parts[1] if len(parts) > 1 else ""
        try:
            response = self.dispatch(cmd, args)
        except Exception as ex:
            response = f"Error: {ex}"
        self.wfile.write(response.encode("utf-8") + b"\n")

    def dispatch(self, cmd, args):
        """分发控制命令"""
        handlers = {
            "status": self._ctl_status,
            "cache-stats": self._ctl_cache_stats,
            "cache-clear": self._ctl_cache_clear,
            "reload": self._ctl_reload,
        }
        handler = handlers.get(cmd)
        if not handler:
            return f"Unknown command: {cmd}"
        return handler(args)

    def _ctl_status(self, args):
        proxy = self.dns_proxy
        uptime = time.time() - proxy._start_time if proxy._start_time else 0
        hours, remainder = divmod(int(uptime), 3600)
        minutes, seconds = divmod(remainder, 60)
        days, hours = divmod(hours, 24)
        if days > 0:
            uptime_s = f"{days}d {hours}h {minutes}m {seconds}s"
        else:
            uptime_s = f"{hours}h {minutes}m {seconds}s"
        lines = [
            f"Version: {__version__}",
            f"Python: {platform.python_version()}",
            f"Uptime: {uptime_s}",
            f"Listen: {proxy.server_address[0]}:{proxy.server_address[1]}",
            f"TCP: {'enabled' if proxy.enable_tcp else 'disabled'}",
        ]
        loaded_paths = config.get_loaded_config_paths()
        if loaded_paths:
            lines.append("Config files:")
            for path in loaded_paths:
                lines.append(f"  - {path}")
        return "\n".join(lines)

    def _ctl_cache_stats(self, args):
        cache = self.dns_proxy.dns_resolver.query_cache
        lines = [
            f"Enabled: {config.ENABLE_DNS_CACHE}",
            f"Size: {cache.size()} / {config.DNS_CACHE_SIZE}",
            f"TTL: {config.DNS_CACHE_TTL}s",
            f"Auto refresh: {config.ENABLE_CACHE_REFRESH}",
        ]
        return "\n".join(lines)

    def _ctl_cache_clear(self, args):
        resolver = self.dns_proxy.dns_resolver
        count = resolver.query_cache.size()
        resolver.clear_cache()
        log.info("Cache cleared via control port, %s entries removed", count)
        return f"Cache cleared, {count} entries removed."

    def _ctl_reload(self, args):
        config.load_config(self.dns_proxy.config_path, reset=True)
        resolver = self.dns_proxy.dns_resolver
        for attr in ['nameservers', 'inland_nameservers', 'foreign_nameservers',
                     'plugins', '_socks_proxies', 'query_cache']:
            resolver.__dict__.pop(attr, None)
        self.dns_proxy._apply_extra_hosts(resolver)
        log.info("Resolver configuration reloaded via control port")
        return "Resolver configuration reloaded."


class DNSProxyServer(object):
    """DNS 代理服务器"""

    def __init__(self, server_address, nameservers=None, hosts_path=None,
                 enable_tcp=False, enable_ipv6=False,
                 control_server_address=None, config_path=None):
        self.server_address = server_address
        self.nameservers = nameservers
        self.hosts_path = hosts_path
        self.enable_tcp = enable_tcp
        self.enable_ipv6 = enable_ipv6
        self.control_server_address = control_server_address
        self.config_path = config_path

        self._udp_server = None
        self._tcp_server = None
        self._control_server = None

        self._udp_server_thread = None
        self._tcp_server_thread = None
        self._control_server_thread = None

        self._keep_running = True
        self._start_time = None

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
        self._apply_extra_hosts(resolver)
        log.debug("All nameservers: %s",
                  [str(item) for item in resolver.nameservers])
        return resolver

    def _apply_extra_hosts(self, resolver):
        """将命令行 --hosts-path 指定的 hosts 文件应用到 local_hosts 插件"""
        hosts_plugin = resolver.plugins.get("local_hosts")
        if not hosts_plugin:
            return
        if self.hosts_path:
            for path in hosts_plugin.fetch_config_files(self.hosts_path):
                hosts_plugin.hosts.update(hosts_plugin.parse_hosts_file(path))
        log.debug("All local hosts size %s", len(hosts_plugin.hosts))

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
        if self._control_server:
            self._control_server.shutdown()
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
        if config.ENABLE_CONTROL_SERVER:
            from .utils import parse_ip_port
            ctl_addr = (
                self.control_server_address or config.CONTROL_SERVER_LISTEN
            )
            ctl_ip, ctl_port = parse_ip_port(ctl_addr)
            ctl_port = ctl_port or 8051
            self._control_server = ControlServer(
                (ctl_ip, ctl_port), ControlHandler
            )
            self._control_server.dns_proxy = self
            self._control_server_thread = threading.Thread(
                target=self._control_server.serve_forever,
                name="ControlServerThread",
            )
            self._control_server_thread.daemon = True
            self._control_server_thread.start()
            log.info("Control server started on '%s:%s'", ctl_ip, ctl_port)

        log.info("DNSPX server started on address '%s:%s'",
                 *self.server_address)

        self._keep_running = True
        self._start_time = time.time()
        self.dns_resolver.load_cache()

        last_evict_cache_time = time.time()
        try:
            while True:
                if not self._keep_running:
                    log.info("keep_running is set to %s", self._keep_running)
                    break

                time.sleep(3)

                # 定时刷新缓存，并清理过期的缓存，同时持久化缓存
                if time.time() - last_evict_cache_time >= 600:
                    with suppress(Exception, logger=log, loglevel="warning"):
                        if config.ENABLE_CACHE_REFRESH:
                            self.dns_resolver.refresh_cache()
                        evicted_count = self.dns_resolver.evict_cache()
                        remain_count = self.dns_resolver.query_cache.size()
                        log.debug("evict cache done, %s evicted, %s remained",
                                  evicted_count, remain_count)
                        self.dns_resolver.save_cache()
                        __import__("gc").collect()
                        last_evict_cache_time = time.time()
        except (SystemExit, Exception) as ex:
            log.warning(ex)

        with suppress(Exception, logger=log, loglevel="warning"):
            self.dns_resolver.save_cache()

        log.info("DNSPX server is shutting down")
