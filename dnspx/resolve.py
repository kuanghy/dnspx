# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import os
import time
import glob
import random
import socket
import struct
import logging
import ipaddress
from importlib import import_module
from collections import OrderedDict
from functools import lru_cache
from urllib.parse import urlparse
from urllib.request import (
    Request as HTTPRequest,
    ProxyHandler as HTTPProxyHandler,
    build_opener as build_http_opener,
)

import dns.query
import dns.message
import dns.flags
import dns.opcode
import dns.rcode
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.IN.HTTPS
import dns.rdtypes.svcbbase as dns_svcb
from dns.rdtypes.svcbbase import ParamKey as SVCBParamKey
from dns.message import Message as DNSMessage, BadEDNS as BadEDNSMessage
from dns.query import BadResponse as BadDNSResponse
from dns.rdatatype import to_text as qtype2text

from cacheout import LRUCache as Cache

from . import config
from .utils import (
    cached_property,
    thread_sync,
    check_internet_socket,
)
from .error import (
    DNSTimeout,
    DNSUnreachableError,
    PluginExistsError,
)


OPCODE_QUERY = dns.opcode.QUERY
RCODE_NOERROR = dns.rcode.NOERROR

QTYPE_A = dns.rdatatype.A
QTYPE_AAAA = dns.rdatatype.AAAA
QTYPE_HTTPS = dns.rdatatype.HTTPS
QTYPE_PTR = dns.rdatatype.PTR


log = logging.getLogger(__name__)


def patch_qmsg_attrs(msg):
    """为查询消息对象添加一些属性，方便后续处理

    这里仅处理最后一个 question，对于多个 question 的消息无意义，因为
    内置解析器只对有单个 question 的请求做特殊处理，如本地自定义域解析，缓存等，
    对于有多个 question 的请求，内置解析器直接做转发处理
    """
    question = msg.question[-1]
    msg.question_len = len(question)
    msg.qname = question.name
    msg.qname_s = question.name.to_text().strip('.')
    msg.question_s = " & ".join(str(q) for q in msg.question)
    msg.qtype = question.rdtype
    msg.qclass = question.rdclass
    msg.is_multi_question = len(question) > 1

    # 操作类型是否为标准查询
    msg.is_query_op = (msg.opcode() == OPCODE_QUERY)

    # 查询类型是否为 PTR
    msg.is_qtype_ptr = msg.qtype == QTYPE_PTR

    # DNS服务发现（DNS-Based Service Discovery, DNS-SD）
    msg.is_dns_sd = (
        '._dns-sd._udp.' in msg.qname_s or '._dns-sd._tcp.' in msg.qname_s
    )

    return msg


class NameServer(object):

    def __init__(self, address, type_="inland", comment=None, proxy=None):
        self.raw_address = address
        self.type_ = type_
        self.comment = comment
        self._proxy = proxy

    @classmethod
    def parse(cls, server):
        if isinstance(server, str):
            return cls(server)
        elif isinstance(server, (tuple, list)):
            return cls(*server[:4])
        elif isinstance(server, dict):
            return cls(
                server["address"],
                server.get("type", "inland"),
                server.get("comment"),
                server.get("proxy"),
            )
        else:
            raise ValueError(f'invalid dns server: {server!r}')

    @cached_property
    def _pr_address(self):
        return urlparse(
            self.raw_address if "//" in self.raw_address
            else f"//{self.raw_address}"
        )

    @cached_property
    def is_doh(self):
        # Check DNS over HTTP
        return self._pr_address.scheme in ("http", "https")

    @cached_property
    def is_foreign(self):
        return self.type_ == "foreign"

    @cached_property
    def host(self):
        return self._pr_address.hostname

    @cached_property
    def port(self):
        return self._pr_address.port if self._pr_address.port else (
            80 if self.is_doh else 53
        )

    @cached_property
    def address(self):
        return self.host, self.port

    @cached_property
    def proxy(self):
        return urlparse(self._proxy) if self._proxy else None

    def __repr__(self):
        return "NameServer(address={}, type={}, comment={}, proxy={})".format(
            self.raw_address, self.type_, self.comment, self._proxy
        )

    def __str__(self):
        return str(self.raw_address)


class _BaseQuery(object):

    def __init__(self, qmsg, nameserver, proxyserver=None, timeout=3):
        self.qmsg = qmsg
        self.nameserver = nameserver
        self.proxyserver = proxyserver
        self.timeout = timeout

        self.adata = b''

    @property
    def qdata(self):
        if isinstance(self.qmsg, DNSMessage):
            data = self.qmsg.to_wire()
        else:
            data = self.qmsg
        return data

    def _convert_message(self, wire):
        """转换报文数据包到 DNSMessage，如果转换失败则直接返回数据包"""
        try:
            msg = dns.message.from_wire(wire)
        except (BadEDNSMessage) as e:
            if isinstance(self.qmsg, DNSMessage):
                question_s = self.qmsg.question_s
                warn_msg = (f"convert wire failed, question: {question_s}, "
                            f"msg: {e}")
            else:
                warn_msg = f"convert wire failed: {e}"
            log.warning(warn_msg)
            msg = wire
        return msg

    @property
    def amsg(self):
        return self._convert_message(self.adata)

    def get(self):
        return self.amsg

    def __call__(self):
        return self.amsg, 0  # (answer_message, response_time)


class _UDPQuery(_BaseQuery):

    def __init__(self, qmsg, nameserver, proxyserver=None,
                 socket_family=socket.AF_INET, timeout=3):
        super().__init__(qmsg, nameserver, proxyserver, timeout)

        self.socket_family = socket_family
        self.socket = None

    @cached_property
    def address(self):
        return self.nameserver.address

    @cached_property
    def socket_type(self):
        return socket.SOCK_DGRAM

    def make_socket(self):
        if self.proxyserver:
            pysocks = import_module("socks")
            sock = pysocks.socksocket(self.socket_family, self.socket_type, 0)
            proxy_params = dict(
                proxy_type=getattr(pysocks, self.proxyserver.scheme.upper()),
                addr=self.proxyserver.hostname,
                port=self.proxyserver.port,
                rdns=True,
                username=self.proxyserver.username,
                password=self.proxyserver.password,
            )
            sock.set_proxy(**proxy_params)
        else:
            sock = socket.socket(self.socket_family, self.socket_type, 0)
        sock.settimeout(self.timeout)
        sock.connect(self.address)
        self.socket = sock
        return sock

    def get_sock(self):
        return self.socket

    def compute_expiration(self):
        if self.timeout is None:
            return None
        else:
            return time.time() + self.timeout

    def _wait_for_writable(self, sock, expiration):
        try:
            dns.query._wait_for_writable(sock, expiration)
        except AttributeError as ex:
            log.warning("Wait for writable error: %s", ex)

    def send_msg(self, expiration=None):
        sock = self.get_sock()
        self._wait_for_writable(sock, expiration)
        sent_time = time.time()
        length = sock.sendall(self.qdata)
        return length, sent_time

    def receive_msg(self, expiration=None):
        sock = self.get_sock()
        dns.query._wait_for_readable(sock, expiration)
        wire = sock.recv(65535)
        received_time = time.time()
        self.adata += wire
        return wire, received_time

    def __call__(self):
        self.make_socket()
        self.adata = b''
        expiration = self.compute_expiration()
        _, sent_time = self.send_msg(expiration)
        _, received_time = self.receive_msg(expiration)
        self.socket.close()
        response_time = received_time - sent_time
        amsg = self.amsg
        if isinstance(amsg, DNSMessage):
            amsg.time = response_time
            if (isinstance(self.qmsg, DNSMessage) and
                    not self.qmsg.is_response(amsg)):
                raise BadDNSResponse
        return amsg, response_time


class _TCPQuery(_UDPQuery):

    @cached_property
    def socket_type(self):
        return socket.SOCK_STREAM

    @property
    def qdata(self):
        if isinstance(self.qmsg, DNSMessage):
            data = self.qmsg.to_wire()
            data = struct.pack('!H', len(data)) + data
        else:
            data = self.qmsg
        return data

    @property
    def amsg(self):
        return self._convert_message(self.adata[2:])


class _HTTPQuery(_BaseQuery):

    @property
    def url(self):
        return str(self.nameserver)

    @property
    def _opener(self):
        if not self.proxyserver:
            return build_http_opener()

        if self.proxyserver.scheme.startswith("socks"):
            socks = import_module("socks")
            SocksiPyHandler = import_module("sockshandler").SocksiPyHandler
            socks_type = getattr(
                socks, "PROXY_TYPE_" + self.proxyserver.scheme.upper()
            )
            socks_handler = SocksiPyHandler(
                socks_type,
                self.proxyserver.hostname,
                self.proxyserver.port,
                rdns=True,
                username=self.proxyserver.username,
                password=self.proxyserver.password,
            )
            opener = build_http_opener(socks_handler)
        else:
            proxy_handler = HTTPProxyHandler({
                'http': self.proxyserver, 'https': self.proxyserver
            })
            opener = build_http_opener(proxy_handler)
        return opener

    def request(self):
        req = HTTPRequest(self.url, data=self.qdata, method="POST")
        req.add_header("Content-Type", "application/dns-message")
        with self._opener.open(req, timeout=self.timeout) as resp:
            if resp.status != 200:
                raise
            self.adata = resp.read()
        return self.adata

    def __call__(self):
        start_time = time.time()
        self.request()
        end_time = time.time()
        response_time = end_time - start_time
        amsg = self.amsg
        if isinstance(amsg, DNSMessage):
            amsg.time = response_time
            if (isinstance(self.qmsg, DNSMessage) and
                    not self.qmsg.is_response(amsg)):
                raise BadDNSResponse
        return amsg, response_time


def proxy_dns_query(qmsg, nameservers, proxyserver=None, timeout=3):
    if proxyserver:
        log.debug(f"Use proxy '{proxyserver.geturl()}' for question "
                  f"'{qmsg.question_s}'")
    qsocket_type = qmsg.qsocket_type
    for nameserver in nameservers:
        if qmsg.qname_s == nameserver.host:
            continue
        if nameserver.proxy:
            _proxyserver = nameserver.proxy
        elif config.ONLY_FOREIGN_PROXY and not nameserver.is_foreign:
            _proxyserver = None
        else:
            _proxyserver = proxyserver
        _timeout = (
            config.FOREIGN_QUERY_TIMEOUT  # 海外 DNS 速度较慢，超时可设长一点
            if nameserver.is_foreign and config.FOREIGN_QUERY_TIMEOUT > 0
            else timeout
        )
        if nameserver.is_doh:
            query = _HTTPQuery(
                qmsg, nameserver,
                proxyserver=_proxyserver,
                timeout=_timeout
            )
        else:
            Query = (_UDPQuery if qsocket_type == socket.SOCK_DGRAM
                     else _TCPQuery)
            query = Query(
                qmsg, nameserver,
                proxyserver=_proxyserver,
                socket_family=qmsg.qsocket_family,
                timeout=_timeout
            )
        try:
            amsg, response_time = query()
        except Exception as ex:
            _log = log.exception
            if isinstance(ex, (OSError, DNSTimeout, BadDNSResponse)):
                _log = log.warning
            _log(f"Proxy query [@{nameserver} {qmsg.id} {qmsg.question_s}] "
                 f"failed: {ex}")
        else:
            log.info(f"Proxy to {nameserver} [{qmsg.id} {qmsg.question_s}] "
                     f"{(response_time * 1000):.2f} msec")
            break
    else:
        raise DNSUnreachableError("no servers could be reached")

    return amsg


class DNSResolver(object):

    def __init__(self, nameservers=None, timeout=3):
        self._nameservers = nameservers or config.NAMESERVERS or []
        self.timeout = timeout

    @thread_sync()
    def _fetch_nameservers(self):
        return [NameServer.parse(server) for server in self._nameservers]

    @cached_property
    def nameservers(self):
        return self._fetch_nameservers()

    @cached_property
    def inland_nameservers(self):
        with thread_sync():
            servers = [item for item in self.nameservers if not item.is_foreign]
        return servers

    @cached_property
    def foreign_nameservers(self):
        with thread_sync():
            servers = [item for item in self.nameservers if item.is_foreign]
        return servers

    def check_nameservers(self, socket_type=socket.SOCK_DGRAM):
        for server in self.nameservers:
            if server.is_doh:
                continue
            ret = check_internet_socket(
                server.host,
                server.port,
                socket_type,
                self.timeout,
            )
            if ret:
                return ret
        return False

    @staticmethod
    def _mount_plugin(target, name, plugin):
        if name in target:
            raise PluginExistsError("plugin '{}' exists".format(name))
        target[name] = plugin
        log.info(f"Mounted '{name}' plugin")

    @thread_sync()
    def _load_plugins(self):
        plugins = OrderedDict()
        if config.ENABLE_LOCAL_HOSTS:
            self._mount_plugin(
                plugins, "local_hosts", LocalHostsPlugin()
            )
        if config.ENABLE_FOREIGN_RESOLVER:
            # 先尝试用海外域名服务器解析，海外域名服务器均失败后再尝试国内的域名服务器
            nameservers = self.foreign_nameservers + self.inland_nameservers
            self._mount_plugin(
                plugins, "foreign_resolver",
                ForeignResolverPlugin(nameservers)
            )
        if config.ENABLE_SPLIT_RESOLVE:
            self._mount_plugin(
                plugins, "split_resolver", SplitResolverPlugin()
            )
        return plugins

    @cached_property
    def plugins(self):
        return self._load_plugins()

    @thread_sync()
    def mount_plugin(self, name, plugin):
        """挂载查询插件

        需要为插件指定一个唯一的名字，插件需为一个可调用对象，接受一个查询消息对象参数
        如果插件返回一个 DNSMessage 对象，则用该返回值作为解析结果
        如果插件返回 True，则表示执行成功，返回 False 则表示执行失败
        """
        self._mount_plugin(self.plugins, name, plugin)

    def unmount_plugin(self, name):
        """卸载查询插件"""
        self.plugins.pop(name, None)
        log.info(f"Unmounted '{name}' plugin")

    def run_plugins(self, qmsg):
        """运行插件

        如果有插件返回一个非空值，则直接返回该值，所有插件均未返回非空值时返回 None
        """
        resp_msg = None
        for name, plugin in self.plugins.items():
            try:
                ret = plugin(qmsg)
            except Exception:
                log.exception(f"failed to run plugin {name!r}")
                continue
            if ret and not isinstance(ret, bool):
                resp_msg = ret
                break
            elif ret is False:
                log.warning(f"return False when running plugin {name!r}")
        return resp_msg

    @cached_property
    def query_cache(self):
        # 这里使用的 Cache 本身是线程安全的，操作时不必再加锁
        return Cache(maxsize=config.DNS_CACHE_SIZE, ttl=config.DNS_CACHE_TTL)

    def _get_cache_ttl(self):
        return config.DNS_CACHE_TTL + round(random.uniform(1, 60), 2)

    def set_cache(self, qmsg, amsg, ttl=None):
        key = (qmsg.qname_s, qmsg.qclass, qmsg.qtype)
        if ttl is None:
            if amsg.rcode() != RCODE_NOERROR:
                ttl = 10
            elif not amsg.answer:
                ttl = 30
            else:
                ttl = self._get_cache_ttl()
        self.query_cache.set(key, amsg, ttl=ttl)
        return True

    def get_cache(self, qmsg):
        key = (qmsg.qname_s, qmsg.qclass, qmsg.qtype)
        return self.query_cache.get(key)

    def has_cache(self, qmsg):
        key = (qmsg.qname_s, qmsg.qclass, qmsg.qtype)
        return self.query_cache.has(key)

    def clear_cache(self):
        return self.query_cache.clear()

    def evict_cache(self):
        return self.query_cache.evict()

    def refresh_cache(self):
        if not self.query_cache:
            return
        # 仅刷新最新使用的 1/3 缓存，但至少为 10 个
        size = max(round(self.query_cache.size() / 3), 10)
        keys = list(self.query_cache.keys())[-size:]
        count = 0
        for key in keys:
            name, qclass, qtype = key
            amsg = self.query_cache.get(key)
            if not amsg:
                continue
            qmsg = dns.message.make_query(
                name,
                rdtype=qtype,
                rdclass=qclass,
                flags=dns.flags.RD
            )
            qmsg = patch_qmsg_attrs(qmsg)
            qmsg.qsocket_family = socket.AF_INET
            qmsg.qsocket_type = socket.SOCK_DGRAM
            self.query(qmsg, bypass_cache=True)

            if config.ENABLE_DNS_CACHE and qmsg.is_query_op:
                self.set_cache(qmsg, amsg)

            count += 1

        log.debug("%s cache records were refreshed", count)

    @cached_property
    def _socks_proxies(self):
        proxies = set(config.PROXY_SERVERS or [])
        return [urlparse(proxy) for proxy in proxies]

    @property
    def proxyserver(self):
        return (
            random.choice(self._socks_proxies) if self._socks_proxies else None
        )

    def query_from_cache(self, qmsg, default=None):
        data = self.get_cache(qmsg)
        if data:
            data.id = qmsg.id
            log.debug(f"Query [{qmsg.question_s}] cache is valid, use it")
            return data
        else:
            return default

    def query(self, qmsg, bypass_cache=False):
        # Answer message
        amsg = None

        # 如果是 PTR 和 DNS-SD 请求，则直接返回 NXDOMAIN
        if qmsg.is_qtype_ptr or qmsg.is_dns_sd:
            amsg = dns.message.make_response(qmsg)
            amsg.set_rcode(dns.rcode.NXDOMAIN)
            amsg.flags |= dns.flags.RA
            return amsg

        # 仅对单个请求，且是 Query 查询操作时，执行插件和缓存查询
        if not qmsg.is_multi_question and qmsg.is_query_op:
            # 如果开启了缓存，则从缓存中查询到结果后直接返回
            if config.ENABLE_DNS_CACHE and not bypass_cache:
                amsg = self.query_from_cache(qmsg)
                if amsg:
                    return amsg

            # 仅对 A, AAAA, QTYPE_HTTPS 类型的查询执行插件
            if qmsg.qtype in {QTYPE_A, QTYPE_AAAA, QTYPE_HTTPS}:
                amsg = self.run_plugins(qmsg)

        if not amsg:
            amsg = proxy_dns_query(
                qmsg, self.nameservers,
                proxyserver=self.proxyserver,
                timeout=self.timeout
            )

        return amsg


class LocalHostsPlugin(object):

    def __init__(self, hosts=None):
        self._hosts = hosts or {}

        self._ipv4_local = "127.0.0.1"
        self._ipv6_local = "::1"

    def get_sys_hosts_path(self):
        if config.IS_WIN32:
            return r"C:\Windows\System32\drivers\etc\hosts"
        else:
            return "/etc/hosts"

    @staticmethod
    def fetch_config_files(path):
        if os.path.isfile(path):
            return [path]

        config_paths = []
        for sub_path in glob.iglob(os.path.join(path, "*")):
            if os.path.isfile(sub_path):
                config_paths.append(sub_path)
        return config_paths

    def get_hosts_config_paths(self):
        config_paths = [
            self.get_sys_hosts_path()
        ]

        for config_dir in config._CONFIG_DIRS:
            if not config_dir or not os.path.exists(config_dir):
                continue
            config_paths.append(os.path.join(config_dir, "hosts"))
            sub_config_dir = os.path.join(config_dir, "hosts.conf.d")
            config_paths.extend(self.fetch_config_files(sub_config_dir))

        if config.LOCAL_HOSTS_PATH:
            config_paths.extend(
                self.fetch_config_files(config.LOCAL_HOSTS_PATH)
            )

        return config_paths

    def parse_hosts_file(self, path):
        hosts = {}
        if not path or not os.path.exists(path):
            return hosts

        with open(path, encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                host_name = line.split()
                if len(host_name) > 1:
                    host, name = host_name[:2]
                else:
                    host, name = self._ipv4_local, host_name[0]
                hosts[name] = host
        if hosts:
            log.info(f"Load hosts file '{path}', size {len(hosts)}")
        return hosts

    def get_hosts_from_config(self):
        config_paths = self.get_hosts_config_paths()
        hosts = {}
        for config_path in config_paths:
            hosts.update(self.parse_hosts_file(config_path))
        return hosts

    @cached_property
    def hosts(self):
        return {**self.get_hosts_from_config(), **self._hosts}

    def __call__(self, qmsg):
        name = qmsg.qname_s
        host = self.hosts.get(name)
        if not host:
            return True

        if qmsg.qtype == QTYPE_AAAA and host == self._ipv4_local:
            host = self._ipv6_local
        elif qmsg.qtype == QTYPE_A and host == self._ipv6_local:
            host = self._ipv4_local

        log.debug(f"Domain '{name}' in local hosts, host is '{host}'")
        ip_addr = ipaddress.ip_address(host)
        if qmsg.qtype == QTYPE_A and ip_addr.version == 4:
            rd = dns.rdtypes.IN.A.A(
                dns.rdataclass.IN,
                QTYPE_A,
                host,
            )
        elif qmsg.qtype == QTYPE_AAAA and ip_addr.version == 6:
            rd = dns.rdtypes.IN.AAAA.AAAA(
                dns.rdataclass.IN,
                QTYPE_AAAA,
                host,
            )
        elif qmsg.qtype == QTYPE_HTTPS:
            parmas = {
                SVCBParamKey.ALPN: dns_svcb.ALPNParam([b'h2', b'h3'])
            }
            if ip_addr == 6:
                parmas[SVCBParamKey.IPV6HINT] = dns_svcb.IPv4HintParam([host])
            else:
                parmas[SVCBParamKey.IPV4HINT] = dns_svcb.IPv4HintParam([host])
            rd = dns.rdtypes.IN.HTTPS.HTTPS(
                dns.rdataclass.IN,
                QTYPE_HTTPS,
                priority=1,
                target='.',
                params=parmas,
            )
        else:
            log.warning(f"Local query '{name}' host is IPv{ip_addr.version}, "
                        f"not support {qtype2text(qmsg.qtype)} qtype")
            return True

        rrset = dns.rrset.RRset(qmsg.qname, qmsg.qclass, qmsg.qtype)
        rrset.add(rd)
        rrset.ttl = 86400  # a day

        amsg = dns.message.make_response(qmsg)
        amsg.answer.append(rrset)
        return amsg


class ForeignResolverPlugin(object):

    def __init__(self, nameservers=None):
        self.nameservers = nameservers or [
            ("8.8.8.8", 53),  # Google Public DNS
            ("1.1.1.1", 53),  # CloudFlare DNS
        ]

    @cached_property
    def _socks_proxies(self):
        proxies = set(config.PROXY_SERVERS or [])
        return [urlparse(proxy) for proxy in proxies]

    @property
    def proxyserver(self):
        return (
            random.choice(self._socks_proxies) if self._socks_proxies else None
        )

    @thread_sync()
    def _fetch_foreign_domains(self):
        patterns = set()
        external_config_prefix = "ext:"
        if not config.FOREIGN_DOMAINS:
            foreign_domain_patterns = []
        elif isinstance(config.FOREIGN_DOMAINS, str):
            domain_group = config.FOREIGN_DOMAINS
            if domain_group.startswith("domain_group"):
                raise ValueError("invalid config FOREIGN_DOMAINS")
            foreign_domain_patterns = getattr(config, domain_group.upper())
        elif isinstance(config.FOREIGN_DOMAINS, (list, tuple, set)):
            foreign_domain_patterns = config.FOREIGN_DOMAINS
        else:
            raise ValueError("invalid config FOREIGN_DOMAINS")
        for pattern in foreign_domain_patterns:
            if pattern.startswith(external_config_prefix):
                config_path = pattern.replace(external_config_prefix, "")
                with open(config_path) as fp:
                    for line in fp:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        patterns.add(line)
            patterns.add(pattern)
        return patterns

    @cached_property
    def foreign_domains(self):
        return self._fetch_foreign_domains()

    @lru_cache(200)
    def check_foreign_domain(self, name):
        full_match_prefix = "full:"
        domain_match_prefix = "domain:"
        for pattern in self.foreign_domains:
            if pattern.startswith(full_match_prefix):
                pattern = pattern.replace(full_match_prefix, "")
                if name == pattern:  # 完全匹配
                    return True
            elif pattern.startswith(domain_match_prefix):
                pattern = pattern.replace(domain_match_prefix, "")
                if name.endswith(f'.{pattern}'):  # 仅匹配子域名
                    return True
            elif pattern == name or name.endswith(f".{pattern}"):
                return True
        return False

    def __call__(self, qmsg):
        name = qmsg.qname_s
        is_foreign = self.check_foreign_domain(name)
        if not is_foreign:
            return True

        log.debug(f"Domain '{name}' is foreign, using foreign nameserver")
        try:
            amsg = proxy_dns_query(
                qmsg, self.nameservers, proxyserver=self.proxyserver,
            )
        except Exception as ex:
            log.warning("failed to resolve [%s] using foreign nameservers: %s",
                qmsg.question_s, ex
            )
            return True if isinstance(ex, DNSUnreachableError) else False

        return amsg


class SplitResolverPlugin(object):

    @cached_property
    def split_resolve_map(self):
        mapping = {}
        if not config.SPLIT_RESOLVE_MAP:
            return mapping
        for domain_group, nameserver_group in config.SPLIT_RESOLVE_MAP.items():
            domain_group = domain_group.upper()
            nameserver_group = nameserver_group.upper()
            domain_group_list = getattr(config, domain_group)
            nameserver_group_list = getattr(config, nameserver_group)
            if domain_group_list and nameserver_group_list:
                mapping[domain_group] = nameserver_group
        return mapping

    @thread_sync()
    def _fetch_grouped_nameservers(self):
        mapping = {}
        for nameserver_group in self.split_resolve_map.values():
            nameserver_group_list = getattr(config, nameserver_group)
            mapping[nameserver_group] = [
                NameServer.parse(server) for server in nameserver_group_list
            ]
        return mapping

    @cached_property
    def grouped_nameservers(self):
        return self._fetch_grouped_nameservers()

    @lru_cache(200)
    def match_domain(self, name, domain_group_name):
        full_match_prefix = "full:"
        domain_match_prefix = "domain:"
        domain_patterns = getattr(config, domain_group_name.upper())
        for pattern in domain_patterns:
            if pattern.startswith(full_match_prefix):
                pattern = pattern.replace(full_match_prefix, "")
                if name == pattern:  # 完全匹配
                    return True
            elif pattern.startswith(domain_match_prefix):
                pattern = pattern.replace(domain_match_prefix, "")
                if name.endswith(f'.{pattern}'):  # 仅匹配子域名
                    return True
            elif pattern == name or name.endswith(f".{pattern}"):
                return True
        return False

    def __call__(self, qmsg):
        name = qmsg.qname_s
        for domain_group, nameserver_group in self.split_resolve_map.items():
            if not self.match_domain(name, domain_group):
                continue
            log.debug("Domain '%s' matches %s, using %s to resolve",
                      name, domain_group, nameserver_group)
            nameservers = self.grouped_nameservers[nameserver_group]
            try:
                return proxy_dns_query(qmsg, nameservers)
            except Exception as ex:
                msg = "failed to resolve [%s] using %s: %s" % (
                    qmsg.question_s, nameserver_group, ex
                )
                if isinstance(ex, DNSUnreachableError):
                    log.debug(msg)
                    return True
                else:
                    log.warning(msg)
                    return False

        return True
