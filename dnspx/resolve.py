# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import os
import glob
import logging
import ipaddress
from collections import namedtuple, OrderedDict

import dns.query
import dns.message
import dns.opcode
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
from dns.message import Message as DNSMessage
from dns.rdatatype import to_text as qtype2text

from cacheout import Cache

from . import config
from .utils import cached_property, thread_sync
from .error import DNSTimeout, DNSError, PluginExistsError


log = logging.getLogger(__name__)


def proxy_dns_query(qmsg, nameservers, timeout=3):
    if qmsg.qprotocol not in {"udp", "tcp"}:
        raise DNSError(f"unsupported dns query protocol '{qmsg.qprotocol}'")

    for host, port, *_ in nameservers:
        question_str = f"@{host}:{port} {qmsg.id} {qmsg.question_str}"
        try:
            if qmsg.qprotocol == "udp":
                amsg = dns.query.udp(qmsg, host, port=port, timeout=timeout)
            else:
                amsg = dns.query.tcp(qmsg, host, port=port, timeout=timeout)
        except Exception as e:
            _log = log.exception
            if isinstance(e, (OSError, DNSTimeout)):
                _log = log.warning
            _log(f"Proxy query failed, question: {question_str}, "
                 f"msg: {e}")
        else:
            log.debug(f"Proxy query successful, question: {question_str}, "
                      f"take {(amsg.time * 1000):.2f} msec")
            break
    else:
        raise DNSError("no servers could be reached")

    return amsg


class DNSResolver(object):

    def __init__(self, nameservers=None, timeout=3):
        self._nameservers = nameservers or []
        self.timeout = timeout

    @thread_sync()
    def _fetch_nameservers(self):
        servers = []
        NameServer = namedtuple("NameServer", ("ip", "port", "type", "comment"))
        NameServer.__new__.__defaults__ = (None, 53, "inland", None)
        for server in self._nameservers + (config.NAMESERVERS or []):
            if not isinstance(server, (tuple, list)):
                server = (server, 53)
            server = NameServer(*server)
            server = server._replace(port=int(server.port))
            servers.append(server)
        return servers

    @cached_property
    def nameservers(self):
        return self._fetch_nameservers()

    @cached_property
    def foreign_nameservers(self):
        servers = []
        all_nameservers = self.nameservers
        with thread_sync():
            for server in all_nameservers:
                if server.type == "foreign":
                    servers.append(server)
        return servers

    @staticmethod
    def _mount_plugin(target, name, plugin):
        if name in target:
            raise PluginExistsError("plugin '{}' exists".format(name))
        target[name] = plugin
        log.info(f"Mounted '{name}' plugin")

    @thread_sync()
    def _initialize_plugins(self):
        plugins = OrderedDict()
        if config.ENABLE_LOCAL_HOSTS:
            self._mount_plugin(
                plugins, "local_hosts", LocalHostsPlugin()
            )
        if config.ENABLE_FOREIGN_RESOLVER:
            self._mount_plugin(
                plugins, "foreign_resolver",
                ForeignResolverPlugin(self.foreign_nameservers, self.timeout)
            )
        return plugins

    @cached_property
    def plugins(self):
        return self._initialize_plugins()

    @thread_sync()
    def mount_plugin(self, name, plugin):
        """挂载插件

        需要为插件指定一个唯一的名字，插件需为一个可调用对象，接受一个查询消息对象参数
        如果插件返回一个 DNSMessage 对象，则用该返回值作为解析结果
        如果插件返回 True，则表示执行成功，返回 False 则表示执行失败
        """
        self._mount_plugin(self.plugins, name, plugin)

    def unload_plugin(self, name):
        self.plugins.pop(name, None)

    def run_plugins(self, qmsg):
        """运行插件

        如果有插件返回 DNSMessage 对象，则用用该返回值作为解析结果返回，
        如果有多个插件返回 DNSMessage 对象，则以最后一个插件的返回值作为解析结果返回
        如果没有插件返回 DNSMessage 对象，且有插件执行成功，则返回 True
        如果没有插件执行成功则返回 False
        """
        is_successful = False
        resp_msg = None
        for name, plugin in self.plugins.items():
            ret = plugin(qmsg)
            if isinstance(ret, DNSMessage):
                resp_msg = ret
            if ret is not False:
                is_successful = True
        return is_successful if resp_msg is None else resp_msg

    @cached_property
    def query_cache(self):
        return Cache(
            maxsize=config.DNS_CACHE_SIZE,
            ttl=config.DNS_CACHE_TTL,
        )

    @staticmethod
    def _get_cache_key(qname, qclass, qtype):
        return f"{qname}_{qclass}_{qtype}"

    def set_cache(self, name, qclass, qtype, amsg):
        key = self._get_cache_key(name, qclass, qtype)
        self.query_cache.set(key, amsg)

    def get_cache(self, name, qclass, qtype):
        key = self._get_cache_key(name, qclass, qtype)
        return self.query_cache.get(key)

    def _proxy_query(self, qmsg):
        return proxy_dns_query(qmsg, self.nameservers, self.timeout)

    def query(self, qmsg):
        name = qmsg.qname_str
        qclass = qmsg.qclass
        qtype = qmsg.qtype
        question_str = qmsg.question_str
        is_query_op = (qmsg.opcode() == dns.opcode.QUERY)
        enable_dns_cache = config.ENABLE_DNS_CACHE
        if is_query_op:
            if enable_dns_cache:
                data = self.get_cache(name, qclass, qtype)
                if data:
                    log.debug(f"Query '{question_str}' cache is valid, use it")
                    data.id = qmsg.id
                    return data
            if qtype in {dns.rdatatype.A,  dns.rdatatype.AAAA}:
                ret = self.run_plugins(qmsg)
                if isinstance(ret, DNSMessage):
                    if enable_dns_cache:
                        self.set_cache(name, qclass, qtype, ret)
                    return ret

        amsg = self._proxy_query(qmsg)
        if is_query_op and enable_dns_cache:
            self.set_cache(name, qclass, qtype, amsg)
        return amsg


class LocalHostsPlugin(object):

    def __init__(self, hosts=None):
        self._hosts = hosts or {}

        self._ipv4_local = "127.0.0.1"
        self._ipv6_local = "::1"

    def get_sys_hosts_path(self):
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

        with open(path) as fp:
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
        name = qmsg.qname_str
        host = self.hosts.get(name)
        if not host:
            return True

        if qmsg.qtype == dns.rdatatype.AAAA and host == self._ipv4_local:
            host = self._ipv6_local
        elif qmsg.qtype == dns.rdatatype.A and host == self._ipv6_local:
            host = self._ipv4_local

        log.debug(f"Domain '{name}' in local hosts, host is '{host}'")
        ip_addr = ipaddress.ip_address(host)
        if qmsg.qtype == dns.rdatatype.A and ip_addr.version == 4:
            rd = dns.rdtypes.IN.A.A(
                dns.rdataclass.IN,
                dns.rdatatype.A,
                host,
            )
        elif qmsg.qtype == dns.rdatatype.AAAA and ip_addr.version == 6:
            rd = dns.rdtypes.IN.AAAA.AAAA(
                dns.rdataclass.IN,
                dns.rdatatype.AAAA,
                host,
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

    def __init__(self, nameservers=None, timeout=3):
        self.nameservers = nameservers or [
            ("8.8.8.8", 53)  # Google Public DNS
            ("1.1.1.1", 53)  # CloudFlare DNS
        ]
        self.timeout = timeout

    @thread_sync()
    def _fetch_foreign_domains(self):
        patterns = set()
        external_config_prefix = "ext:"
        for pattern in config.FOREIGN_DOMAINS:
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

    full_match_prefix = "full:"
    domain_match_prefix = "domain:"

    def __call__(self, qmsg):
        name = qmsg.qname_str
        is_foreign = False
        for pattern in self.foreign_domains:
            if pattern.startswith(self.full_match_prefix):
                pattern = pattern.replace(self.full_match_prefix, "")
                if name == pattern:
                    is_foreign = True
                    break
            elif pattern.startswith(self.domain_match_prefix):
                pattern = pattern.replace(self.domain_match_prefix, "")
                if name.endswith(pattern):
                    is_foreign = True
                    break
            else:
                if pattern in name:
                    is_foreign = True
                    break

        if not is_foreign:
            return True

        log.debug(f"Domain '{name}' is foreign, using foreign nameserver")
        try:
            amsg = proxy_dns_query(qmsg, self.nameservers, self.timeout)
        except Exception as e:
            log.debug(f"Foreign nameservers resolve failed: {e}")
            return False

        return amsg
