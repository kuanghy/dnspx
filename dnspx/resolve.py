# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import os
import glob
import logging
from collections import OrderedDict

import dns.query
import dns.message
import dns.opcode
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
from dns.message import Message as DNSMessage

from . import config
from .utils import cached_property
from .error import DNSError, PluginExistsError


log = logging.getLogger(__name__)


class DNSResolver(object):

    def __init__(self, nameservers=None, adhosts=None, timeout=5):
        self.nameservers = nameservers
        self.adhosts = adhosts
        self.timeout = timeout

    @cached_property
    def plugins(self):
        plugins = OrderedDict()
        if config.ENABLE_ADBLOCK:
            plugins["adblock"] = ADBlockPlugin(self.adhosts)
        return plugins

    def mount_plugin(self, name, plugin):
        """挂载插件

        需要为插件指定一个唯一的名字，插件需为一个可调用对象，接受一个查询消息对象参数
        如果插件返回一个 DNSMessage 对象，则用该返回值作为解析结果
        如果插件返回 True，则表示执行成功，返回 False 则表示执行失败
        """
        if name in self.plugins:
            raise PluginExistsError("plugin '{}' exists".format(name))
        self.plugins[name] = plugin

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

    def _proxy_query(self, qmsg, host, port=53, protocol="udp"):
        if protocol == "udp":
            amsg = dns.query.udp(qmsg, host, port=port, timeout=self.timeout)
        elif protocol == "tcp":
            amsg = dns.query.tcp(qmsg, host, port=port, timeout=self.timeout)
        else:
            raise DNSError(f"unsupported protocol '{protocol}'")
        return amsg

    def query(self, qmsg, protocol="udp"):

        if qmsg.opcode() == dns.opcode.QUERY and qmsg.qtype in {
            dns.rdatatype.A,  dns.rdatatype.AAAA
        }:
            ret = self.run_plugins(qmsg)
            if isinstance(ret, DNSMessage):
                return ret

        for host, port in self.nameservers:
            try:
                amsg = self._proxy_query(qmsg, host, port)
            except Exception as e:
                log.error("Proxy query error: %s", e)
            else:
                break
        else:
            raise DNSError("no servers could be reached")

        return amsg


class ADBlockPlugin(object):

    def __init__(self, adhosts=None):
        self._adhosts = adhosts or set()

    def get_adhosts_from_config(self):
        config_paths = []
        for config_dir in config.ADHOSTS_PATH:
            if not config_dir or os.path.exists(config_dir):
                continue
            config_paths.append(os.path.join(config_dir, "adhosts"))
            sub_config_dir = os.path.join(config_dir, "adhosts.conf.d")
            for path in glob.iglob(os.path.join(sub_config_dir, "*")):
                config_paths.append(path)
        config_paths.append(config.ADHOSTS_PATH)
        hosts = set()
        for config_path in config_paths:
            if not config_path or not os.path.exists(config_path):
                continue
            log.info(f"Load adhosts file '{config_path}'")
            with open(config_path) as fp:
                for line in fp:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    hosts.add(line)
        return hosts

    @cached_property
    def adhosts(self):
        return self._adhosts | self.get_adhosts_from_config()

    def __call__(self, qmsg):
        name = qmsg.qname_str
        if name not in self.adhosts:
            return True

        if qmsg.qtype == dns.rdatatype.A:
            rd = dns.rdtypes.IN.A.A(
                dns.rdataclass.IN,
                dns.rdatatype.A,
                "127.0.0.1"
            )
        elif qmsg.qtype == dns.rdatatype.AAAA:
            rd = dns.rdtypes.IN.AAAA.AAAA(
                dns.rdataclass.IN,
                dns.rdatatype.AAAA,
                "::1"
            )
        else:
            return True

        rrset = dns.rrset.RRset(qmsg.qname, qmsg.qclass, qmsg.qtype)
        rrset.add(rd)
        rrset.ttl = 86400

        amsg = dns.message.make_response(qmsg)
        amsg.answer.append(rrset)
        return amsg


class LocalHostsPlugin(object):
    pass
