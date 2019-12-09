# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import logging
from collections import OrderedDict

import dns.query
import dns.message

from .error import DNSError, PluginExistsError


log = logging.getLogger(__name__)


class DNSResolver(object):

    def __init__(self, nameservers=None, timeout=5):
        self.nameservers = nameservers
        self.timeout = timeout
        self.plugins = OrderedDict()

    def mount_plugin(self, name, plugin):
        """挂载插件

        需要为插件指定一个唯一的名字，插件需为一个可调用对象，接受一个查询消息对象参数
        如果插件返回一个字符串，则用该返回值作为解析结果
        如果插件返回 True，则表示执行成功，返回 False 则表示执行失败
        """
        if name in self.plugins:
            raise PluginExistsError("plugin '{}' exists".format(name))
        self.plugins[name] = plugin

    def run_plugins(self, qmsg):
        """运行插件

        如果有插件返回字符串，则用用该返回值作为解析结果返回，
        如果有多个插件返回字符串，则以最后一个插件的返回值作为解析结果返回
        如果没有插件返回字符串，且有插件执行成功，则返回 True，没有插件成功则返回 False
        """
        is_successful = False
        resp_msg = None
        for name, plugin in self.plugins.items():
            ret = plugin(qmsg)
            if isinstance(ret, str):
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
            raise DNSError("unsupported protocol '{}'".format(protocol))
        return amsg

    def query(self, qmsg, protocol="udp"):
        ret = self.run_plugins(qmsg)
        if isinstance(ret, str):
            pass

        for host, port in self.nameservers:
            try:
                self._proxy_query(qmsg, host, port)
            except Exception:
                pass
