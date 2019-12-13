# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

try:
    from dns.exception import Timeout as DNSTimeout
except ImportError:
    DNSTimeout = type("DNSTimeout", (Exception,), {})

DNSError = type("DNSError", (Exception,), {})

PluginExistsError = type("PluginExistsError", (Exception,), {})
