# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>


class Error(Exception):
    """Base error"""

    msg = None

    def __init__(self, *args, **kwargs):
        if self.msg is None:
            self.msg = self.__doc__
        if args or kwargs:
            super().__init__(*args, **kwargs)
        else:
            super().__init__(self.msg)


class DNSError(Error):
    """The DNS error"""


try:
    from dns.exception import Timeout as DNSTimeout
except ImportError:

    class DNSTimeout(DNSError):
        """The DNS operation timed out"""


class DNSUnreachableError(DNSError):
    """no servers could be reached"""


class PluginExistsError(Error):
    """The plugin already exists"""
