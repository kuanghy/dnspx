# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

__version__ = '0.1.4'


_VersionInfo = __import__("collections").namedtuple(
    "version_info", ["major", "minor", "micro"]
)
version_info = ([int(v) for v in __version__.split('.')[:3]] + [0] * 3)[:3]
version_info = _VersionInfo(*version_info)

version_str = "dnspx version {}, python version {}".format(
    __version__,
    ".".join(str(item) for item in __import__("sys").version_info)
)
