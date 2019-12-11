# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
import logging
from .core import DNSProxyServer


def main():
    if sys.version_info.major < 3:
        print("Only supports Python3")
        return
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    server = DNSProxyServer()
    server.run()
