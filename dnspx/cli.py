# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
import logging
from argparse import ArgumentParser

from .version import version_str as version
from .log import basic_config as log_basic_config, setup_logging
from .core import DNSProxyServer


def parse_arguments(args):
    parser = ArgumentParser(description="DNS proxy tool",
                            epilog="")
    parser.add_argument("-v", "--version", action='version', version=version)


def main(args=None):
    if sys.version_info.major < 3:
        print("Only supports Python3")
        return
    log_basic_config(logging.DEBUG)
    server = DNSProxyServer(
        ("127.0.0.1", 53)
    )
    server.run()
