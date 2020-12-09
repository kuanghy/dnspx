# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
import logging
from argparse import ArgumentParser

from .version import version_str as version
from .config import load_config
from .log import basic_config as log_basic_config, setup_logging
from .utils import parse_ip_port
from .core import DNSProxyServer


def parse_arguments(args):
    parser = ArgumentParser(description="DNS proxy tool",
                            epilog="")
    parser.add_argument("-v", "--version", action='version', version=version)

    add_arg = lambda _p, *args, **kwargs: _p.add_argument(*args, **kwargs)

    server_group = parser.add_argument_group(title="server arguments")
    add_arg(server_group, "-a", "--listen", help="Listen on address")
    add_arg(server_group, "-n", "--nameserver",
            help="DNS servers to use with proxied requests")
    add_arg(server_group, "--enable-tcp", action="store_true",
            help="Enable TCP server, default UDP only")
    add_arg(server_group, "--enable-ipv6", action="store_true",
            help="Enable IPv6 protocel")
    add_arg(server_group, "--hosts-path",
            help="Hosts configuration file paths, "
                 "overwrite LOCAL_HOSTS_PATH configuration")

    general_group = parser.add_argument_group(title="general arguments")
    add_arg(general_group, "--config", help="Path to config file")
    add_arg(general_group, "--loglevel",
            choices=["debug", "info", "warning", "error", "fatal",
                     "critical"],
            help="Log level (default: info)")
    add_arg(general_group, "--enable-rotate-log", action="store_true",
            help="Enable rotating file log")
    add_arg(general_group, "--enable-time-rotate-log", action="store_true",
            help="Enable rotating file log")
    add_arg(general_group, "--enable-mail-report", action="store_true",
            help="Report errors by email")

    return parser.parse_args(args)


def main(args=None):
    if sys.version_info < (3, 6):
        print("Error, only supports Python version 3.6 or later", file=sys.stderr)
        return

    args = parse_arguments(args)

    log_basic_config(level=getattr(logging, (args.loglevel or "INFO").upper()))
    config = load_config(args.config)
    setup_logging(
        reset=True,
        enable_rotate_log=args.enable_rotate_log or config.ENABLE_ROTATE_LOG,
        enable_time_rotate_log=(
            args.enable_time_rotate_log or config.ENABLE_TIME_ROTATE_LOG
        ),
        enable_smtp_log=args.enable_mail_report or config.ENABLE_MAIL_REPORT
    )
    loglevel = args.loglevel or config.LOGLEVEL
    logging.getLogger().setLevel(getattr(logging, loglevel.upper()))

    ip, port = parse_ip_port(args.listen or config.SERVER_LISTEN)
    if port is None:
        port = 53
    server_address = (ip, port)
    nameservers = args.nameserver.split(",") if args.nameserver else None
    server = DNSProxyServer(
        server_address,
        nameservers=nameservers,
        hosts_path=args.hosts_path,
        enable_tcp=args.enable_tcp,
        enable_ipv6=args.enable_ipv6,
    )
    server.run()
    logging.shutdown()
