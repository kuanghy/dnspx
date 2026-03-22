# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
import socket
import logging
from importlib import import_module
from argparse import ArgumentParser

from .version import version_str as version
from .config import IS_WINDOWS, load_config
from .log import basic_config as log_basic_config, setup_logging
from .utils import parse_ip_port
from .core import DNSProxyServer
from .dig import do_query


def send_control_command(address, command):
    """向控制端口发送命令并打印响应"""
    host, port = parse_ip_port(address)
    port = port or 8051
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall((command + "\n").encode("utf-8"))
            # 持续读取直到连接关闭
            chunks = []
            while True:
                chunk = sock.recv(65535)
                if not chunk:
                    break
                chunks.append(chunk)
            response = b"".join(chunks).decode("utf-8").strip()
    except ConnectionRefusedError:
        print(f"Error: cannot connect to {host}:{port} "
              "(is dnspx server running?)", file=sys.stderr)
        sys.exit(1)
    except socket.timeout:
        print(f"Error: connection to {host}:{port} timed out",
              file=sys.stderr)
        sys.exit(1)
    print(response)


def parse_arguments(args):
    parser = ArgumentParser(description="DNS proxy tool",
                            epilog="")
    parser.add_argument("-v", "--version", action='version', version=version)

    add_arg = lambda _p, *args, **kwargs: _p.add_argument(*args, **kwargs)

    general_group = parser.add_argument_group(title="general arguments")
    add_arg(general_group, "--service", help="As a windows service")
    add_arg(general_group, "--config", help="Path to config file or directory")
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

    server_group = parser.add_argument_group(title="server arguments")
    add_arg(server_group, "-a", "--listen",
            help="Listen on address, e.g. 127.0.0.1:53")
    add_arg(server_group, "-n", "--nameserver",
            help="DNS servers to use with proxied requests")
    add_arg(server_group, "--enable-tcp", action="store_true",
            help="Enable TCP server, default UDP only")
    add_arg(server_group, "--enable-ipv6", action="store_true",
            help="Enable IPv6 protocol")
    add_arg(server_group, "--hosts-path",
            help="Hosts configuration file paths, "
                 "overwrite LOCAL_HOSTS_PATH configuration")

    ctl_group = parser.add_argument_group(title="control arguments")
    add_arg(ctl_group, "--ctl",
            help="Send control command to running server "
                 "(status, cache-stats, cache-clear, reload)")
    add_arg(ctl_group, "--ctl-address",
            help="Control listen / --ctl target (default from config)")

    query_group = parser.add_argument_group(title="query arguments")
    add_arg(query_group, "--query", metavar="DOMAIN",
            help="Query a domain name (dig-like, independent of server)")
    add_arg(query_group, "-t", "--type", default="A",
            help="Query type: A, AAAA, MX, CNAME, etc. (default: A)")
    add_arg(query_group, "--short", action="store_true",
            help="Show only record values in query output")

    args = parser.parse_args(args)

    if args.service and not IS_WINDOWS:
        parser.error("Windows service mode is not supported on this platform.")

    return args


def main(args=None):
    if sys.version_info < (3, 6):
        print("Error, only supports Python version 3.6 or later",
              file=sys.stderr)
        return

    if IS_WINDOWS and len(sys.argv) >= 2 and sys.argv[1] == '--service':
        config = load_config()
        setup_logging(
            reset=True,
            enable_rotate_log=config.ENABLE_ROTATE_LOG,
            enable_time_rotate_log=config.ENABLE_TIME_ROTATE_LOG,
            enable_smtp_log=config.ENABLE_MAIL_REPORT
        )
        loglevel = config.LOGLEVEL
        logging.getLogger().setLevel(getattr(logging, loglevel.upper()))
        import_module(".service", __package__).run_as_windows_service()
        logging.shutdown()
        return

    args = parse_arguments(args)

    # 控制命令模式：连接运行中的服务器
    if args.ctl:
        config = load_config(args.config)
        address = args.ctl_address or config.CONTROL_SERVER_LISTEN
        send_control_command(address, args.ctl)
        return

    # 查询模式：独立 DNS 查询
    if args.query:
        config = load_config(args.config)
        if args.nameserver:
            nameservers = args.nameserver.split(",")
        else:
            nameservers = config.NAMESERVERS or ["223.5.5.5"]
        do_query(args.query, args.type, nameservers, short=args.short)
        return

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
        control_server_address=args.ctl_address,
        config_path=args.config,
    )
    server.run()
    logging.shutdown()
