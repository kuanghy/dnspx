# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
import time
import datetime

import dns.message
import dns.flags
import dns.rdatatype

from .resolve import NameServer, QueryContext, proxy_dns_query


def do_query(domain, qtype_s, nameservers, short=False):
    """独立 DNS 查询，不依赖运行中的 dnspx 服务"""
    try:
        qtype = dns.rdatatype.from_text(qtype_s)
    except dns.rdatatype.UnknownRdatatype:
        print(f"Error: unknown query type '{qtype_s}'", file=sys.stderr)
        sys.exit(1)

    qmsg = dns.message.make_query(domain, rdtype=qtype, flags=dns.flags.RD)
    qmsg = QueryContext(qmsg)

    ns_list = [NameServer.parse(ns) for ns in nameservers]
    used_ns = ns_list[0]

    start_time = time.time()
    try:
        amsg = proxy_dns_query(qmsg, ns_list, timeout=5)
    except Exception as ex:
        print(f"Error: query failed: {ex}", file=sys.stderr)
        sys.exit(1)
    elapsed = (time.time() - start_time) * 1000

    if short:
        if hasattr(amsg, 'answer'):
            for rrset in amsg.answer:
                for rd in rrset:
                    print(rd.to_text())
        return

    proto = "DoH" if used_ns.is_doh else ("DoT" if used_ns.is_dot else "UDP")
    print(f";; QUESTION: {domain} {qtype_s.upper()}")
    print(f";; SERVER: {used_ns.host}:{used_ns.port} ({proto})")
    print()

    if hasattr(amsg, 'answer') and amsg.answer:
        print(";; ANSWER SECTION:")
        for rrset in amsg.answer:
            for rd in rrset:
                print(f"{rrset.name}    {rrset.ttl}    "
                      f"{dns.rdatatype.to_text(rrset.rdtype)}    "
                      f"{rd.to_text()}")
    else:
        print(";; No answer")

    print()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f";; Query time: {elapsed:.0f}ms")
    print(f";; WHEN: {now}")
