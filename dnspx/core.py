#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import socketserver


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):

    pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    pass


class DNSProxyServer(object):

    def run(object):
        pass
