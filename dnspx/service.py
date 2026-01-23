# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
import socket
import logging
import traceback

import win32service
import servicemanager
import win32serviceutil
import win32event
import win32api

from .config import load_config
from .utils import parse_ip_port
from .core import DNSProxyServer


log = logging.getLogger(__name__)


class DNSPXWinService(win32serviceutil.ServiceFramework):

    _svc_name_ = "DNSPX"
    _svc_display_name_ = "DNSPX Service"
    _svc_description_ = "DNS proxy service"

    def __init__(self, args):
        self._logger = log.getChild(__name__)

        config = load_config()
        ip, port = parse_ip_port(config.SERVER_LISTEN)
        if port is None:
            port = 53
        server_address = (ip, port)
        self._dns_proxy_server = DNSProxyServer(
            server_address,
            enable_tcp=False,
            enable_ipv6=False,
        )

        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)

        self.log('Service Initialized')

    def log(self, msg):
        msg = f"[{self._svc_name_}] {msg}"
        # servicemanager.LogInfoMsg(msg)
        self._logger.info(msg)

    def sleep(self, sec):
        win32api.Sleep(sec * 1000, True)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._dns_proxy_server.stop()
        win32event.SetEvent(self.hWaitStop)
        self.log('Service has stopped')

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.log('Service is starting')
        try:
            self._dns_proxy_server.run()
        except Exception:
            exception_traceback = traceback.format_exc()
            self.log(f"Failed to run dnspx server\n{exception_traceback}")


def run_as_windows_service():
    if len(sys.argv) <= 2:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(DNSPXWinService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        argv = [sys.argv[0]] + sys.argv[2:]
        win32serviceutil.HandleCommandLine(DNSPXWinService, argv=argv)
