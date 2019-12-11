# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
import time
import socket
import getpass
import logging
import smtplib
import datetime
import traceback
from email.mime.text import MIMEText
from email.utils import formatdate as email_utils_localtime
from logging.handlers import (
    RotatingFileHandler,
    TimedRotatingFileHandler,
    SMTPHandler
)


from . import config
from .utils import text_shorten


default_logger = logging.getLogger("dnspx")

info = default_logger.info
warn = default_logger.warning
warning = default_logger.warning
debug = default_logger.debug
error = default_logger.error
exception = default_logger.exception

default_format = "%(asctime)s - %(levelname)s - %(message)s"

_log = logging.getLogger(__name__)


class ColoredStreamHandler(logging.StreamHandler):
    """带色彩的流日志处理器"""

    C_BLACK = '\033[0;30m'
    C_RED = '\033[0;31m'
    C_GREEN = '\033[0;32m'
    C_BROWN = '\033[0;33m'
    C_BLUE = '\033[0;34m'
    C_PURPLE = '\033[0;35m'
    C_CYAN = '\033[0;36m'
    C_GREY = '\033[0;37m'

    C_DARK_GREY = '\033[1;30m'
    C_LIGHT_RED = '\033[1;31m'
    C_LIGHT_GREEN = '\033[1;32m'
    C_YELLOW = '\033[1;33m'
    C_LIGHT_BLUE = '\033[1;34m'
    C_LIGHT_PURPLE = '\033[1;35m'
    C_LIGHT_CYAN = '\033[1;36m'
    C_WHITE = '\033[1;37m'

    C_RESET = "\033[0m"

    def __init__(self, *args, **kwargs):
        self._colors = {logging.DEBUG: self.C_DARK_GREY,
                        logging.INFO: self.C_RESET,
                        logging.WARNING: self.C_BROWN,
                        logging.ERROR: self.C_RED,
                        logging.CRITICAL: self.C_LIGHT_RED}
        super(ColoredStreamHandler, self).__init__(*args, **kwargs)

    @property
    def is_tty(self):
        isatty = getattr(self.stream, 'isatty', None)
        return isatty and isatty()

    def emit(self, record):
        try:
            message = self.format(record)
            stream = self.stream
            if not self.is_tty:
                stream.write(message)
            else:
                message = self._colors[record.levelno] + message + self.C_RESET
                stream.write(message)
            stream.write(getattr(self, 'terminator', '\n'))
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handleError(record)

    def setLevelColor(self, logging_level, escaped_ansi_code):
        self._colors[logging_level] = escaped_ansi_code


class TitledSMTPHandler(SMTPHandler):
    """可定制邮件主题 SMTP 日志处理器"""

    def emit(self, record):
        # add extra record
        record.host = socket.gethostname()
        record.user = getpass.getuser()
        if not hasattr(record, "task"):
            record.task = None
        super(TitledSMTPHandler, self).emit(record)

    def getSubject(self, record):
        if record.task:
            subject_fmt = ("%(levelname)s on %(host)s [%(name)s] "
                           "[TASK=%(task)s]: %(summary)s")
        else:
            subject_fmt = "%(levelname)s on %(host)s [%(name)s]: %(summary)s"
        message = record.getMessage()
        record = vars(record)
        record["summary"] = text_shorten(message.strip().split('\n')[-1])
        return subject_fmt % record


class BufferedTitledSMTPHandler(logging.handlers.BufferingHandler):
    """支持缓冲区及主题定制的 SMTP 日志处理器"""

    def __init__(self, mailhost, fromaddr, toaddrs, subject,
                 credentials=None, secure=None, timeout=5.0,
                 capacity=100, max_wait_time=300):
        logging.handlers.BufferingHandler.__init__(self, capacity)
        if isinstance(mailhost, (list, tuple)):
            self.mailhost, self.mailport = mailhost
        else:
            self.mailhost, self.mailport = mailhost, None
        if isinstance(credentials, (list, tuple)):
            self.username, self.password = credentials
        else:
            self.username = None
        self.fromaddr = fromaddr
        if isinstance(toaddrs, str):
            toaddrs = [toaddrs]
        self.toaddrs = toaddrs
        self.subject = subject
        self.secure = secure
        self.timeout = timeout
        self.last_flush_time = -1
        self.max_wait_time = max_wait_time

    def shouldFlush(self, record):
        return (len(self.buffer) >= self.capacity) or (
            self.last_flush_time > 0 and
            time.time() - self.last_flush_time > self.max_wait_time
        )

    def emit(self, record):
        record.host = socket.gethostname()
        record.user = getpass.getuser()
        if not hasattr(record, "task"):
            record.task = None
        self.buffer.append(record)
        if self.last_flush_time < 0:
            self.last_flush_time = time.time()
        if self.shouldFlush(record):
            self.flush()

    def getSubject(self):
        tasks = ",".join({
            str(record.task) for record in self.buffer if record.task
        })
        if tasks:
            subject_fmt = ("%(levelname)s on %(host)s [%(name)s] "
                           "[TASK={}]: %(summary)s").format(tasks)
        else:
            subject_fmt = "%(levelname)s on %(host)s [%(name)s]: %(summary)s"
        record = self.buffer[0]
        message = record.getMessage()
        record = vars(record)
        record["summary"] = "{} ({})".format(
            text_shorten(message.strip().split('\n')[0]),
            len(self.buffer)
        )
        return subject_fmt % record

    @staticmethod
    def _check_newline(text):
        return text if text.endswith("\n") else text + '\n'

    def getBody(self):
        if len(self.buffer) == 1:
            body = self.format(self.buffer[0])
        else:
            body = "\r\n".join(
                self._check_newline("[{0} Record {1} {0}]\n{2}".format(
                    '#' * 10, idx, self.format(record)
                )) for idx, record in enumerate(self.buffer, 1)
            )
        return body

    def flush(self):
        if not self.buffer:
            return

        self.acquire()
        try:
            port = self.mailport
            if not port:
                port = smtplib.SMTP_PORT
            smtp = smtplib.SMTP(self.mailhost, port, timeout=self.timeout)
            msg = MIMEText(self.getBody())
            msg['From'] = self.fromaddr
            msg['To'] = ','.join(self.toaddrs)
            msg['Subject'] = self.getSubject()
            msg['Date'] = email_utils_localtime()
            if self.username:
                if self.secure is not None:
                    smtp.ehlo()
                    smtp.starttls(*self.secure)
                    smtp.ehlo()
                smtp.login(self.username, self.password)
            smtp.sendmail(self.fromaddr, self.toaddrs, msg.as_string())
            smtp.quit()

            self.buffer = []
            self.last_flush_time = time.time()
        except Exception as e:
            try:
                sys.stderr.write(
                    "Flush bufferd log record error: {}\n{}".format(
                        e, traceback.format_exc()
                    )
                )
            except IOError:
                pass
        finally:
            self.release()


class SystemLogFormatter(logging.Formatter):
    """支持微秒的日志格式器"""

    converter = datetime.datetime.fromtimestamp

    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = ct.strftime(datefmt)
        else:
            t = ct.strftime("%Y-%m-%d %H:%M:%S")
            s = "%s,%03d" % (t, record.msecs)
        return s


def basic_config(level=None, format=None):
    level = level or logging.INFO
    format = format or default_format
    logger = logging.getLogger()
    logger.handlers = []
    logger.setLevel(logging.DEBUG)
    stream_handler = ColoredStreamHandler(sys.stdout)
    stream_handler.setLevel(level)
    formatter = SystemLogFormatter(format, datefmt='%Y-%m-%d %H:%M:%S,%f')
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)


def setup_logging(reset=False, enable_rotate_log=False,
                  enable_time_rotate_log=False, enable_smtp_log=False):
    logger = logging.getLogger()

    if len(logger.handlers) > 0 and not reset:
        _log.debug("logging has been set up")
        return

    logger.handlers = []  # 重置处理器
    logger.setLevel(logging.DEBUG)

    # 尝试加载一遍配置，避免配置没有被预先加载
    config.load_config()

    log_format = config.LOG_FORMAT or default_format
    rotate_log_file = config.ROTATE_LOG_FILE
    rotate_log_maxsize = config.ROTATE_LOG_MAXSIZE
    rotate_log_backups = config.ROTATE_LOG_BACKUPS
    error_log_file = config.ERROR_LOG_FILE

    time_rotate_log_file = config.TIME_ROTATE_LOG_FILE
    time_rotate_log_file_suffix = config.TIME_ROTATE_LOG_FILE_SUFFIX

    formatter = SystemLogFormatter(log_format, datefmt='%Y-%m-%d %H:%M:%S,%f')

    # 添加标准流日志处理器
    if not config.DISABLE_STREAM_LOG:
        stream_handler = ColoredStreamHandler(sys.stdout)
        stream_handler.setLevel(logging.DEBUG)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    def _add_rotating_file_handler(logfile, level):
        logsize = int(rotate_log_maxsize or (20 * 1024 * 1024))
        backups = int(rotate_log_backups or 10)
        file_handler = RotatingFileHandler(logfile, maxBytes=logsize,
                                           backupCount=backups)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        _log.debug(
            "Added rotating file log handler, "
            "logfile: %s, logsize: %s, backups: %s",
            file_handler.baseFilename,
            file_handler.maxBytes,
            file_handler.backupCount
        )

    # 添加可自动轮转的文件日志处理器
    if enable_rotate_log and rotate_log_file:
        _add_rotating_file_handler(rotate_log_file, logging.DEBUG)

    # 添加错误文件日志处理器，以记录错误日志到单独的文件
    if error_log_file:
        _add_rotating_file_handler(error_log_file, logging.ERROR)

    # 添加以时间自动轮转的文件日志处理器
    if enable_time_rotate_log and time_rotate_log_file:
        file_handler = TimedRotatingFileHandler(
            time_rotate_log_file,
            when='D',
            backupCount=(rotate_log_backups or 30),
        )
        file_handler.suffix = time_rotate_log_file_suffix
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        _log.debug(
            "Added timed rotating file log handler, "
            "logfile: %s, suffix: %s, backups: %s",
            file_handler.baseFilename,
            file_handler.suffix,
            file_handler.backupCount
        )

    # 添加邮件日志处理器，将错误日志通过邮件发送出去
    if enable_smtp_log and config.EMAIL_TOADDRS:
        params = dict(
            mailhost=config.EMAIL_HOST,
            fromaddr="JQFactorBaseErrorMonitor<{}>".format(config.EMAIL_ADDR),
            toaddrs=config.EMAIL_TOADDRS,
            subject=None,
            credentials=(config.EMAIL_ADDR, config.EMAIL_PASSWD)
        )
        if config.ENABLE_BUFFERED_SMTP_LOG:
            params["capacity"] = config.BUFFERED_SMTP_LOG_CAPACITY
            params["max_wait_time"] = config.BUFFERED_SMTP_LOG_MAX_WAIT_TIME
            smtp_handler = BufferedTitledSMTPHandler(**params)
        else:
            smtp_handler = TitledSMTPHandler(**params)
        smtp_handler.setLevel(logging.ERROR)
        smtp_handler.setFormatter(logging.Formatter(config.SMTP_LOG_FORMAT))
        logger.addHandler(smtp_handler)

    return logger
