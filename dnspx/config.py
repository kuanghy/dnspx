# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

_os = __import__("os")
_sys = __import__("sys")
_log = __import__("logging").getLogger(__name__)

USER_HOME = _os.getenv("HOME", "/home/server")

# 开启本地 hosts 文件支持
ENABLE_LOCAL_HOSTS = True
LOCAL_HOSTS_PATH = None

# 开启邮件报告功能，以通过邮件报告运行错误或者运行结果
ENABLE_MAIL_REPORT = False

# 日志相关配置
LOGLEVEL = "INFO"
DISABLE_STREAM_LOG = bool(_os.getenv("DISABLE_STREAM_LOG"))  # 关闭标准流日志
ENABLE_ROTATE_LOG = False
ENABLE_TIME_ROTATE_LOG = False

ERROR_LOG_FILE = _os.getenv("ERROR_LOG_FILE")
ROTATE_LOG_FILE = _os.getenv("ROTATE_LOG_FILE")
ROTATE_LOG_MAXSIZE = _os.getenv("ROTATE_LOG_MAXSIZE")
ROTATE_LOG_BACKUPS = _os.getenv("ROTATE_LOG_BACKUPS")

TIME_ROTATE_LOG_FILE = _os.getenv("TIME_ROTATE_LOG_FILE")
TIME_ROTATE_LOG_FILE_SUFFIX = "%Y%m%d"

LOG_FORMAT = "[%(asctime)s] [%(name)s] [%(levelname)s] [%(process)d] %(message)s"
SMTP_LOG_FORMAT = """\
Logger Name:        %(name)s
Message type:       %(levelname)s
Location:           %(pathname)s:%(lineno)d
Module:             %(module)s
Function:           %(funcName)s
Process:            %(process)d
Task:               %(task)s
Host:               %(host)s
User:               %(user)s
Time:               %(asctime)s

Message:

%(message)s
"""

ENABLE_BUFFERED_SMTP_LOG = False       # 打开支持缓冲区的错误日志邮件
BUFFERED_SMTP_LOG_CAPACITY = 100       # 错误日志邮件的缓冲区大小
BUFFERED_SMTP_LOG_MAX_WAIT_TIME = 300  # 错误日志邮件刷新缓存区的间隔时间，单位为秒

# 邮件发送配置，配置时会发送错误日志报告邮件，否则不发送
EMAIL_HOST = ""       # 发件邮箱的 SMTP 服务器
EMAIL_ADDR = ""       # 发件邮箱地址
EMAIL_PASSWD = ""     # 发件邮箱密码
EMAIL_TOADDRS = []    # 收件人列表


# 配置文件目录
_CONFIG_DIRS = [
    '/etc/dnspx/',
    _os.path.join(USER_HOME, '.config', 'dnspx'),
    _os.getenv("PWD"),
]

# 标记配置是否已被加载过
_HAS_BEEN_LOADED = False


def _get_default_config_paths():
    suffixes = [".py", ".yml", ".yaml"]
    return [
        _os.path.join(config_dir, f"dnspx{suffix}")
        for config_dir in _CONFIG_DIRS
        for suffix in suffixes
        if config_dir
    ]


def _parse_yaml_config_file(path):
    try:
        import yaml
    except ImportError:
        _log.error("Got a yaml config file, but no yaml package")
        return

    with open(path) as fp:
        _config = yaml.load(fp)
    globals().update({key.upper(): val for key, val in _config.items()})


def _parse_config_file(path):
    with open(path) as fp:
        code = compile(fp.read(), path, "exec")
    exec(code, globals(), globals())


def load_config(path=None, reset=False):
    global _HAS_BEEN_LOADED
    reset = bool(reset or path)
    if _HAS_BEEN_LOADED and not reset:
        return _sys.modules[__name__]

    config_paths = _get_default_config_paths() + [
        _os.getenv("DNSPX_CONFIG_PATH"),
        path,
    ]

    for path in config_paths:
        if not path or not _os.path.exists(path):
            continue
        _log.debug("Load config: %s", path)
        _, fileext = _os.path.splitext(path)
        if fileext in {".yml", ".yaml"}:
            _parse_yaml_config_file(path)
        else:
            _parse_config_file(path)

    _HAS_BEEN_LOADED = True
    return _sys.modules[__name__]
