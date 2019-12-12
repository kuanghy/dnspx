# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

_os = __import__("os")
_sys = __import__("sys")
_log = __import__("logging").getLogger(__name__)

# 判断系统平台
IS_WINDOWS = _sys.platform in ['win32', 'cygwin']
IS_MACOSX = _sys.platform == 'darwin'
IS_LINUX = _sys.platform.startswith('linux')

IS_UNIX = (IS_LINUX or IS_LINUX)


# 用户主目录
USER_HOME = _os.getenv("HOME", "/home/server")

# 配置公共 DNS 服务器
# 每一个 DNS 配置可以为一个 tuple，list，每一项包含：IP地址，端口，类型，说明
# 除 IP地址 外，其他项为非必须项，不指定时取默认值，端口为 53，属性 inland，说明为 None
# DNS 配置也可以为一个仅包含 ip 的字符串
NAMESERVERS = [
    ("119.29.29.29", "53", "inland", "Public DNS+，腾讯云旗下的公共 DNS 服务"),
    ("223.5.5.5", "53", "inland", "AliDNS 阿里公共 DNS"),
    ("114.114.114.114", "53", "inland", "国内电信运营商自用的 DNS 服务"),
    ("180.76.76.76", "53", "inland", "百度 BaiduDNS"),
    ("1.2.4.8", "53", "inland", "CNNIC sDNS"),
    ("117.50.11.11", "53", "inland", "OneDNS 拦截版"),
    ("117.50.10.10", "53", "inland", "OneDNS 纯净版"),
    ("1.1.1.1", "53", "foreign", "CloudFlare DNS，号称全球最快的 DNS 服务"),
    ("8.8.8.8", "53", "foreign", "Google Public DNS"),
    ("1.0.0.1", "53", "foreign", "CloudFlare DNS 备用地址"),
    ("8.8.4.4", "53", "foreign", "Google Public DNS 备用地址"),
    "223.6.6.6",  # Public DNS+ 备用地址
    "114.114.115.115",  # 114DNS 备用地址
    "114.114.114.119",  # 114DNS 拦截钓鱼病毒木马网站
    "114.114.114.110",  # 114DNS 拦截色情网站
]

# 开启 DNS 缓存
ENABLE_DNS_CACHE = True
DNS_CACHE_SIZE = 1024
DNS_CACHE_TTL = 60 * 60 * 1

# 开启本地 hosts 文件支持
ENABLE_LOCAL_HOSTS = True
LOCAL_HOSTS_PATH = None  # 可以为目录或者文件

# 开启海外域名用海外 DNS 解析功能
ENABLE_FOREIGN_RESOLVER = True
FOREIGN_DOMAINS = [  # 标记海外域名，以用海外的 DNS 解析
    "google.com",
    "github.com",
    "github.io",
    # "sina.com",  # 部分匹配，匹配 sina.com、sina.com.cn、www.sina.com 等
    # "full:google.com",  # 完全匹配，仅匹配 google.com
    # "domain:google.com",  # 子域名匹配，匹配 xxx.google.com, yyy.google.com 等
    # "ext:/etc/dnspx/foreign-domains",  # 重外部文件中读取配置
]

# 服务监听地址
SERVER_LISTEN = "127.0.0.1:53"

# 服务器运行的进程优先级，值为 20 到 19，仅 Unix 环境有效
PROCESS_PRIORITY = 0

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

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
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
