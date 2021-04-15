# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

_os = __import__("os")
_sys = __import__("sys")
_log = __import__("logging").getLogger(__name__)

# 判断系统平台
IS_WIN32 = _sys.platform == 'win32'
IS_CYGWIN = _sys.platform == 'cygwin'
IS_WINDOWS = _sys.platform in ['win32', 'cygwin']
IS_MACOSX = _sys.platform == 'darwin'
IS_LINUX = _sys.platform.startswith('linux')

IS_UNIX = (IS_MACOSX or IS_LINUX)

# 用户主目录
USER_HOME = _os.getenv("HOME", "/home/server")

# 配置公共 DNS 服务器
# 每一个 DNS 配置可以为一个 tuple，list，每一项包含：
#     服务器地址，服务器类型，服务器说明
# 除 服务器地址 外，其他项为非必须项，不指定时取默认值，类型 inland，说明为 None
# 如果其类型主要用来标记是国内还是海外，包含两种类型：inland, foreign
# 服务器端口默认为 53，也可以在地址中指定端口，如 127.0.0.1:50053
NAMESERVERS = DEFAULT_NAMESERVERS = [
    ("119.29.29.29", "inland", "Public DNS+，腾讯云旗下的公共 DNS 服务"),
    ("223.5.5.5", "inland", "AliDNS 阿里公共 DNS"),
    ("114.114.114.114", "inland", "国内电信运营商自用的 DNS 服务"),
    ("180.76.76.76", "inland", "百度 BaiduDNS"),
    ("1.2.4.8", "inland", "CNNIC sDNS"),
    ("117.50.11.11", "inland", "OneDNS 拦截版"),
    ("117.50.10.10", "inland", "OneDNS 纯净版"),

    ("1.1.1.1", "foreign", "CloudFlare DNS，号称全球最快的 DNS 服务"),
    ("8.8.8.8", "foreign", "Google Public DNS"),
    ("208.67.222.222", "foreign", "OpenDNS"),
    ("9.9.9.9", "foreign", "IBM Quad9"),
    ("199.85.126.30", "foreign", "Norton ConnectSafe DNS C"),
    ("199.85.126.20", "foreign", "Norton ConnectSafe DNS B"),
    ("199.85.126.10", "foreign", "Norton ConnectSafe DNS A"),
    ("84.200.69.80", "foreign", "DNS.WATCH"),
    ("1.0.0.1", "foreign", "CloudFlare DNS 备用地址"),
    ("8.8.4.4", "foreign", "Google Public DNS 备用地址"),

    "223.6.6.6",  # Public DNS+ 备用地址
    "114.114.115.115",  # 114DNS 备用地址
    "114.114.114.119",  # 114DNS 拦截钓鱼病毒木马网站
    "114.114.114.110",  # 114DNS 拦截色情网站

    # DNS over HTTP (DOH)服务器
    # 不能只单独配置 DOH，需要配合至少一个 UDP 或 TCP 的上游服务器使用
    ("https://cloudflare-dns.com/dns-query", "foreign", "CloudFlare DoH"),
    ("https://dns.google/dns-query", "foreign", "Google DoH"),
]

# 往上游 DNS 服务器查询时的默认超时时间，单位为秒
QUERY_TIMEOUT = 2
# 往海外 DNS 服务器查询的超时时间，单位为秒
# 该值大于 0 时，所有向海外 DNS 服务器的查询都会使用此超时时间
FOREIGN_QUERY_TIMEOUT = 0

# 开启 DNS 缓存
ENABLE_DNS_CACHE = True
DNS_CACHE_SIZE = 256
DNS_CACHE_TTL = 60 * 60 * 3  # 默认为 3 小时

# 开启本地 hosts 文件支持
ENABLE_LOCAL_HOSTS = True
LOCAL_HOSTS_PATH = None  # 本地 hosts 文件路径，可以为目录或者单个文件

# 开启海外域名用海外 DNS 解析功能
ENABLE_FOREIGN_RESOLVER = True
FOREIGN_DOMAINS = [  # 标记海外域名，以用海外的 DNS 解析
    "google.com",
    "youtube.com",
    "github.com",
    "github.io",
    "stackoverflow.com",
    "yahoo.com",
    "amazon.com",
    "facebook.com",
    "twitter.com",
    "githubusercontent.com",
    "full:wikipedia.org",
    "full:www.wikipedia.org",
    "python.org",
    "bitbucket.org",
    "gnome-look.org",
    "googleapis.com",
    "gitbook.com",
    "wordpress.com",

    # "sina.com",  # 部分匹配，匹配 sina.com、sina.com.cn、www.sina.com 等
    # "full:google.com",  # 完全匹配，仅匹配 google.com
    # "domain:google.com",  # 子域名匹配，匹配 xxx.google.com, yyy.google.com 等
    # "ext:/etc/dnspx/foreign-domains",  # 从外部文件中读取配置
]

# 服务监听地址
SERVER_LISTEN = "127.0.0.1:53"

# 网络代理服务器
PROXY_SERVERS = None
ONLY_FOREIGN_PROXY = False  # 仅对海外 DNS 使用代理

# 服务器运行的进程优先级，值为 -20 到 19，仅 Unix 环境有效
PROCESS_PRIORITY = 0

# 服务器进程名称
PROCESS_TITLE = "dnspx: server"

# 最多允许同时有多少个线程处理请求（默认为 CPU 核数的 3 倍）
MAX_THREAD_NUM = _os.cpu_count() * 3

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


# Windows 平台下打包的可执行程序路径
APP_PATH = None
APP_LOG_PATH = None
APP_BUNDLE_PATH = None
if IS_WIN32 and getattr(_sys, 'frozen', False):
    APP_PATH = _os.path.dirname(_sys.executable)
    APP_LOG_PATH = _os.path.join(APP_PATH, "logs")
    APP_BUNDLE_PATH = getattr(_sys, '_MEIPASS', None)

    if not ROTATE_LOG_FILE:
        ROTATE_LOG_FILE = _os.path.join(APP_LOG_PATH, "dnspx.log")


# 配置文件目录
_CONFIG_DIRS = [
    '/etc/dnspx/',
    '/usr/local/etc/dnspx',
    _os.path.join(USER_HOME, '.local', 'etc', 'dnspx'),
    _os.path.join(USER_HOME, '.config', 'dnspx'),
    _os.path.join(_os.getcwd(), 'config')
]

# 标记配置是否已被加载过
_HAS_BEEN_LOADED = False


def _get_default_config_paths():
    common_config_suffixes = [".py", ".yml", ".yaml"]  # 公共的配置文件后缀
    local_config_suffixes = [                          # 本地定制化配置文件后缀
        ".local" + item for item in common_config_suffixes
    ]
    suffixes = [
        suffix
        for item in zip(common_config_suffixes, local_config_suffixes)
        for suffix in item
    ]
    return [
        _os.path.join(config_dir, f"dnspx{suffix}")
        for config_dir in _CONFIG_DIRS
        for suffix in suffixes
        if config_dir and _os.path.exists(config_dir)
    ]


def _parse_yaml_config_file(path):
    try:
        import yaml
    except ImportError:
        _log.error("Got a yaml config file, but no yaml package")
        return

    try:
        from yaml import CLoader as Loader
    except ImportError:
        from yaml import Loader

    with open(path, encoding="utf-8") as fp:
        _config = yaml.load(fp, Loader=Loader)
    globals().update({key.upper(): val for key, val in _config.items()})


def _parse_config_file(path):
    _, fileext = _os.path.splitext(path)
    if fileext in {".yml", ".yaml"}:
        _parse_yaml_config_file(path)
    else:
        with open(path, encoding="utf-8") as fp:
            code = compile(fp.read(), path, "exec")
        exec(code, globals(), globals())


def load_config(path=None, reset=False):
    global _HAS_BEEN_LOADED
    reset = bool(reset or path)
    if _HAS_BEEN_LOADED and not reset:
        return _sys.modules[__name__]

    if path and _os.path.isdir(path):
        _CONFIG_DIRS.append(path)
    env_path = _os.getenv("DNSPX_CONFIG_PATH")
    if env_path and _os.path.isdir(env_path):
        _CONFIG_DIRS.append(env_path)
    if APP_PATH:
        _CONFIG_DIRS.append(_os.path.join(APP_PATH, "config"))

    config_paths = _get_default_config_paths()
    if path and _os.path.isfile(path):
        config_paths.append(path)
    if env_path and _os.path.isfile(env_path):
        config_paths.append(env_path)

    for cfg_path in config_paths:
        if not cfg_path or not _os.path.exists(cfg_path):
            continue
        _log.debug("Load config: %s", cfg_path)
        _parse_config_file(cfg_path)

    _HAS_BEEN_LOADED = True
    return _sys.modules[__name__]
