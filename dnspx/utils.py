# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
import functools
import threading
from collections import Counter
from urllib.parse import urlparse
from importlib import import_module

try:
    import asyncio
except (ImportError, SyntaxError):
    asyncio = None


class cached_property(object):

    def __init__(self, func):
        self.__doc__ = getattr(func, "__doc__")
        self.func = func

    def __get__(self, obj, cls):
        if obj is None:
            return self

        if asyncio and asyncio.iscoroutinefunction(self.func):
            return self._wrap_in_coroutine(obj)

        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value


class classproperty(object):

    def __init__(self, func):
        self.func = classmethod(func)

    def __get__(self, instance, owner):
        return self.func.__get__(instance, owner)()


class thread_sync(object):

    mutex = threading.RLock()

    _tag_mutex_mapping = {}
    _tag_counter = Counter()

    def __init__(self, tag=None, timeout=10):
        if tag:
            if tag not in self._tag_mutex_mapping:
                mutex = threading.Lock()
                self._tag_mutex_mapping[tag] = mutex
            self.mutex = self._tag_mutex_mapping[tag]
            self._tag_counter[tag] += 1
        self.tag = tag
        self.timeout = timeout
        self.is_locked = False

    def __enter__(self):
        if not self.mutex.acquire(timeout=self.timeout):
            raise TimeoutError("acquire lock timeout")
        self.is_locked = True
        return self.mutex

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.tag:
            self._tag_counter[self.tag] -= 1
        if not self.is_locked:
            return

        try:
            self.mutex.release()
        except RuntimeError:
            pass

        if not self.tag or self._tag_counter[self.tag] > 0:
            return

        del self._tag_mutex_mapping[self.tag]
        del self._tag_counter[self.tag]

    def __call__(self, func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self:
                ret = func(*args, **kwargs)
            return ret
        return wrapper


class suppress(object):

    def __init__(self, *exceptions, **kwargs):
        self.exceptions = exceptions
        self.logger = kwargs.get("logger") or kwargs.get("log")
        self.loglevel = kwargs.get("loglevel", "exception")

        self._log = (getattr(self.logger, self.loglevel, None)
                     if self.logger else None)

    def __enter__(self):
        return

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not exc_type or not issubclass(exc_type, self.exceptions):
            return
        if exc_val and self._log:
            self._log(exc_val)
        return True


def text_shorten(text, width=60, placeholder="..."):
    return text[:width] + (text[width:] and placeholder)


def parse_ip_port(netloc):
    netloc = netloc if "//" in netloc else f'//{netloc}'
    parsed = urlparse(netloc)
    return parsed.hostname, parsed.port


def is_tty():
    isatty = getattr(sys.stdout, 'isatty', None)
    return bool(isatty and isatty())


def check_internet_socket(host="8.8.8.8", port=53, socket_type=None, timeout=3):
    socket = import_module("socket")
    if not socket_type:
        socket_type = socket.SOCK_STREAM
    try:
        sock = socket.socket(socket.AF_INET, socket_type)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except socket.error:
        return False
    else:
        sock.close()
        return True


def is_main_thread():
    return threading.current_thread() == threading.main_thread()


class DomainMatcher:
    """基于 Trie 树的高效域名匹配器

    将域名按 . 分割并反转后构建 Trie 树，实现 O(m) 复杂度的域名匹配，
    其中 m 为域名的层级数（通常 2-5 层），与 pattern 数量无关。

    支持三种匹配模式：
    - "google.com"         : 匹配 google.com 及其所有子域名
    - "full:google.com"    : 仅完全匹配 google.com
    - "domain:google.com"  : 仅匹配子域名，不匹配 google.com 本身
    """

    _END = object()  # 标记终点的特殊对象

    def __init__(self, patterns=None):
        self._trie = {}
        if patterns:
            self.add_many(patterns)

    def add(self, pattern):
        """添加一个域名 pattern"""
        if not pattern:
            return

        full_match = False
        subdomain_only = False

        if pattern.startswith("full:"):
            pattern = pattern[5:]
            full_match = True
        elif pattern.startswith("domain:"):
            pattern = pattern[7:]
            subdomain_only = True

        # 按 . 分割并反转
        parts = pattern.lower().split('.')
        parts.reverse()

        node = self._trie
        for part in parts:
            if part not in node:
                node[part] = {}
            node = node[part]

        # 存储匹配模式信息
        node[self._END] = {
            'full_match': full_match,
            'subdomain_only': subdomain_only,
        }

    def add_many(self, patterns):
        """批量添加 patterns"""
        for pattern in patterns:
            if pattern and not pattern.startswith("ext:"):
                self.add(pattern)

    def match(self, name):
        """检查域名是否匹配任意 pattern

        时间复杂度: O(m)，m 为域名的层级数（通常 2-5 层）
        """
        if not name:
            return False

        parts = name.lower().split('.')
        parts.reverse()
        total_depth = len(parts)

        node = self._trie
        for i, part in enumerate(parts):
            if part not in node:
                break
            node = node[part]
            depth = i + 1

            # 检查当前节点是否是一个有效终点
            if self._END in node:
                match_info = node[self._END]
                is_exact = (depth == total_depth)

                if match_info['full_match']:
                    # full: 模式要求完全匹配
                    if is_exact:
                        return True
                    # 不是完全匹配，继续检查更深的节点
                elif match_info['subdomain_only']:
                    # domain: 模式要求必须是子域名
                    if not is_exact:
                        return True
                    # 是完全匹配，继续检查更深的节点
                else:
                    # 普通模式：完全匹配或子域名都可以
                    return True

        return False

    def __contains__(self, name):
        return self.match(name)

    def __len__(self):
        """返回 pattern 数量（遍历统计）"""
        def count_ends(node):
            total = 1 if self._END in node else 0
            for key, child in node.items():
                if key is not self._END:
                    total += count_ends(child)
            return total
        return count_ends(self._trie)
