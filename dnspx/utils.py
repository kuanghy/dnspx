# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import functools
import threading
from collections import Counter

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
