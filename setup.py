#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

from __future__ import print_function

import os
from setuptools import setup, find_packages
from os.path import join as path_join, dirname as path_dirname


CURRDIR = path_dirname(__file__)

EXCLUDE_FROM_PACKAGES = ["tests"]

DESCRIPTION = "DNS proxy query service tool"
LONG_DESCRIPTION = """
**dnspx** is a DNS proxy query service tool. It provides a lightweight
local DNS server, to accelerate the DNS, avoid pollution of DNS, and so on.
"""

setup_args = dict(
    name='dnspx',
    version='0.0.1',
    packages=find_packages(exclude=EXCLUDE_FROM_PACKAGES),
    author='Huoty',
    author_email='sudohuoty@163.com',
    maintainer="Huoty",
    maintainer_email="sudohuoty@163.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    url='https://github.com/kuanghy/dnspx',
    keywords=["dns", "dnsproxy", "dnspx", "ns"],
    zip_safe=False,
    license='Apache License v2',
    python_requires='>=3.6',
    platforms=["any"],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: Apache Software License',
    ],
)


def get_version():
    scope = {}
    version = '1.0'
    version_file = path_join(CURRDIR, "dnspx", "version.py")
    if os.path.exists(version_file):
        with open(version_file) as fp:
            exec(fp.read(), scope)
        version = scope.get('__version__', '1.0')
    return version


def main():
    setup_args["version"] = get_version()
    setup_args["package_data"] = {
        "": ["*.so", "*.dll", "*.pyd"]
    }
    setup_args["install_requires"] = [
        "dnspython",
        "PyYAML",
        "cacheout",
    ]
    setup_args["extras_require"] = {
        "socks": ["pysocks"],
    }
    setup_args["entry_points"] = {
        'console_scripts': [
            'dnspx=dnspx.cli:main',
        ],
    }

    setup(**setup_args)


if __name__ == "__main__":
    main()
