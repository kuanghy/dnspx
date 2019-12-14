#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import os
import sys
import shutil
from argparse import ArgumentParser


def main():
    parser = ArgumentParser()
    parser.add_argument("--user", action="store_true")
    parser.add_argument("--sys", action="store_true")
    parser.add_argument("-t", "--target")
    args = parser.parse_args()

    if args.sys:
        if sys.platform.startswith('win'):
            print("Unsupported system platform '{sys.platform}'")
            return
        config_dir = "/etc/dnspx/"
        if os.path.exists("/usr/local/etc"):
            config_dir = "/usr/local/etc/dnspx"
    elif args.user:
        home_dir = os.getenv("HOME", "/root")
        config_dir = os.path.join(home_dir, '.config', 'dnspx')
    else:
        if not args.target:
            print(f"Don't know installation directory")
            return
        config_dir = args.target

    print(f"Installing config files to '{config_dir}'")
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

    def copy_file(src, dst):
        shutil.copy2(src, dst)
        print(f"Copy '{src}' to '{dst}'")

    pro_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    config_file = os.path.join(pro_dir, "config.example.yml")
    adhosts_file = os.path.join(pro_dir, "data", "adhosts")
    if os.path.exists(config_file):
        copy_file(config_file, os.path.join(config_dir, "dnspx.yml"))
    if os.path.exists(adhosts_file):
        hosts_config_dir = os.path.join(config_dir, "hosts.conf.d")
        if not os.path.exists(hosts_config_dir):
            os.makedirs(hosts_config_dir)
        copy_file(adhosts_file, hosts_config_dir)

    print("Install done")


if __name__ == "__main__":
    main()
