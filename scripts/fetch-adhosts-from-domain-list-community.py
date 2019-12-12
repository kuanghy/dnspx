#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

"""
从 domain-list-community 仓库中提取广告域名列表
仓库地址：https://github.com/v2ray/domain-list-community.git
"""

import os
import glob
from argparse import ArgumentParser


def main():
    parser = ArgumentParser()
    parser.add_argument("-s", "--repo-path", help="仓库 domain-list-community 路径")
    parser.add_argument("-o", "--out-path", default="adhosts", help="输出文件路径")

    args = parser.parse_args()

    newhosts = set()
    data_path = os.path.join(args.repo_path, "data")
    for path in glob.iglob(os.path.join(data_path, "*")):
        with open(path) as fp:
            for line in fp:
                line = line.strip()
                if not line or line.startswith("#") or "@ads" not in line:
                    continue
                host = line.split()[0]
                newhosts.add(host)

    if not newhosts:
        return

    with open(args.out_path, "w+", encoding="utf-8") as fp:
        oldhosts = {line.strip() for line in fp}
        adhosts = newhosts | oldhosts
        adhosts = list(adhosts)
        adhosts.sort()
        fp.write("\n".join(adhosts))


if __name__ == "__main__":
    main()
