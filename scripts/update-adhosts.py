#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

from argparse import ArgumentParser
import requests


hosts_urls = [
    "https://hosts.nfz.moe/127.0.0.1/full/hosts",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
]


def main():
    parser = ArgumentParser()
    parser.add_argument("-o", "--out-path", default="adhosts", help="输出文件路径")
    args = parser.parse_args()

    newhosts = set()
    for url in hosts_urls:
        resp = requests.get(url)
        try:
            resp.raise_for_status()
        except Exception:
            continue

        content = resp.content.decode("utf-8", errors='ignore')
        for line in content.split("\n"):
            if not line or line.startswith("#"):
                continue
            if "localhost" in line or "loopback" in line:
                continue
            items = line.split()
            host = items[0] if len(items) == 1 else items[1]
            newhosts.add(host)

    with open(args.out_path, "w+", encoding="utf-8") as fp:
        oldhosts = {line.strip() for line in fp}
        adhosts = newhosts | oldhosts
        adhosts = list(adhosts)
        adhosts.sort()
        fp.write("\n".join(adhosts))


if __name__ == "__main__":
    main()
