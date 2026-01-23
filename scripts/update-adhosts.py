#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

"""
广告域名列表更新工具

支持以下格式的规则：
- hosts 格式: "0.0.0.0 ads.example.com" 或 "127.0.0.1 ads.example.com"
- 纯域名格式: "ads.example.com"
- AdGuard 格式: "||ads.example.com^"

使用示例:
    python update-adhosts.py -o ../data/adhosts
    python update-adhosts.py -o ../data/adhosts --proxy socks5://127.0.0.1:10618
"""

import os
import re
import sys
from argparse import ArgumentParser

import requests


# 广告域名列表源
# 格式: (URL, 是否需要代理, 描述)
AD_SOURCES = [
    # 国内源（无需代理）
    (
        "https://anti-ad.net/domains.txt",
        False,
        "Anti-AD 国内广告过滤列表"
    ),
    (
        "https://hosts.nfz.moe/127.0.0.1/full/hosts",
        False,
        "nfz.moe 广告过滤列表"
    ),

    # 国外源（可能需要代理）
    (
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        True,
        "AdGuard DNS filter"
    ),
    (
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        True,
        "StevenBlack hosts (综合多个来源)"
    ),
    (
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0",
        True,
        "Peter Lowe's Ad servers list"
    ),
    (
        "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
        True,
        "Disconnect.me 广告列表"
    ),
    (
        "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
        True,
        "Disconnect.me 追踪列表"
    ),
    (
        "https://o0.pages.dev/Lite/domains.txt",
        True,
        "1Hosts Lite"
    ),
]

# 域名验证正则
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# AdGuard 规则正则: ||domain.com^ 或 ||domain.com
ADGUARD_PATTERN = re.compile(r'^\|\|([a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,})\^?$')


def is_valid_domain(domain):
    """验证域名是否有效"""
    if not domain or len(domain) > 253:
        return False
    # 排除 IP 地址
    if domain.replace('.', '').isdigit():
        return False
    # 排除 localhost 相关
    if 'localhost' in domain or 'loopback' in domain:
        return False
    # 排除特殊域名
    if domain in ('0.0.0.0', '127.0.0.1', '::1', 'broadcasthost', 'local'):
        return False
    return bool(DOMAIN_PATTERN.match(domain))


def parse_line(line):
    """
    解析单行规则，提取域名

    支持格式:
    - hosts 格式: "0.0.0.0 ads.example.com" 或 "127.0.0.1 ads.example.com"
    - 纯域名格式: "ads.example.com"
    - AdGuard 格式: "||ads.example.com^"
    """
    line = line.strip()

    # 跳过空行和注释
    if not line or line.startswith('#') or line.startswith('!'):
        return None

    # 尝试 AdGuard 格式
    adguard_match = ADGUARD_PATTERN.match(line)
    if adguard_match:
        return adguard_match.group(1).lower()

    # 跳过其他 AdGuard 特殊规则（白名单、正则等）
    if line.startswith('@@') or line.startswith('/') or line.startswith('|'):
        return None

    # hosts 格式或纯域名格式
    parts = line.split()
    if len(parts) >= 2:
        # hosts 格式: IP 域名 [域名2 ...]
        # 取第二个字段作为域名
        domain = parts[1].lower()
    elif len(parts) == 1:
        # 纯域名格式
        domain = parts[0].lower()
    else:
        return None

    # 移除可能的尾部注释标记
    domain = domain.split('#')[0].strip()

    return domain if is_valid_domain(domain) else None


def fetch_domains(url, proxy=None, timeout=30):
    """从 URL 获取域名列表"""
    domains = set()

    proxies = None
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy,
        }

    try:
        resp = requests.get(url, proxies=proxies, timeout=timeout)
        resp.raise_for_status()

        content = resp.content.decode('utf-8', errors='ignore')
        for line in content.split('\n'):
            domain = parse_line(line)
            if domain:
                domains.add(domain)

    except requests.exceptions.RequestException as e:
        print(f"  [错误] 请求失败: {e}", file=sys.stderr)
    except Exception as e:
        print(f"  [错误] 解析失败: {e}", file=sys.stderr)

    return domains


def load_existing_hosts(filepath):
    """加载现有的 adhosts 文件"""
    hosts = set()
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as fp:
            for line in fp:
                line = line.strip()
                if line and not line.startswith('#'):
                    hosts.add(line)
    return hosts


def load_whitelist(filepath):
    """加载白名单文件"""
    whitelist = set()
    if filepath and os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as fp:
            for line in fp:
                line = line.strip()
                if line and not line.startswith('#'):
                    whitelist.add(line.lower())
    return whitelist


def filter_by_whitelist(domains, whitelist):
    """根据白名单过滤域名

    白名单中的域名及其子域名都会被过滤掉
    例如白名单包含 "example.com"，则 "example.com" 和 "sub.example.com" 都会被过滤
    """
    if not whitelist:
        return domains

    filtered = set()
    for domain in domains:
        is_whitelisted = False
        for wl_domain in whitelist:
            # 完全匹配或子域名匹配
            if domain == wl_domain or domain.endswith('.' + wl_domain):
                is_whitelisted = True
                break
        if not is_whitelisted:
            filtered.add(domain)
    return filtered


def save_hosts(filepath, hosts):
    """保存域名列表到文件"""
    sorted_hosts = sorted(hosts)
    with open(filepath, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(sorted_hosts))
        fp.write('\n')


def main():
    # 获取脚本所在目录，用于默认路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_whitelist = os.path.join(script_dir, '..', 'docs', 'domain-whitelist.txt')

    parser = ArgumentParser(description="广告域名列表更新工具")
    parser.add_argument(
        "-o", "--out-path",
        default="adhosts",
        help="输出文件路径 (默认: adhosts)"
    )
    parser.add_argument(
        "--proxy",
        help="代理服务器地址，用于访问国外源 (例如: socks5://127.0.0.1:10618)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="请求超时时间，单位秒 (默认: 30)"
    )
    parser.add_argument(
        "--no-merge",
        action="store_true",
        help="不合并现有文件，完全覆盖"
    )
    parser.add_argument(
        "--whitelist",
        default=default_whitelist,
        help=f"白名单文件路径 (默认: {default_whitelist})"
    )
    parser.add_argument(
        "--no-whitelist",
        action="store_true",
        help="不使用白名单过滤"
    )
    args = parser.parse_args()

    print(f"广告域名列表更新工具")
    print(f"输出文件: {args.out_path}")
    if args.proxy:
        print(f"代理服务器: {args.proxy}")
    print("-" * 50)

    # 加载现有域名
    if args.no_merge:
        all_domains = set()
        print("模式: 覆盖")
    else:
        all_domains = load_existing_hosts(args.out_path)
        print(f"模式: 合并 (现有 {len(all_domains)} 条记录)")
    print("-" * 50)

    # 从各个源获取域名
    for url, needs_proxy, description in AD_SOURCES:
        print(f"\n[获取] {description}")
        print(f"  URL: {url}")

        proxy = args.proxy if needs_proxy else None
        if needs_proxy and not proxy:
            print("  [跳过] 需要代理但未配置代理")
            continue

        domains = fetch_domains(url, proxy=proxy, timeout=args.timeout)
        if domains:
            before = len(all_domains)
            all_domains.update(domains)
            added = len(all_domains) - before
            print(f"  [完成] 获取 {len(domains)} 条, 新增 {added} 条")
        else:
            print("  [警告] 未获取到有效域名")

    # 白名单过滤
    print("-" * 50)
    if not args.no_whitelist:
        whitelist = load_whitelist(args.whitelist)
        if whitelist:
            print(f"[过滤] 加载白名单: {args.whitelist} ({len(whitelist)} 条)")
            before_filter = len(all_domains)
            all_domains = filter_by_whitelist(all_domains, whitelist)
            filtered_count = before_filter - len(all_domains)
            print(f"[过滤] 已过滤 {filtered_count} 条白名单域名")
        else:
            print(f"[过滤] 白名单文件不存在或为空: {args.whitelist}")

    # 保存结果
    print("-" * 50)
    save_hosts(args.out_path, all_domains)
    print(f"\n[完成] 共 {len(all_domains)} 条广告域名已保存到 {args.out_path}")


if __name__ == "__main__":
    main()
