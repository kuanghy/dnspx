DNS Proxy Tool
==============

DNS 代理查询服务工具，旨在构建一个本地的轻量级的 DNS 服务器，用于加速 DNS 解析，规避 DNS 污染，屏蔽域名等。

## 特性

- 支持 UDP 和 TCP，以及 IPv4 和 IPv6
- 支持将海外域名用海外 DNS 服务器解析
- 支持额外的 hosts 文件，可用于广告过滤等
- 支持本地缓存 DNS，加速解析
- 支持挂载插件，以实现额外功能

## 安装

### Unix 平台

```shell
pip install dnspx
```

查看帮助：

```
dnspx --help
```

配置文件可参考：[config.example.yml](./config.example.yml)，配置文件支持以下位置：

```
/etc/dnspx/config.yml
/usr/local/etc/dnspx/config.yml
~/.local/etc/dnspx/config.yml
~/.config/dnspx/config.yml
```

支持加载多个自定义 hosts 文件，用于过滤广告等，自定义 hosts 文件支持以下位置：

```
/etc/dnspx/hosts
/usr/local/etc/dnspx/hosts
~/.local/etc/dnspx/hosts
~/.config/dnspx/hosts
/etc/dnspx/hosts.d/*
/usr/local/etc/dnspx/hosts.d/*
~/.local/etc/dnspx/hosts.d/*
~/.config/dnspx/hosts.d/*
```

在 unix 平台（如 Linux，MacOSX）推荐使用 supervisor 部署服务，配置文件可参考 [supervisor.example.conf](./supervisor.example.conf)。

### Windows

从 [Releases](https://github.com/kuanghy/dnspx/releases) 页面下载最新的发布版进行安装。或者 clone 本项目到本地，参考脚本 [build-app.bat](./scripts/build-app.bat) 自行构建。

安装完成后，可注册系统服务，让程序随系统自动启动（假设安装到了 `D:\dnspx` 目录下）：

```
sc create dnspx binPath= D:\dnspx\dnspx.exe start= delayed-auto displayname= dnspx
```

服务操作：

- 启动服务: `net start dnspx`
- 停止服务: `net stop dnspx`
- 删除服务: `sc delete dnspx`


## 参考链接

- [https://github.com/rthalley/dnspython](https://github.com/rthalley/dnspython)
- [https://github.com/Gandi/dnsknife](https://github.com/Gandi/dnsknife)
- [https://github.com/Anorov/PySocks](https://github.com/Anorov/PySocks)
