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

配置文件支持以下位置：

```
/etc/dnspx/config.yml
/usr/local/etc/dnspx/config.yml
~/.local/etc/dnspx/config.yml
~/.config/dnspx/config.yml
```

配置文件可参考：[config.example.yml](./config.example.yml)

本地 hosts 文件支持以下位置：

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

查看帮助：

```
dnspx --help
```

### Windows

安装完成后，注册系统服务，让程序隋系统自动启动（假设安装到了 `D:\dnspx` 目录下）：

```
sc create dnspx binPath= "D:\dnspx\dnspx.exe --config D:\dnspx\config" start= delayed-auto displayname= dnspx
```

- 启动服务: `net start dnspx`
- 停止服务: `net stop dnspx`
- 删除服务: `sc delete dnspx`


## 参考链接

- [https://github.com/rthalley/dnspython](https://github.com/rthalley/dnspython)
- [https://github.com/Gandi/dnsknife](https://github.com/Gandi/dnsknife)
- [https://github.com/Anorov/PySocks](https://github.com/Anorov/PySocks)
