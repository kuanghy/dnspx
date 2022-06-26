DNS 服务压力测试
===============

[DNSPerf（DNS Performance）](https://github.com/cobblau/dnsperf) 工具可用于测试 DNS 服务器的性能。

测试示例：

```
dnsperf -s 114.114.114.114 -p 53 -d names-dnsperf.txt
```

其中 -d 选项指定需要查询的数据文件名，其内容如：

```
baidu.com A
google.com A
qq.com A
qq.com MX
gmail.com MX
sina.com A
konghy.cn A
blog.konghy.cn A
163.com A
163.com MX
taobao.com A
12306.com A
```

参数 -s 表示指定 DNS 服务器地址，还有 -p 参数可用于指定 DNS 服务器的端口


*Copyright (c) Huoty, 2020.06.22*
