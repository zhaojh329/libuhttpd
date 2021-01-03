# libuhttpd

[1]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/libuhttpd/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/libuhttpd/issues/new
[7]: https://img.shields.io/badge/release-3.7.0-blue.svg?style=plastic
[8]: https://github.com/zhaojh329/libuhttpd/releases
[9]: https://travis-ci.org/zhaojh329/libuhttpd.svg?branch=master
[10]: https://travis-ci.org/zhaojh329/libuhttpd

[![license][1]][2]
[![PRs Welcome][3]][4]
[![Issue Welcome][5]][6]
[![Release Version][7]][8]
[![Build Status][9]][10]

[libev]: http://software.schmorp.de/pkg/libev.html
[http-parser]: https://github.com/nodejs/http-parser
[openssl]: https://github.com/openssl/openssl
[mbedtls]: https://github.com/ARMmbed/mbedtls
[wolfssl]: https://github.com/wolfSSL/wolfssl

一个非常灵活的,轻量的,全异步的HTTP服务器C库，基于[libev]和[http-parser]，主要用于嵌入式Linux。

# 特性
* 轻量、全异步
* 使用[libev]作为其事件后端
* 支持HTTPS - OpenSSL, mbedtls 和 CyaSSl(wolfssl)
* 支持 HTTP 流水线
* 支持 IPv6
* 支持插件
* 支持上传大文件
* 支持多进程模型 - 和 Nginx 一样的多进程模型
* 可伸缩 - 你可以非常方便的扩展你的应用程序，使之具备HTTP/HTTPS服务
* 代码结构简洁通俗易懂，亦适合学习

# 依赖
* [libev] - 一个全功能和高性能的事件循环库
* [http-parser] - 一个用 C 语言编写的高性能的 HTTP 消息解析器
* [mbedtls] - 如果你选择mbedtls作为你的SSL后端
* [wolfssl] - 如果你选择wolfssl作为你的SSL后端
* [openssl] - 如果你选择openssl作为你的SSL后端

# 基准测试
## Nginx

	$ wrk -t4 -c400 -d10s http://localhost:80/test.html
	Running 10s test @ http://localhost:80/test.html
	4 threads and 400 connections
	Thread Stats   Avg      Stdev     Max   +/- Stdev
		Latency     3.54ms    7.32ms 224.58ms   93.30%
		Req/Sec    40.63k    12.49k   96.29k    74.50%
	1622012 requests in 10.05s, 385.09MB read
	Requests/sec: 161390.39
	Transfer/sec:     38.32MB

## libuhttpd

	$ wrk -t4 -c400 -d10s http://localhost:8080/test.html
	Running 10s test @ http://localhost:8080/test.html
	4 threads and 400 connections
	Thread Stats   Avg      Stdev     Max   +/- Stdev
		Latency     2.12ms    3.01ms  31.30ms   89.26%
		Req/Sec    70.87k    12.53k  142.54k    79.75%
	2826394 requests in 10.05s, 547.18MB read
	Requests/sec: 281328.83
	Transfer/sec:     54.46MB

# 配置
查看支持哪些配置选项

	~/libuhttpd/$ mkdir build && cd build
	~/libuhttpd/build$ cmake .. -L
	~/libuhttpd/build$ cmake .. -LH

# 编译和安装

	~/libuhttpd/build$ make && sudo make install

# 运行示例程序
运行

	~/libuhttpd/build$ ./example/example -v
	
然后使用命令curl或者浏览器进行测试

	$ curl -k 'https://127.0.0.1:8000/hello'

# 安装到OpenWRT
    opkg update
    opkg list | grep libuhttpd
    opkg install libuhttpd-nossl

如果安装失败，你可以[自己编译](/BUILDOPENWRT_ZH.md)。

# [示例程序](/example)

# 贡献代码
如果你想帮助[libuhttpd](https://github.com/zhaojh329/libuhttpd)变得更好，请参考
[CONTRIBUTING_ZH.md](https://github.com/zhaojh329/libuhttpd/blob/master/CONTRIBUTING_ZH.md)。

# 技术交流
QQ群：153530783

