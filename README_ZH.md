# libuhttpd

[1]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/libuhttpd/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/libuhttpd/issues/new
[7]: https://img.shields.io/badge/release-3.3.0-blue.svg?style=plastic
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
* 支持插件
* 可伸缩 - 你可以非常方便的扩展你的应用程序，使之具备HTTP/HTTPS服务
* 代码结构简洁通俗易懂，亦适合学习

# 依赖
* [libev]
* [http-parser] - 已经集成到源码里面
* [mbedtls] - 如果你选择mbedtls作为你的SSL后端
* [wolfssl] - 如果你选择wolfssl作为你的SSL后端
* [openssl] - 如果你选择openssl作为你的SSL后端

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

