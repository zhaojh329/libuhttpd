# libuhttpd

[1]: https://img.shields.io/badge/license-LGPL2-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/libuhttpd/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/libuhttpd/issues/new
[7]: https://img.shields.io/badge/release-2.2.0-blue.svg?style=plastic
[8]: https://github.com/zhaojh329/libuhttpd/releases
[9]: https://travis-ci.org/zhaojh329/libuhttpd.svg?branch=master
[10]: https://travis-ci.org/zhaojh329/libuhttpd

[![license][1]][2]
[![PRs Welcome][3]][4]
[![Issue Welcome][5]][6]
[![Release Version][7]][8]
[![Build Status][9]][10]

[libubox]: https://git.openwrt.org/?p=project/libubox.git
[uhttpd]: https://git.openwrt.org/?p=project/uhttpd.git
[ustream-ssl]: https://git.openwrt.org/?p=project/ustream-ssl.git
[openssl]: https://github.com/openssl/openssl
[mbedtls]: https://github.com/ARMmbed/mbedtls
[CyaSSl(wolfssl)]: https://github.com/wolfSSL/wolfssl

一个轻量的全异步的HTTP服务器C库，基于[libubox]，参考了[uhttpd]。

`请保持关注以获取最新的项目动态`

# 特性
* 轻量、全异步
* 使用[libubox]作为其事件后端
* 支持HTTPS - OpenSSL, mbedtls 和 CyaSSl(wolfssl)
* 可伸缩 - 你可以非常方便的扩展你的应用程序，使之具备HTTP/HTTPS服务
* 代码结构简洁通俗易懂，亦适合学习
* Lua模板 - 嵌入LUA代码到HTML中，就像嵌入PHP到HTML中一样
* Lua绑定

# 依赖
* [libubox]
* [ustream-ssl] - 如果你需要支持SSL
* [mbedtls] - 如果你选择mbedtls作为你的SSL后端
* [CyaSSl(wolfssl)] - 如果你选择wolfssl作为你的SSL后端
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

	~/libuhttpd/build$ ./example/helloworld
	
然后使用命令curl或者浏览器进行测试

	$ curl -k 'https://127.0.0.1:8000/hello?name=test' -d '{"name":"libuhttpd"}' -v

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

# 如果该项目对您有帮助，请随手star，谢谢！
