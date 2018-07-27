# libuhttpd([中文](/README_ZH.md))

[1]: https://img.shields.io/badge/license-LGPL2-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/libuhttpd/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/libuhttpd/issues/new
[7]: https://img.shields.io/badge/release-2.2.1-blue.svg?style=plastic
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

A Lightweight and fully asynchronous HTTP server library based on [libubox] and referenced
from [uhttpd] for Embedded Linux.

`Keep Watching for More Actions on This Space`

# Features
* Lightweight and fully asynchronous
* Use [libubox] as its event backend
* Support HTTPS - OpenSSL, mbedtls and CyaSSl(wolfssl)
* Flexible - you can easily extend your application to have HTTP/HTTPS services
* Code structure is concise and understandable, also suitable for learning
* Lua Template - Embed Lua code into HTML code, like embedding PHP into HTML
* Lua binding

# Dependencies
* [libubox]
* [ustream-ssl] - If you need to support SSL
* [mbedtls] - If you choose mbedtls as your SSL backend
* [CyaSSl(wolfssl)] - If you choose wolfssl as your SSL backend
* [openssl] - If you choose openssl as your SSL backend

# Configure
See which configuration are supported

	~/libuhttpd/$ mkdir build && cd build
	~/libuhttpd/build$ cmake .. -L
	~/libuhttpd/build$ cmake .. -LH

# Build and install

	~/libuhttpd/build$ make && sudo make install

# Run Example	
Run

	~/libuhttpd/build$ ./example/helloworld
	
Then use the command curl or browser to test

	$ curl -k 'https://127.0.0.1:8000/hello?name=test' -d '{"name":"libuhttpd"}' -v

# Install on OpenWrt
    opkg update
    opkg list | grep libuhttpd
    opkg install libuhttpd-nossl

If the install command fails, you can [compile it yourself](/BUILDOPENWRT.md).

# [Example](/example)

# Contributing
If you would like to help making [libuhttpd](https://github.com/zhaojh329/libuhttpd) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/libuhttpd/blob/master/CONTRIBUTING.md) file.

# QQ group: 153530783

# If the project is helpful to you, please do not hesitate to star. Thank you!
