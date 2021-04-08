# libuhttpd([中文](/README_ZH.md))

[1]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/libuhttpd/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/libuhttpd/issues/new
[7]: https://img.shields.io/badge/release-3.11.0-blue.svg?style=plastic
[8]: https://github.com/zhaojh329/libuhttpd/releases
[9]: https://github.com/zhaojh329/libuhttpd/workflows/build/badge.svg

[![license][1]][2]
[![PRs Welcome][3]][4]
[![Issue Welcome][5]][6]
[![Release Version][7]][8]
![Build Status][9]

[libev]: http://software.schmorp.de/pkg/libev.html
[http-parser]: https://github.com/nodejs/http-parser
[openssl]: https://github.com/openssl/openssl
[mbedtls]: https://github.com/ARMmbed/mbedtls
[wolfssl]: https://github.com/wolfSSL/wolfssl

A very flexible, lightweight and fully asynchronous HTTP server library based on [libev] and [http-parser] for Embedded Linux.

# Features
* Lightweight and fully asynchronous
* Use [libev] as its event backend
* Support HTTPS - OpenSSL, mbedtls and CyaSSl(wolfssl)
* Support HTTP pipelining
* Support IPv6
* Support plugin
* Support upload large file
* Support HTTP range requests
* Support multi-process model - The same multi-process model as Nginx
* Flexible - you can easily extend your application to have HTTP/HTTPS services
* Code structure is concise and understandable, also suitable for learning

# Dependencies
* [libev] - A full-featured and high-performance event loop
* [http-parser] - A high performance parser for HTTP messages written in C
* [mbedtls] - If you choose mbedtls as your SSL backend
* [wolfssl] - If you choose wolfssl as your SSL backend
* [openssl] - If you choose openssl as your SSL backend

# Benchmark
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

# Configure
See which configuration are supported

	~/libuhttpd/$ mkdir build && cd build
	~/libuhttpd/build$ cmake .. -L
	~/libuhttpd/build$ cmake .. -LH

# Build and install

	~/libuhttpd/build$ make && sudo make install

# Run Example	
Run

	~/libuhttpd/build$ ./example/simple_server -v
	
Then use the command curl or browser to test

	$ curl 'https://127.0.0.1:8000' -v

# Install on OpenWrt
    opkg update
    opkg list | grep libuhttpd
    opkg install libuhttpd-nossl

If the install command fails, you can [compile it yourself](/BUILDOPENWRT.md).

# [Example](/example)

# Contributing
If you would like to help making [libuhttpd](https://github.com/zhaojh329/libuhttpd) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/libuhttpd/blob/master/CONTRIBUTING.md) file.

