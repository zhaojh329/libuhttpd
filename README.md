# libuhttpd([中文](https://github.com/zhaojh329/libuhttpd/blob/master/README_ZH.md))

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

[libev]: http://software.schmorp.de/pkg/libev.html
[http-parser]: https://github.com/nodejs/http-parser

A very tiny and fast HTTP server library based on [libev] and [http-parser] for Embedded Linux.
Support HTTPS(alternative OpenSSL and CyaSSl(wolfssl)) and if you're sensitive to size,
you can choose CyaSSl(wolfssl).

`Keep Watching for More Actions on This Space`

# Features
* tiny and fast
* use [libev] as its event backend
* support HTTPS: alternative OpenSSL and CyaSSl(wolfssl)
* flexible and you can easily extend your application to have HTTP/HTTPS services
* Lua template: embed LUA code into HTML code, like embedding PHP to HTML
* code structure is concise and understandable, also suitable for learning

# Why use [libev] as its backend?
[libev] tries to do one thing only (POSIX event library), and this in the most efficient way possible.
Libevent tries to give you the full solution (event lib, non-blocking I/O library, http server, DNS client).

[libev] tries to follow the UNIX toolbox philosophy of doing one thing only, as good as possible.

# How to Build
## Install dependency Tools and Libraries
Ubuntu

	~$ sudo apt install gcc cmake libev-dev libssl-dev libwolfssl-dev

CentOS

	~$ sudo yum install gcc cmake libev-devel openssl-devel

## Clone the repository

	~$ git clone https://github.com/zhaojh329/libuhttpd.git
	~$ cd libuhttpd

## Create the build directory

	~/libuhttpd$ mkdir build
	~/libuhttpd$ cd build

## Configure
See which configuration are supported

	~/libuhttpd/build$ cmake .. -L
	~/libuhttpd/build$ cmake .. -LH

Default configure: automatically select the SSL library as its SSL backend(If there is a SSL library available)

	~/libuhttpd/build$ cmake ..

Disable SSl support

	~/libuhttpd/build$ cmake .. -DUHTTP_DISABLE_SSL=1

Explicit use OpenSSL as its SSL backend

	~/libuhttpd/build$ cmake .. -DUHTTP_USE_OPENSSL=1

Explicit use CyaSSl(wolfssl) as its SSL backend

	~/libuhttpd/build$ cmake .. -DUHTTP_USE_CYASSL=1

Turn on debug

	~/libuhttpd/build$ cmake .. -DUHTTP_DEBUG=1
	
## Build and install libuhttpd

    ~/libuhttpd/build$ make && sudo make install
	
## Run the Example
First generate the SSL certificate file

	~/libuhttpd/build$ cd ..
	~/libuhttpd$ ./gen_cert.sh
	
Run

	~/libuhttpd$ ./build/example/helloworld
	
Then use the command curl or browser to test

	$ curl -k 'https://127.0.0.1:8000/test?name=context%3d%7b"nid"%3a"test"%7d' -v

If use browser to test, it will be show

	Hello World
	Libuhttp v0.1
	Url: /test?name=context%3d%7b%22nid%22%3a%22test%22%7d
	Path: /test
	Name: context%3d%7b%22nid%22%3a%22test%22%7d
	Unescaped Name: context={"nid":"test"}
	Host: 192.168.0.100:8000
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36
	
# [Example](https://github.com/zhaojh329/libuhttpd/blob/master/example/helloworld.c)

# Contributing
If you would like to help making [libuhttpd](https://github.com/zhaojh329/libuhttpd) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/libuhttpd/blob/master/CONTRIBUTING.md) file.

# Thanks for the following project
* [libev]
* [http-parser]
* [mongoose](https://github.com/cesanta/mongoose)
