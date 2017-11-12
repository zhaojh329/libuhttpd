# libuhttp

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

[libev]: http://software.schmorp.de/pkg/libev.html
[http-parser]: https://github.com/nodejs/http-parser

A very tiny and fast HTTP library based on [libev] and [http-parser] for Embedded Linux.

`Keep Watching for More Actions on This Space`

# Features
* use [libev] as its event backend
* tiny and fast
* SSL support: Optional OpenSSL and CyaSSl(wolfssl)
* flexible and you can easily extend your application to have HTTP/HTTPS services

# Why use [libev] as its backend?
[libev] tries to do one thing only (POSIX event library), and this in the most efficient way possible.
Libevent tries to give you the full solution (event lib, non-blocking I/O library, http server, DNS client).

[libev] tries to follow the UNIX toolbox philosophy of doing one thing only, as good as possible.

# Build on Ubuntu
## Install dependency Tools and Libraries

	~$ sudo apt install cmake libev-dev libhttp-parser-dev libssl-dev libwolfssl-dev

## Clone the repository

	~$ git clone https://github.com/zhaojh329/libuhttp.git
	~$ cd libuhttp

## Create the build directory

	~/libuhttp$ mkdir build
	~/libuhttp$ cd build

## Configure
See which configuration are supported

	~/libuhttp/build$ cmake .. -LH

Default configure: automatically select the SSL library as its SSL backend(If there is a SSL library available).

	~/libuhttp/build$ cmake ..

Disable SSl support

	~/libuhttp/build$ cmake .. -DUHTTP_DISABLE_SSL=1

Explicit use OpenSSL as its SSL backend

	~/libuhttp/build$ cmake .. -DUHTTP_USE_OPENSSL=1

Explicit use CyaSSl(wolfssl) as its SSL backend

	~/libuhttp/build$ cmake .. -DUHTTP_USE_CYASSL=1

Turn on debug

	~/libuhttp/build$ cmake .. -DUHTTP_DEBUG=1
	
## Build and install libuhttp

    ~/libuhttp/build$ make && sudo make install
	
## Run the Example
First generate the SSL certificate file

	~/libuhttp/build$ cd ..
	~/libuhttp$ ./gen_cert.sh
	
Run

	~/libuhttp$ ./build/example/helloworld
	
Then use the command curl or browser to access https://127.0.0.1:8000/test

	$ curl -k https://127.0.0.1:8000/test -v
	
# [Example](https://github.com/zhaojh329/libuhttp/blob/master/example/helloworld.c)

# Contributing
If you would like to help making [libuhttp](https://github.com/zhaojh329/libuhttp) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/libuhttp/blob/master/CONTRIBUTING.md) file.

# Thanks for the following project
* [libev]
* [http-parser]

# If the project is helpful to you, please do not hesitate to star. Thank you!