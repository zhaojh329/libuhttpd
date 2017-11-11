# libuhttp

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

A very tiny and fast HTTP library based on [libev](http://software.schmorp.de/pkg/libev.html) and 
[http-parser](https://github.com/nodejs/http-parser) for Embedded Linux.

# Features
* Tiny and fast
* SSL support: Optional OpenSSL and CyaSSl(wolfssl)
* Highly customizable, and can be easily integrated into your application

# How To Compile on Ubuntu
## Install dependency Tools and Libraries
	sudo apt install cmake libev-dev libhttp-parser-dev

## Compile libuhttp
	git clone https://github.com/zhaojh329/libuhttp.git
    cd libuhttp
    mkdir build
    cd build
    cmake ../
    make && sudo make install

## Test
	$ cd ../ && ./gen_cert.sh
	$ ./build/example/helloworld
	
	Then use the command curl or browser to access https://127.0.0.1:8000/test
	
	$ curl -k https://127.0.0.1:8000/test -v
	
# [Example](https://github.com/zhaojh329/libuhttp/blob/master/example/helloworld.c)

# Contributing
If you would like to help making [libuhttp](https://github.com/zhaojh329/libuhttp) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/libuhttp/blob/master/CONTRIBUTING.md) file.

# Thanks for the following project
* [libev](http://software.schmorp.de/pkg/libev.html)
* [http-parser](https://github.com/nodejs/http-parser)

# If the project is helpful to you, please do not hesitate to star. Thank you!