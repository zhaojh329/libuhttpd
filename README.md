# libuhttp

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

A very tiny and fast HTTP library based on [libev](http://software.schmorp.de/pkg/libev.html) and 
[http-parser](https://github.com/nodejs/http-parser) for Embedded Linux.

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
	$ ./example/helloworld
	
	Then use the command curl or browser to access http://127.0.0.1:8000/test