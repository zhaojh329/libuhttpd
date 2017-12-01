# libuhttp

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

[libev]: http://software.schmorp.de/pkg/libev.html
[http-parser]: https://github.com/nodejs/http-parser

一个专门针对嵌入式Linux的非常小巧且快速的HTTP C库，基于[libev]和[http-parser]。支持HTTPS，
SSL后端可以选择OpenSSL和CyaSSl(wolfssl)，如果你对大小敏感，那么你可以选择CyaSSl(wolfssl)。

`请保持关注以获取最新的项目动态`

# 特性
* 小巧且快速
* 使用[libev]作为其事件后端
* 支持HTTPS: 可以选择OpenSSL和CyaSSl(wolfssl)
* 可伸缩：你可以非常方便的扩展你的应用程序，使之具备HTTP/HTTPS服务
* Lua模板：嵌入LUA代码到HTML中，就像嵌入PHP到HTML中一样（即将支持）
* 代码结构简洁通俗易懂，亦适合学习

# 为什么使用[libev]作为其事件后端?
[libev]试图做好一件事而已（目标是成为POSIX的事件库），这是最高效的方法。
libevent则尝试给你全套解决方案（事件库，非阻塞IO库，http库，DNS客户端）
[libev]尝试追随UNIX工具箱哲学，一次只干一件事，每次都做到最好。

# 如何编译
## 安装依赖的工具和库
Ubuntu

	~$ sudo apt install gcc cmake libev-dev libssl-dev libwolfssl-dev

CentOS

	~$ sudo yum install gcc cmake libev-devel openssl-devel

## 克隆仓库代码

	~$ git clone https://github.com/zhaojh329/libuhttp.git
	~$ cd libuhttp

## 创建编译目录

	~/libuhttp$ mkdir build
	~/libuhttp$ cd build

## 配置
查看支持哪些配置选项

	~/libuhttp/build$ cmake .. -L
	~/libuhttp/build$ cmake .. -LH

默认配置: 自动选择SSL库(如果有可用的SSL库)

	~/libuhttp/build$ cmake ..

禁用SSL

	~/libuhttp/build$ cmake .. -DUHTTP_DISABLE_SSL=1

强制选择OpenSSL

	~/libuhttp/build$ cmake .. -DUHTTP_USE_OPENSSL=1

强制选择CyaSSl(wolfssl)

	~/libuhttp/build$ cmake .. -DUHTTP_USE_CYASSL=1

打开调试

	~/libuhttp/build$ cmake .. -DUHTTP_DEBUG=1
	
## 编译和安装libuhttp

    ~/libuhttp/build$ make && sudo make install
	
## 运行例子
首先生成SSL证书文件

	~/libuhttp/build$ cd ..
	~/libuhttp$ ./gen_cert.sh
	
运行

	~/libuhttp$ ./build/example/helloworld
	
然后使用命令curl或者浏览器进行测试

	$ curl -k 'https://127.0.0.1:8000/test?name=context%3d%7b"nid"%3a"test"%7d' -v

如果使用浏览器测试，浏览器将会输出

	Hello World
	Libuhttp v0.1
	Url: /test?name=context%3d%7b%22nid%22%3a%22test%22%7d
	Path: /test
	Name: context%3d%7b%22nid%22%3a%22test%22%7d
	Unescaped Name: context={"nid":"test"}
	Host: 192.168.0.100:8000
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36
	
# [示例程序](https://github.com/zhaojh329/libuhttp/blob/master/example/helloworld.c)

# 贡献代码
如果你想帮助[libuhttp](https://github.com/zhaojh329/libuhttp)变得更好，请参考
[CONTRIBUTING_ZH.md](https://github.com/zhaojh329/libuhttp/blob/master/CONTRIBUTING_ZH.md)。

# 感谢以下开源项目提供帮助
* [libev]
* [http-parser]
* [mongoose](https://github.com/cesanta/mongoose)
