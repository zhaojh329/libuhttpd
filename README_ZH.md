# libuhttpd

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

[libubox]: https://git.openwrt.org/?p=project/libubox.git
[uhttpd]: https://git.openwrt.org/?p=project/uhttpd.git
[ustream-ssl]: https://git.openwrt.org/?p=project/ustream-ssl.git
[openssl]: https://github.com/openssl/openssl
[mbedtls]: https://github.com/ARMmbed/mbedtls
[CyaSSl(wolfssl)]: https://github.com/wolfSSL/wolfssl

一个专门针对嵌入式Linux的非常小巧且快速的HTTP服务器C库，基于[libubox]，参考了[uhttpd]。

`请保持关注以获取最新的项目动态`

# 特性
* Action - 通过调用映射到特定路径的已注册C函数来处理请求。
* 小巧且快速
* 使用[libubox]作为其事件后端
* 支持HTTPS - OpenSSL, mbedtls 和 CyaSSl(wolfssl)
* 可伸缩 - 你可以非常方便的扩展你的应用程序，使之具备HTTP/HTTPS服务
* 代码结构简洁通俗易懂，亦适合学习

# 计划支持
* Lua API - 使用Lua编程
* Lua模板 - 嵌入LUA代码到HTML中，就像嵌入PHP到HTML中一样

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

# 如何在OpenWRT中使用
Add new feed into "feeds.conf.default":

    src-git libuhttpd https://github.com/zhaojh329/libuhttpd-feed.git

Install libuhttpd packages:

    ./scripts/feeds update libuhttpd
    ./scripts/feeds install -a -p libuhttpd

Select package libuhttpd in menuconfig and compile new image.

    Libraries  --->
        Networking  --->
            <*> libuhttpd-mbedtls.................................... libuhttpd (mbedtls)
            < > libuhttpd-nossl....................................... libuhttpd (NO SSL)
            < > libuhttpd-openssl.................................... libuhttpd (openssl)
            < > libuhttpd-wolfssl.................................... libuhttpd (wolfssl)

# 示例程序
```
#include <uhttpd.h>

static void hello_action(struct uh_client *cl)
{
    int body_len = 0;

    cl->send_header(cl, 200, "OK", -1);
    cl->append_header(cl, "Myheader", "Hello");
    cl->header_end(cl);

    cl->chunk_printf(cl, "<h1>Hello Libuhttpd %s</h1>", UHTTPD_VERSION_STRING);
    cl->chunk_printf(cl, "<h1>REMOTE_ADDR: %s</h1>", cl->get_peer_addr(cl));
    cl->chunk_printf(cl, "<h1>URL: %s</h1>", cl->get_url(cl));
    cl->chunk_printf(cl, "<h1>PATH: %s</h1>", cl->get_path(cl));
    cl->chunk_printf(cl, "<h1>QUERY: %s</h1>", cl->get_query(cl));
    cl->chunk_printf(cl, "<h1>VAR name: %s</h1>", cl->get_var(cl, "name"));
    cl->chunk_printf(cl, "<h1>BODY:%s</h1>", cl->get_body(cl, &body_len));
    cl->request_done(cl);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [option]\n"
        "          -p port  # Default port is 8080\n"
        "          -s       # SSl on\n"
        "          -v       # verbose\n", prog);
    exit(1);
}

int main(int argc, char **argv)
{
    struct uh_server *srv = NULL;
    int verbose = false;
    int ssl = false;
    int port = 8080;
    int opt;

    while ((opt = getopt(argc, argv, "p:vs")) != -1) {
        switch (opt)
        {
        case 'p':
            port = atoi(optarg);
            break;
        case 's':
            ssl = true;
            break;
        case 'v':
            verbose = true;
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

    if (!verbose)
        ulog_threshold(LOG_ERR);
    
    uh_log_debug("libuhttpd version: %s", UHTTPD_VERSION_STRING);

    uloop_init();

    srv = uh_server_new("0.0.0.0", port);
    if (!srv)
        goto done;

#if (!UHTTPD_SSL_SUPPORT)
    if (ssl)
        uh_log_debug("SSl is not compiled in");
#else
    if (ssl && srv->ssl_init(srv, "server-key.pem", "server-cert.pem") < 0)
        goto done;
#endif

    uh_log_debug("Listen on: %s *:%d", srv->ssl ? "https" : "http", port);

    srv->add_action(srv, "/hello", hello_action);
    
    uloop_run();
done:
    uloop_done();
    srv->free(srv);
    
    return 0;
}
```

# 贡献代码
如果你想帮助[libuhttpd](https://github.com/zhaojh329/libuhttpd)变得更好，请参考
[CONTRIBUTING_ZH.md](https://github.com/zhaojh329/libuhttpd/blob/master/CONTRIBUTING_ZH.md)。

# 技术交流
QQ群：153530783
