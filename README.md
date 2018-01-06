# libuhttpd([中文](https://github.com/zhaojh329/libuhttpd/blob/master/README_ZH.md))

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

[libubox]: https://git.openwrt.org/?p=project/libubox.git
[uhttpd]: https://git.openwrt.org/?p=project/uhttpd.git
[ustream-ssl]: https://git.openwrt.org/?p=project/ustream-ssl.git
[openssl]: https://github.com/openssl/openssl
[mbedtls]: https://github.com/ARMmbed/mbedtls
[CyaSSl(wolfssl)]: https://github.com/wolfSSL/wolfssl

A very tiny and fast HTTP server library based on [libubox] and referenced from [uhttpd] for Embedded Linux.

`Keep Watching for More Actions on This Space`

# Features
* Action - processes requests by invoking registered C functions which mapped to a specific path.
* Tiny and fast
* Use [libubox] as its event backend
* Support HTTPS - OpenSSL, mbedtls and CyaSSl(wolfssl)
* Flexible - you can easily extend your application to have HTTP/HTTPS services
* Code structure is concise and understandable, also suitable for learning

# TO DO
* Lua API - Using Lua programming
* Lua Template - Embed Lua code into HTML code, like embedding PHP into HTML

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
	
# How to use on OpenWRT
add new feed into "feeds.conf.default":

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

# Example
```
#include <uhttpd.h>

//#define EXAMPLE_SSL

#define port 8000

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

int main(int argc, char **argv)
{
    struct uh_server *srv = NULL;
    
    uh_log_debug("libuhttpd version: %s", UHTTPD_VERSION_STRING);

    uloop_init();

    srv = uh_server_new("0.0.0.0", port);
    if (!srv)
        goto done;

    uh_log_debug("Listen on: *:%s", port);

#ifdef EXAMPLE_SSL
#if (UHTTPD_SSL_SUPPORT)
    if (srv->ssl_init(srv, "server-key.pem", "server-cert.pem") < 0)
        goto done;
#endif
#endif
    srv->add_action(srv, "/hello", hello_action);
    
    uloop_run();
done:
    uloop_done();
    srv->free(srv);
    
    return 0;
}
```

# Contributing
If you would like to help making [libuhttpd](https://github.com/zhaojh329/libuhttpd) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/libuhttpd/blob/master/CONTRIBUTING.md) file.
