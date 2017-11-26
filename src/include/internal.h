#ifndef _UHTTP_INTERNAL_H
#define _UHTTP_INTERNAL_H

#include "uhttp/http_parser.h"
#include "list.h"
#include "uhttp/uhttp.h"

#define UH_BUFFER_SIZE        2048
#define UH_CONNECTION_TIMEOUT 30
#define UH_URI_SIZE_LIMIT     1024
#define UH_HEAD_SIZE_LIMIT    1024
#define UH_BODY_SIZE_LIMIT    (2 * 1024 * 1024)
#define UH_HEADER_NUM_LIMIT   20

#define UH_CON_CLOSE                (1 << 0)
#define UH_CON_SSL_HANDSHAKE_DONE   (1 << 1)    /* SSL hanshake has completed */
#define UH_CON_PARSERING            (1 << 2)    /* Whether executed http_parser_execute() */
#define UH_CON_REUSE                (1 << 3)

#define likely(x)   (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))

#define ev_timer_mode(l,w,after,repeat) do { \
    ev_timer_stop(l, w); \
    ev_timer_init(w, ev_cb(w), after, repeat); \
    ev_timer_start(l, w); \
    } while (0)

struct uh_route {
    char *path;
    uh_route_handler_t cb;
    struct list_head list;
};

struct uh_server {
    int sock;
#if (UHTTP_SSL_ENABLED) 
    void *ssl_ctx;
#endif
    ev_io read_watcher;
    struct ev_loop *loop;
    struct list_head routes;
    struct list_head connections;
};

struct uh_header {
    struct uh_str field;
    struct uh_str value;
};

struct uh_request {
    struct uh_str url;
    struct uh_str path;
    struct uh_str query;
    struct uh_str body;
    int header_num;
    struct uh_header header[UH_HEADER_NUM_LIMIT];
};

struct uh_connection {  
    int sock;
#if (UHTTP_SSL_ENABLED) 
    void *ssl;
#endif
    unsigned char flags;
    struct uh_buf read_buf;
    struct uh_buf write_buf;
    ev_io read_watcher;
    ev_io write_watcher;
    ev_timer timer_watcher;
    struct uh_request req;
    http_parser parser;
    struct list_head list;
    struct uh_server *srv;
};

#endif
