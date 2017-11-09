#ifndef _UHTTP_INTERNAL_H
#define _UHTTP_INTERNAL_H

#include "list.h"
#include "uhttp.h"

#define UH_BUFFER_SIZE 2048
#define UH_CONNECTION_TIMEOUT 30
#define UH_MAX_HTTP_HEADERS	20

#define UH_CONNECTION_CLOSE	(1 << 0)

#define likely(x)	(__builtin_expect(!!(x), 1))
#define unlikely(x)	(__builtin_expect(!!(x), 0))

struct uh_route {
	char *path;
	uh_route_handler_t cb;
	struct list_head list;
};

struct uh_server {
	int sock;
	ev_io read_watcher;
	struct ev_loop *loop;
	struct list_head routes;
	struct list_head connections;
};

struct uh_header {
	struct uh_value field;
	struct uh_value value;
};

struct uh_request {
	struct uh_value url;
	struct uh_value body;
	int header_num;
	struct uh_header header[UH_MAX_HTTP_HEADERS];
};

struct uh_connection {	
	int sock;
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