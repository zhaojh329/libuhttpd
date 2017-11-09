#ifndef _UHTTP_H
#define _UHTTP_H

#include <ev.h>
#include "uhttp_config.h"
#include "uhttp_log.h"
#include "uhttp_buf.h"

struct uh_server;
struct uh_connection;

struct uh_value {
	const char *at;
	size_t len;
};

typedef void (*uh_route_handler_t)(struct uh_connection *con);

const char *uh_version();

/* creates a new uhttp server instance. */
struct uh_server *uh_server_new(struct ev_loop *loop, const char *ipaddr, int port);

/* frees a uhttp server instance. */
void uh_server_free(struct uh_server *srv);

/* Sends data to the connection. */
int uh_send(struct uh_connection *con, const void *buf, int len);

/* Sends printf-formatted data to the connection. */
int uh_printf(struct uh_connection *con, const char *fmt, ...);

/*
 * Sends the response line and headers.
 * This function sends the response line with the `status`, and
 * automatically sends one header: either "Content-Length" or "Transfer-Encoding".
 * If `length` is negative, then "Transfer-Encoding: chunked" is sent, otherwise,
 * "Content-Length" is sent.
 *
 * NOTE: If `Transfer-Encoding` is `chunked`, then message body must be sent
 * using `uh_send_chunk()` or `uh_printf_chunk()` functions.
 * Otherwise, `uh_send()` or `uh_printf()` must be used.
 * Extra headers could be set through `extra_headers`.
 *
 * NOTE: `extra_headers` must NOT be terminated by a new line.
 */
void uh_send_head(struct uh_connection *con, int status, int length, const char *extra_headers);

/*
 * Sends a http error response. If reason is NULL, the message will be inferred
 * from the error code (if supported).
 */
void uh_send_error(struct uh_connection *con, int code, const char *reason);

/*
 * Sends a http redirect response. `code` should be either 301 
 * or 302 and `location` point to the new location.
 */
void uh_redirect(struct uh_connection *con, int code, const char *location);

/*
 * Sends data to the connection using chunked HTTP encoding.
 *
 * NOTE: The HTTP header "Transfer-Encoding: chunked" should be sent prior to 
 * using this function.
 *
 * NOTE: do not forget to send an empty chunk at the end of the response,
 * to tell the client that everything was sent.
 *
 * Example:
 *		char data[] = "Hello World";
 *		uh_send_chunk(con, data, strlen(data));
 *		uh_send_chunk(con, NULL, 0); // Tell the client we're finished
 */
int uh_send_chunk(struct uh_connection *con, const char *buf, int len);

/*
 * Sends a printf-formatted HTTP chunk.
 * Functionality is similar to `uh_send_chunk()`.
 */
int uh_printf_chunk(struct uh_connection *con, const char *fmt, ...);

/* sets a callback to be executed on a specific path */
int uh_register_route(struct uh_server *srv, const char *path, uh_route_handler_t cb);

struct uh_value *uh_get_url(struct uh_connection *con);
struct uh_value *uh_get_header(struct uh_connection *con, const char *name);

#endif
