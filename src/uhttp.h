#ifndef _UHTTP_H
#define _UHTTP_H

#include <ev.h>
#include "uhttp_config.h"
#include "uhttp_log.h"
#include "uhttp_buf.h"

/* HTTP Status Codes */
enum uh_status {
    UH_STATUS_CONTINUE                        = 100,
    UH_STATUS_SWITCHING_PROTOCOLS             = 101,
    UH_STATUS_PROCESSING                      = 102,
    UH_STATUS_OK                              = 200,
    UH_STATUS_CREATED                         = 201,
    UH_STATUS_ACCEPTED                        = 202,
    UH_STATUS_NON_AUTHORITATIVE_INFORMATION   = 203,
    UH_STATUS_NO_CONTENT                      = 204,
    UH_STATUS_RESET_CONTENT                   = 205,
    UH_STATUS_PARTIAL_CONTENT                 = 206,
    UH_STATUS_MULTI_STATUS                    = 207,
    UH_STATUS_ALREADY_REPORTED                = 208,
    UH_STATUS_IM_USED                         = 226,
    UH_STATUS_MULTIPLE_CHOICES                = 300,
    UH_STATUS_MOVED_PERMANENTLY               = 301,
    UH_STATUS_FOUND                           = 302,
    UH_STATUS_SEE_OTHER                       = 303,
    UH_STATUS_NOT_MODIFIED                    = 304,
    UH_STATUS_USE_PROXY                       = 305,
    UH_STATUS_TEMPORARY_REDIRECT              = 307,
    UH_STATUS_PERMANENT_REDIRECT              = 308,
    UH_STATUS_BAD_REQUEST                     = 400,
    UH_STATUS_UNAUTHORIZED                    = 401,
    UH_STATUS_PAYMENT_REQUIRED                = 402,
    UH_STATUS_FORBIDDEN                       = 403,
    UH_STATUS_NOT_FOUND                       = 404,
    UH_STATUS_METHOD_NOT_ALLOWED              = 405,
    UH_STATUS_NOT_ACCEPTABLE                  = 406,
    UH_STATUS_PROXY_AUTHENTICATION_REQUIRED   = 407,
    UH_STATUS_REQUEST_TIMEOUT                 = 408,
    UH_STATUS_CONFLICT                        = 409,
    UH_STATUS_GONE                            = 410,
    UH_STATUS_LENGTH_REQUIRED                 = 411,
    UH_STATUS_PRECONDITION_FAILED             = 412,
    UH_STATUS_PAYLOAD_TOO_LARGE               = 413,
    UH_STATUS_URI_TOO_LONG                    = 414,
    UH_STATUS_UNSUPPORTED_MEDIA_TYPE          = 415,
    UH_STATUS_RANGE_NOT_SATISFIABLE           = 416,
    UH_STATUS_EXPECTATION_FAILED              = 417,
    UH_STATUS_MISDIRECTED_REQUEST             = 421,
    UH_STATUS_UNPROCESSABLE_ENTITY            = 422,
    UH_STATUS_LOCKED                          = 423,
    UH_STATUS_FAILED_DEPENDENCY               = 424,
    UH_STATUS_UPGRADE_REQUIRED                = 426,
    UH_STATUS_PRECONDITION_REQUIRED           = 428,
    UH_STATUS_TOO_MANY_REQUESTS               = 429,
    UH_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
    UH_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS   = 451,
    UH_STATUS_INTERNAL_SERVER_ERROR           = 500,
    UH_STATUS_NOT_IMPLEMENTED                 = 501,
    UH_STATUS_BAD_GATEWAY                     = 502,
    UH_STATUS_SERVICE_UNAVAILABLE             = 503,
    UH_STATUS_GATEWAY_TIMEOUT                 = 504,
    UH_STATUS_HTTP_VERSION_NOT_SUPPORTED      = 505,
    UH_STATUS_VARIANT_ALSO_NEGOTIATES         = 506,
    UH_STATUS_INSUFFICIENT_STORAGE            = 507,
    UH_STATUS_LOOP_DETECTED                   = 508,
    UH_STATUS_NOT_EXTENDED                    = 510,
    UH_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511
};

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
 *      char data[] = "Hello World";
 *      uh_send_chunk(con, data, strlen(data));
 *      uh_send_chunk(con, NULL, 0); // Tell the client we're finished
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

#if (UHTTP_SSL_ENABLED)
/* Init ssl for the server */
int uh_ssl_init(struct uh_server *srv, const char *cert, const char *key);
#endif

#endif
