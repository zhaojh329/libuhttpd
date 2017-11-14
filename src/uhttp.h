#ifndef _UHTTP_H
#define _UHTTP_H

#include <ev.h>
#include "uhttp_config.h"
#include "uhttp_log.h"
#include "uhttp_buf.h"

/* HTTP Status Codes */
#define UH_STATUS_MAP(XX)                                                   \
  XX(100, CONTINUE,                        Continue)                        \
  XX(101, SWITCHING_PROTOCOLS,             Switching Protocols)             \
  XX(102, PROCESSING,                      Processing)                      \
  XX(200, OK,                              OK)                              \
  XX(201, CREATED,                         Created)                         \
  XX(202, ACCEPTED,                        Accepted)                        \
  XX(203, NON_AUTHORITATIVE_INFORMATION,   Non-Authoritative Information)   \
  XX(204, NO_CONTENT,                      No Content)                      \
  XX(205, RESET_CONTENT,                   Reset Content)                   \
  XX(206, PARTIAL_CONTENT,                 Partial Content)                 \
  XX(207, MULTI_STATUS,                    Multi-Status)                    \
  XX(208, ALREADY_REPORTED,                Already Reported)                \
  XX(226, IM_USED,                         IM Used)                         \
  XX(300, MULTIPLE_CHOICES,                Multiple Choices)                \
  XX(301, MOVED_PERMANENTLY,               Moved Permanently)               \
  XX(302, FOUND,                           Found)                           \
  XX(303, SEE_OTHER,                       See Other)                       \
  XX(304, NOT_MODIFIED,                    Not Modified)                    \
  XX(305, USE_PROXY,                       Use Proxy)                       \
  XX(307, TEMPORARY_REDIRECT,              Temporary Redirect)              \
  XX(308, PERMANENT_REDIRECT,              Permanent Redirect)              \
  XX(400, BAD_REQUEST,                     Bad Request)                     \
  XX(401, UNAUTHORIZED,                    Unauthorized)                    \
  XX(402, PAYMENT_REQUIRED,                Payment Required)                \
  XX(403, FORBIDDEN,                       Forbidden)                       \
  XX(404, NOT_FOUND,                       Not Found)                       \
  XX(405, METHOD_NOT_ALLOWED,              Method Not Allowed)              \
  XX(406, NOT_ACCEPTABLE,                  Not Acceptable)                  \
  XX(407, PROXY_AUTHENTICATION_REQUIRED,   Proxy Authentication Required)   \
  XX(408, REQUEST_TIMEOUT,                 Request Timeout)                 \
  XX(409, CONFLICT,                        Conflict)                        \
  XX(410, GONE,                            Gone)                            \
  XX(411, LENGTH_REQUIRED,                 Length Required)                 \
  XX(412, PRECONDITION_FAILED,             Precondition Failed)             \
  XX(413, PAYLOAD_TOO_LARGE,               Payload Too Large)               \
  XX(414, URI_TOO_LONG,                    URI Too Long)                    \
  XX(415, UNSUPPORTED_MEDIA_TYPE,          Unsupported Media Type)          \
  XX(416, RANGE_NOT_SATISFIABLE,           Range Not Satisfiable)           \
  XX(417, EXPECTATION_FAILED,              Expectation Failed)              \
  XX(421, MISDIRECTED_REQUEST,             Misdirected Request)             \
  XX(422, UNPROCESSABLE_ENTITY,            Unprocessable Entity)            \
  XX(423, LOCKED,                          Locked)                          \
  XX(424, FAILED_DEPENDENCY,               Failed Dependency)               \
  XX(426, UPGRADE_REQUIRED,                Upgrade Required)                \
  XX(428, PRECONDITION_REQUIRED,           Precondition Required)           \
  XX(429, TOO_MANY_REQUESTS,               Too Many Requests)               \
  XX(431, REQUEST_HEADER_FIELDS_TOO_LARGE, Request Header Fields Too Large) \
  XX(451, UNAVAILABLE_FOR_LEGAL_REASONS,   Unavailable For Legal Reasons)   \
  XX(500, INTERNAL_SERVER_ERROR,           Internal Server Error)           \
  XX(501, NOT_IMPLEMENTED,                 Not Implemented)                 \
  XX(502, BAD_GATEWAY,                     Bad Gateway)                     \
  XX(503, SERVICE_UNAVAILABLE,             Service Unavailable)             \
  XX(504, GATEWAY_TIMEOUT,                 Gateway Timeout)                 \
  XX(505, HTTP_VERSION_NOT_SUPPORTED,      HTTP Version Not Supported)      \
  XX(506, VARIANT_ALSO_NEGOTIATES,         Variant Also Negotiates)         \
  XX(507, INSUFFICIENT_STORAGE,            Insufficient Storage)            \
  XX(508, LOOP_DETECTED,                   Loop Detected)                   \
  XX(510, NOT_EXTENDED,                    Not Extended)                    \
  XX(511, NETWORK_AUTHENTICATION_REQUIRED, Network Authentication Required) \

enum uh_status {
#define XX(num, name, string) UH_STATUS_##name = num,
  UH_STATUS_MAP(XX)
#undef XX
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
struct uh_value *uh_get_path(struct uh_connection *con);
struct uh_value *uh_get_query(struct uh_connection *con);
struct uh_value uh_get_var(struct uh_connection *con, const char *name);
struct uh_value *uh_get_header(struct uh_connection *con, const char *name);

/* Unescapes strings like '%7B1,%202,%203%7D' would become '{1, 2, 3}' */
int uh_unescape(const char *str, int len, char *out, int olen);

#if (UHTTP_SSL_ENABLED)
/* Init ssl for the server */
int uh_ssl_init(struct uh_server *srv, const char *cert, const char *key);
#endif

#endif
