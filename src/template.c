/*
 * Copyright (C) 2017  Jianhui Zhao <jianhuizhao329@gmail.com>
 * 
 * based on https://git.lede-project.org/project/luci.git modules/luci-base/src/template_parser.c
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#include <stdint.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "internal.h"
#include "uhttp/uhttp.h"

/* code types */
#define T_TYPE_INIT         0
#define T_TYPE_TEXT         1
#define T_TYPE_COMMENT      2
#define T_TYPE_EXPR         3
#define T_TYPE_INCLUDE      4
#define T_TYPE_CODE         5
#define T_TYPE_EOF          6

/* leading and trailing code for different types */
static const char *gen_code[9][2] = {
    { NULL,                 NULL            },  /* T_TYPE_INIT */
    { "io.write(\"",           "\")"        },  /* T_TYPE_TEXT */
    { NULL,                 NULL            },  /* T_TYPE_COMMENT */
    { "io.write(tostring(",    " or \"\"))" },  /* T_TYPE_EXPR */
    { "include(\"",         "\")"           },  /* T_TYPE_INCLUDE */
    { NULL,                 " "             },  /* T_TYPE_CODE */
    { NULL,                 NULL            },  /* T_TYPE_EOF */
};

/* buffer object */
struct template_buffer {
    char *data;
    char *dptr;
    unsigned int size;
    unsigned int fill;
};

struct template_chunk {
    const char *s;
    const char *e;
    int type;
    int line;
};

/* parser state */
struct template_parser {
    int fd;
    uint32_t size;
    char *data;
    char *off;
    char *gc;
    int line;
    int in_expr;
    int strip_before;
    int strip_after;
    struct template_chunk prv_chunk;
    struct template_chunk cur_chunk;
    const char *file;
};

/* initialize a buffer object */
struct template_buffer *buf_init(int size)
{
    struct template_buffer *buf;

    if (size <= 0)
        size = 1024;

    buf = (struct template_buffer *)malloc(sizeof(struct template_buffer));

    if (buf != NULL)
    {
        buf->fill = 0;
        buf->size = size;
        buf->data = malloc(buf->size);

        if (buf->data != NULL) {
            buf->dptr = buf->data;
            buf->data[0] = 0;
            return buf;
        }
        free(buf);
    }

    return NULL;
}

/* grow buffer */
static int buf_grow(struct template_buffer *buf, int size)
{
    unsigned int off = (buf->dptr - buf->data);
    char *data;

    if (size <= 0)
        size = 1024;

    data = realloc(buf->data, buf->size + size);

    if (data != NULL) {
        buf->data  = data;
        buf->dptr  = data + off;
        buf->size += size;
        return buf->size;
    }

    return 0;
}

/* put one char into buffer object */
static int buf_putchar(struct template_buffer *buf, char c)
{
    if( ((buf->fill + 1) >= buf->size) && !buf_grow(buf, 0) )
        return 0;

    *(buf->dptr++) = c;
    *(buf->dptr) = 0;

    buf->fill++;
    return 1;
}

/* append data to buffer */
static int buf_append(struct template_buffer *buf, const char *s, int len)
{
    if ((buf->fill + len + 1) >= buf->size) {
        if (!buf_grow(buf, len + 1))
            return 0;
    }

    memcpy(buf->dptr, s, len);
    buf->fill += len;
    buf->dptr += len;

    *(buf->dptr) = 0;

    return len;
}

/* read buffer length */
static int buf_length(struct template_buffer *buf)
{
    return buf->fill;
}

/* destroy buffer object and return pointer to data */
static char *buf_destroy(struct template_buffer *buf)
{
    char *data = buf->data;

    free(buf);
    return data;
}

static void luastr_escape(struct template_buffer *out, const char *s, unsigned int l,
                   int escape_xml)
{
    int esl;
    char esq[8];
    char *ptr;

    for (ptr = (char *)s; ptr < (s + l); ptr++) {
        switch (*ptr) {
        case '\\':
            buf_append(out, "\\\\", 2);
            break;

        case '"':
            if (escape_xml)
                buf_append(out, "&#34;", 5);
            else
                buf_append(out, "\\\"", 2);
            break;

        case '\n':
            buf_append(out, "\\n", 2);
            break;

        case '\'':
        case '&':
        case '<':
        case '>':
            if (escape_xml) {
                esl = snprintf(esq, sizeof(esq), "&#%i;", *ptr);
                buf_append(out, esq, esl);
                break;
            }

        default:
            buf_putchar(out, *ptr);
        }
    }
}

/* Simple strstr() like function that takes len arguments for both haystack and needle. */
static char *strfind(char *haystack, int hslen, const char *needle, int ndlen)
{
    int match = 0;
    int i, j;

    for( i = 0; i < hslen; i++ ) {
        if( haystack[i] == needle[0] ) {
            match = ((ndlen == 1) || ((i + ndlen) <= hslen));

            for( j = 1; (j < ndlen) && ((i + j) < hslen); j++ ) {
                if( haystack[i+j] != needle[j] ) {
                    match = 0;
                    break;
                }
            }

            if( match )
                return &haystack[i];
        }
    }

    return NULL;
}


static int template_error(lua_State *L, struct template_parser *parser)
{
    const char *err = luaL_checkstring(L, -1);
    const char *off = parser->prv_chunk.s;
    const char *ptr;
    char msg[1024];
    int line = 0;
    int chunkline = 0;

    if ((ptr = strfind((char *)err, strlen(err), "]:", 2)) != NULL) {
        chunkline = atoi(ptr + 2) - parser->prv_chunk.line;

        while (*ptr) {
            if (*ptr++ == ' ') {
                err = ptr;
                break;
            }
        }
    }

    if (strfind((char *)err, strlen(err), "'char(27)'", 10) != NULL) {
        off = parser->data + parser->size;
        err = "'%>' expected before end of file";
        chunkline = 0;
    }

    for (ptr = parser->data; ptr < off; ptr++)
        if (*ptr == '\n')
            line++;

    snprintf(msg, sizeof(msg), "Syntax error in %s:%d: %s",
             parser->file ? parser->file : "[string]", line + chunkline, err ? err : "(unknown error)");

    lua_pushnil(L);
    lua_pushinteger(L, line + chunkline);
    lua_pushstring(L, msg);

    return 3;
}


static void template_close(struct template_parser *parser)
{
    if (!parser)
        return;

    if (parser->gc != NULL)
        free(parser->gc);

    /* if file is not set, we were parsing a string */
    if (parser->file) {
        if ((parser->data != NULL) && (parser->data != MAP_FAILED))
            munmap(parser->data, parser->size);

        if (parser->fd >= 0)
            close(parser->fd);
    }

    free(parser);
}

static void template_text(struct template_parser *parser, const char *e)
{
    const char *s = parser->off;

    if (s < (parser->data + parser->size)) {
        if (parser->strip_after) {
            while ((s <= e) && isspace(*s))
                s++;
        }

        parser->cur_chunk.type = T_TYPE_TEXT;
    } else {
        parser->cur_chunk.type = T_TYPE_EOF;
    }

    parser->cur_chunk.line = parser->line;
    parser->cur_chunk.s = s;
    parser->cur_chunk.e = e;
}

static void template_code(struct template_parser *parser, const char *e)
{
    const char *s = parser->off;

    parser->strip_before = 0;
    parser->strip_after = 0;

    if (*s == '-') {
        parser->strip_before = 1;
        for (s++; (s <= e) && (*s == ' ' || *s == '\t'); s++);
    }

    if (*(e-1) == '-') {
        parser->strip_after = 1;
        for (e--; (e >= s) && (*e == ' ' || *e == '\t'); e--);
    }

    switch (*s) {
        /* comment */
        case '#':
            s++;
            parser->cur_chunk.type = T_TYPE_COMMENT;
            break;

        /* include */
        case '+':
            s++;
            parser->cur_chunk.type = T_TYPE_INCLUDE;
            break;

        /* expr */
        case '=':
            s++;
            parser->cur_chunk.type = T_TYPE_EXPR;
            break;

        /* code */
        default:
            parser->cur_chunk.type = T_TYPE_CODE;
            break;
    }

    parser->cur_chunk.line = parser->line;
    parser->cur_chunk.s = s;
    parser->cur_chunk.e = e;
}



static const char *template_format_chunk(struct template_parser *parser, size_t *sz)
{
    const char *s, *p;
    const char *head, *tail;
    struct template_chunk *c = &parser->prv_chunk;
    struct template_buffer *buf;

    *sz = 0;
    s = parser->gc = NULL;

    if (parser->strip_before && c->type == T_TYPE_TEXT) {
        while ((c->e > c->s) && isspace(*(c->e - 1)))
            c->e--;
    }

    /* empty chunk */
    if (c->s == c->e) {
        if (c->type == T_TYPE_EOF) {
            *sz = 0;
            s = NULL;
        } else {
            *sz = 1;
            s = " ";
        }
    } else if ((buf = buf_init(c->e - c->s)) != NULL) { /* format chunk */
        if ((head = gen_code[c->type][0]) != NULL)
            buf_append(buf, head, strlen(head));

        switch (c->type) {
            case T_TYPE_TEXT:
                luastr_escape(buf, c->s, c->e - c->s, 0);
                break;

            case T_TYPE_EXPR:
                buf_append(buf, c->s, c->e - c->s);
                for (p = c->s; p < c->e; p++)
                    parser->line += (*p == '\n');
                break;

            case T_TYPE_INCLUDE:
                luastr_escape(buf, c->s, c->e - c->s, 0);
                break;

            case T_TYPE_CODE:
                buf_append(buf, c->s, c->e - c->s);
                for (p = c->s; p < c->e; p++)
                    parser->line += (*p == '\n');
                break;
        }

        if ((tail = gen_code[c->type][1]) != NULL)
            buf_append(buf, tail, strlen(tail));

        *sz = buf_length(buf);
        s = parser->gc = buf_destroy(buf);

        if (!*sz) {
            *sz = 1;
            s = " ";
        }
    }

    return s;
}

static const char *template_reader(lua_State *L, void *ud, size_t *sz)
{
    struct template_parser *parser = ud;
    int rem = parser->size - (parser->off - parser->data);
    char *tag;

    parser->prv_chunk = parser->cur_chunk;

    /* free previous string */
    if (parser->gc) {
        free(parser->gc);
        parser->gc = NULL;
    }

    /* before tag */
    if (!parser->in_expr) {
        if ((tag = strfind(parser->off, rem, "<%", 2)) != NULL) {
            template_text(parser, tag);
            parser->off = tag + 2;
            parser->in_expr = 1;
        } else {
            template_text(parser, parser->data + parser->size);
            parser->off = parser->data + parser->size;
        }
    } else { /* inside tag */
        if ((tag = strfind(parser->off, rem, "%>", 2)) != NULL) {
            template_code(parser, tag);
            parser->off = tag + 2;
            parser->in_expr = 0;
        } else {
            /* unexpected EOF */
            template_code(parser, parser->data + parser->size);

            *sz = 1;
            return "\033";
        }
    }

    return template_format_chunk(parser, sz);
}

static int template_L_do_parse(lua_State *L, struct template_parser *parser, const char *chunkname)
{
    int lua_status, rv;

    if (!parser) {
        lua_pushnil(L);
        lua_pushinteger(L, errno);
        lua_pushstring(L, strerror(errno));
        return 3;
    }

#if LUA_VERSION_NUM > 501
    lua_status = lua_load(L, template_reader, parser, chunkname, NULL);
#else
    lua_status = lua_load(L, template_reader, parser, chunkname);
#endif
    if (lua_status == 0)
        rv = 1;
    else
        rv = template_error(L, parser);

    template_close(parser);

    return rv;
}

struct template_parser * template_open(const char *file)
{
    struct stat s;
    struct template_parser *parser;

    if (!(parser = malloc(sizeof(*parser))))
        goto err;

    memset(parser, 0, sizeof(*parser));
    parser->fd = -1;
    parser->file = file;

    if (stat(file, &s))
        goto err;

    if ((parser->fd = open(file, O_RDONLY)) < 0)
        goto err;

    parser->size = s.st_size;
    parser->data = mmap(NULL, parser->size, PROT_READ, MAP_PRIVATE,
                        parser->fd, 0);

    if (parser->data != MAP_FAILED) {
        parser->off = parser->data;
        parser->cur_chunk.type = T_TYPE_INIT;
        parser->cur_chunk.s    = parser->data;
        parser->cur_chunk.e    = parser->data;

        return parser;
    }

err:
    template_close(parser);
    return NULL;
}

static void template_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    struct uh_connection *con = container_of(w, struct uh_connection, read_watcher_lua);
    char buf[1024] = "";
    int len;

    len = read(w->fd, buf, sizeof(buf));
    if (len > 0)
        uh_send_chunk(con, buf, len);
    else if (len == 0) {
        uh_send_chunk(con, NULL, 0);
        close(w->fd);
        ev_io_stop(con->srv->loop, w);

        if (!(con->flags & UH_CON_CLOSE))
            con->flags |= UH_CON_REUSE;
    }
}

static void child_cb(struct ev_loop *loop, ev_child *w, int revents)
{
    struct uh_connection *con = container_of(w, struct uh_connection, child_watcher);
    ev_child_stop(con->srv->loop, w);
}

void uh_template(struct uh_connection *con)
{
    struct template_parser *parser;
    lua_State *L = con->srv->L;
    pid_t pid;
    int pipefd[2];
    static char path[PATH_MAX] = "";
    struct stat st;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    struct uh_str *ustr;
    int i;

    strcpy(path, con->srv->docroot);
    strncat(path, con->req.path.at, con->req.path.len);

    if (stat(path, &st) < 0) {
        uh_send_error(con, HTTP_STATUS_NOT_FOUND, NULL);
        return;
    }

    uh_log_debug("Path:%s", path);
    

    if (!L) {
        L = luaL_newstate();
        if (!L) {
            uh_log_err("cannot create LUA state: not enough memory");
            goto err;
        }

        con->srv->L = L;
        luaL_openlibs(L);
    }

    /*
     * Add all variables to the global environment of LUA. 
     * eg. <%=_UHTTP["REMOTE_HOST"]%>
     */

    lua_newtable(L);
    
    lua_pushstring(L, uh_get_method_str(con)); 
    lua_setfield(L, -2, "HTTP_METHOD");

    getpeername(con->sock, (struct sockaddr *)&addr, &addrlen);
    lua_pushstring(L, inet_ntoa(addr.sin_addr));
    lua_setfield(L, -2, "REMOTE_HOST");

    ustr = uh_get_url(con);
    lua_pushlstring(L, ustr->at, ustr->len);
    lua_setfield(L, -2, "HTTP_URL");

    ustr = uh_get_path(con);
    lua_pushlstring(L, ustr->at, ustr->len);
    lua_setfield(L, -2, "HTTP_PATH");

    lua_newtable(L);

    for (i = 0; i < con->req.header_num; i ++) {
        struct uh_header *h = &con->req.header[i];

        lua_pushlstring(L, h->field.at, h->field.len);
        lua_pushlstring(L, h->value.at, h->value.len);
        lua_settable(L, -3);
    }

    lua_setfield(L, -2, "HEADERS");

    lua_setglobal(L, "_UHTTP");
    
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) < 0) {
        uh_log_err("pipe");
        goto err;
    }
    
    uh_send_head(con, HTTP_STATUS_OK, -1, "Pragma: no-cache\r\nCache-Control: no-cache\r\n");

    pid = fork();
    switch (pid) {
    case -1:
        uh_log_err("fork");
        goto err;
        break;
        
    case 0:
        close(0);
        close(1);
        close(pipefd[0]);
        dup2(pipefd[1], 1);

        parser = template_open(path);
        if (!parser) {
            uh_log_err("template_open failed");
            return;
        }

    
        if ((template_L_do_parse(L, parser, path) != 1) || lua_pcall(L, 0, 0, 0)) {
            uh_printf_chunk(con, "<h2><b>Lua Error</b></h2>\n%s\n", lua_tostring(L, -1));
            uh_printf_chunk(con, "</body></html>\n");
            uh_send_chunk(con, NULL, 0);
            lua_pop(L, -1);
        } else {
            uh_send_chunk(con, NULL, 0);
        }
        exit(0);
        break;
        
    default:
        close(pipefd[1]);
        ev_io_init(&con->read_watcher_lua, template_read_cb, pipefd[0], EV_READ);
        ev_io_start(con->srv->loop, &con->read_watcher_lua);

        ev_child_init(&con->child_watcher, child_cb, pid, 0);
        ev_child_start(con->srv->loop, &con->child_watcher);
        break;
    }

    return;
err:
    uh_send_error(con, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
}
