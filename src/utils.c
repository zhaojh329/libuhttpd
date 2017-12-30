/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
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

#include "utils.h"

void uh_printf(struct uh_client *cl, const char *format, ...)
{
    va_list arg;

    uloop_timeout_set(&cl->timeout, UHTTPD_CONNECTION_TIMEOUT * 1000);
    va_start(arg, format);
    ustream_vprintf(cl->us, format, arg);
    va_end(arg);
}

void uh_vprintf(struct uh_client *cl, const char *format, va_list arg)
{
    uloop_timeout_set(&cl->timeout, UHTTPD_CONNECTION_TIMEOUT * 1000);
    ustream_vprintf(cl->us, format, arg);
}

void uh_chunk_send(struct uh_client *cl, const void *data, int len)
{
    struct ustream *us = cl->us;

    uloop_timeout_set(&cl->timeout, UHTTPD_CONNECTION_TIMEOUT * 1000);
    ustream_printf(us, "%X\r\n", len);
    ustream_write(us, data, len, true);
    ustream_printf(us, "\r\n", len);
}

void uh_chunk_printf(struct uh_client *cl, const char *format, ...)
{
    va_list arg;

    va_start(arg, format);
    uh_chunk_vprintf(cl, format, arg);
    va_end(arg);
}

void uh_chunk_vprintf(struct uh_client *cl, const char *format, va_list arg)
{
    struct ustream *us = cl->us;
    char buf[256];
    va_list arg2;
    int len;

    uloop_timeout_set(&cl->timeout, UHTTPD_CONNECTION_TIMEOUT * 1000);
    
    va_copy(arg2, arg);
    len = vsnprintf(buf, sizeof(buf), format, arg2);
    va_end(arg2);

    ustream_printf(us, "%X\r\n", len);
    if (len < sizeof(buf))
        ustream_write(cl->us, buf, len, true);
    else
        ustream_vprintf(cl->us, format, arg);
    ustream_printf(us, "\r\n", len);
}

char *uh_split_header(char *str)
{
    char *val;

    val = strchr(str, ':');
    if (!val)
        return NULL;

    *val = 0;
    val++;

    while (isspace(*val))
        val++;

    return val;
}

/* blen is the size of buf; slen is the length of src.  The input-string need
** not be, and the output string will not be, null-terminated.  Returns the
** length of the decoded string, -1 on buffer overflow, -2 on malformed string. */
int uh_urldecode(char *buf, int blen, const char *src, int slen)
{
    int i;
    int len = 0;

#define hex(x) \
    (((x) <= '9') ? ((x) - '0') : \
        (((x) <= 'F') ? ((x) - 'A' + 10) : \
            ((x) - 'a' + 10)))

    for (i = 0; (i < slen) && (len < blen); i++)
    {
        if (src[i] != '%') {
            buf[len++] = src[i];
            continue;
        }

        if (i + 2 >= slen || !isxdigit(src[i + 1]) || !isxdigit(src[i + 2]))
            return -2;

        buf[len++] = (char)(16 * hex(src[i+1]) + hex(src[i+2]));
        i += 2;
    }
    buf[len] = 0;

    return (i == slen) ? len : -1;
}

/* blen is the size of buf; slen is the length of src.  The input-string need
** not be, and the output string will not be, null-terminated.  Returns the
** length of the encoded string, or -1 on error (buffer overflow) */
int uh_urlencode(char *buf, int blen, const char *src, int slen)
{
    int i;
    int len = 0;
    static const char hex[] = "0123456789abcdef";

    for (i = 0; (i < slen) && (len < blen); i++)
    {
        if( isalnum(src[i]) || (src[i] == '-') || (src[i] == '_') ||
            (src[i] == '.') || (src[i] == '~') )
        {
            buf[len++] = src[i];
        }
        else if ((len+3) <= blen)
        {
            buf[len++] = '%';
            buf[len++] = hex[(src[i] >> 4) & 15];
            buf[len++] = hex[ src[i]       & 15];
        }
        else
        {
            len = -1;
            break;
        }
    }

    return (i == slen) ? len : -1;
}

int find_idx(const char *const *list, int max, const char *str)
{
    int i;

    for (i = 0; i < max; i++)
        if (!strcmp(list[i], str))
            return i;
    return -1;
}
