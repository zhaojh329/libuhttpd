/*
 * MIT License
 *
 * Copyright (c) 2019 Jianhui Zhao <zhaojh329@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ctype.h>

#include "utils.h"

const char *saddr2str(struct sockaddr *addr, char buf[], int len, int *port)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        *port = ntohs(sin->sin_port);
        inet_ntop(AF_INET, &sin->sin_addr, buf, len);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        *port = ntohs(sin6->sin6_port);
        inet_ntop(AF_INET6, &sin6->sin6_addr, buf, len);
    }

    return buf;
}

bool support_so_reuseport()
{
    bool ok = false;
    int on = 1;
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (!setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(int)))
        ok = true;

    close(sock);

    return ok;
}

int urldecode(char *buf, int blen, const char *src, int slen)
{
    int i;
    int len = 0;

#define hex(x) \
    (((x) <= '9') ? ((x) - '0') : \
        (((x) <= 'F') ? ((x) - 'A' + 10) : \
            ((x) - 'a' + 10)))

    for (i = 0; (i < slen) && (len < blen); i++) {
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
