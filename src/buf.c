/*
 * Copyright (C) 2017  Jianhui Zhao <jianhuizhao329@gmail.com>
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

#include <assert.h>
#include <string.h>
#include "uhttpd/buf.h"
#include "uhttpd/log.h"

int uh_buf_init(struct uh_buf *buf, size_t initial_size)
{
    buf->len = buf->size = 0;

    if (buf->base) {
        free(buf->base);
        buf->base = NULL;
    }

    if (initial_size > 0) {
        buf->base = malloc(initial_size);
        if (!buf->base)
            return -1;
        buf->size = initial_size;
    }

    return 0;
}

int uh_buf_grow(struct uh_buf *buf, size_t size)
{
    void *base = realloc(buf->base, buf->size + size);
    if (!base)
        return -1;
    
    buf->base = base;
    buf->size += size;

    return 0;
}

void uh_buf_free(struct uh_buf *buf)
{
    uh_buf_init(buf, 0);
}

size_t uh_buf_append(struct uh_buf *buf, const void *data, size_t len)
{
    assert(buf);

    if (!data)
        return 0;

    if (buf->len + len > buf->size) {
        if (uh_buf_grow(buf, len << UH_BUF_SIZE_MULTIPLIER) == -1)
            len = buf->size - buf->len;
    }

    memcpy(buf->base + buf->len, data, len);
    buf->len += len;

    return len;
}

void uh_buf_remove(struct uh_buf *buf, size_t n)
{
    if (n > 0 && n <= buf->len) {
        memmove(buf->base, buf->base + n, buf->len - n);
        buf->len -= n;
    }
}
