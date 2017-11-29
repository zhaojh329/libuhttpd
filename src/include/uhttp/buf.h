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
 
#ifndef _UHTTP_BUF_H
#define _UHTTP_BUF_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define UH_BUF_SIZE_MULTIPLIER 3

struct uh_buf {
    char *base;     /* Buffer pointer */
    size_t len;     /* Data length */
    size_t size;    /* Buffer size */
};

#define uh_buf_available(b) ((b)->size - (b)->len)

/* Return 0 for successful or -1 if out of memory */
int uh_buf_init(struct uh_buf *buf, size_t initial_size);
int uh_buf_grow(struct uh_buf *buf, size_t size);

void uh_buf_free(struct uh_buf *buf);

/* Append data to the buf. Return the number of bytes appended. */
size_t uh_buf_append(struct uh_buf *buf, const void *data, size_t len);

/* Remove n bytes of data from the beginning of the buffer. */
void uh_buf_remove(struct uh_buf *buf, size_t n);

#endif
