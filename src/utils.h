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

#ifndef _UTILS_H
#define _UTILS_H

#include "client.h"

#define min(x, y) (((x) < (y)) ? (x) : (y))
#define max(x, y) (((x) > (y)) ? (x) : (y))

void uh_printf(struct uh_client *cl, const char *format, ...);
void uh_vprintf(struct uh_client *cl, const char *format, va_list arg);
void uh_chunk_send(struct uh_client *cl, const void *data, int len);
void uh_chunk_printf(struct uh_client *cl, const char *format, ...);
void uh_chunk_vprintf(struct uh_client *cl, const char *format, va_list arg);

char *uh_split_header(char *str);
int uh_urldecode(char *buf, int blen, const char *src, int slen);
int uh_urlencode(char *buf, int blen, const char *src, int slen);

int find_idx(const char *const *list, int max, const char *str);

#endif
