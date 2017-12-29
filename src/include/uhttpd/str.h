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
 
#ifndef _UHTTPD_STR_H
#define _UHTTPD_STR_H

struct uh_str {
    const char *at;
    size_t len;
};

 /* Return 1 for equal */
static inline int uh_str_cmp(struct uh_str *uv, const char *str)
{
    if (uv->len != strlen(str))
        return 0;
    return (!strncasecmp(uv->at, str, uv->len));
}

#endif
