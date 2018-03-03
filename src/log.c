/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include "log.h"

void __uh_log(const char *filename, int line, int priority, const char *fmt, ...)
{
    va_list ap;
    static char buf[128];

    snprintf(buf, sizeof(buf), "(%s:%d) ", filename, line);
    
    va_start(ap, fmt);
    vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), fmt, ap);
    va_end(ap);

    if (priority == LOG_ERR && errno > 0) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ":%s", strerror(errno));
        errno = 0;
    }

    ulog(priority, "%s\n", buf);
}

