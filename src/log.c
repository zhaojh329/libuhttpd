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
 
#include "uhttp/log.h"

void __uh_log(const char *filename, int line, int priority, const char *format, ...)
{
    va_list ap;
    static char buf[128];

    snprintf(buf, sizeof(buf), "(%s:%d) ", filename, line);
    
    va_start(ap, format);
    vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), format, ap);
    va_end(ap);

    if (priority == LOG_ERR && errno > 0) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ":%s", strerror(errno));
        errno = 0;
    }
    
    syslog(priority, "%s", buf);

#if (UHTTP_DEBUG)
    fprintf(stderr, "%s\n", buf);
#else
    if (priority == LOG_ERR)
        fprintf(stderr, "%s\n", buf);
#endif
}

