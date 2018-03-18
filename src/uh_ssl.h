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

#ifndef __UHTTPD_SSL_H
#define __UHTTPD_SSL_H

#include "config.h"

#if (UHTTPD_SSL_SUPPORT)

int uh_ssl_init(struct uh_server *srv, const char *key, const char *crt);
void uh_ssl_free();
void uh_ssl_client_attach(struct uh_client *cl);
void uh_ssl_client_detach(struct uh_client *cl);

#else

static inline int uh_ssl_init(const char *key, const char *crt)
{
    return -1;
}

static inline void uh_ssl_free()
{
}

static inline void uh_ssl_client_attach(struct uh_client *cl)
{
}

static inline void uh_ssl_client_detach(struct uh_client *cl)
{
}

#endif

#endif
