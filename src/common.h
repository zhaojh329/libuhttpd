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

#ifndef _COMMON_H
#define _COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/limits.h>

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/kvlist.h>
#include <libubox/ustream.h>

#include "config.h"
#include "log.h"

#endif