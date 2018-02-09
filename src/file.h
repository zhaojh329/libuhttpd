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

#ifndef _FILE_H
#define _FILE_H

#include <sys/stat.h>

#include "client.h"

struct path_info {
    const char *root;
    const char *phys;
    const char *name;
    const char *info;
    bool redirected;
    struct stat stat;
};

struct mimetype {
    const char *extn;
    const char *mime;
};

struct path_info *uh_path_lookup(struct uh_client *cl, const char *path);
bool handle_file_request(struct uh_client *cl, const char *path);

#endif