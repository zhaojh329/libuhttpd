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

#include <strings.h>
#include <string.h>

#include "mimetypes.h"

static const struct mimetype mime_types[] = {
    { "txt",     "text/plain" },
    { "log",     "text/plain" },
    { "js",      "text/javascript" },
    { "css",     "text/css" },
    { "htm",     "text/html" },
    { "html",    "text/html" },
    { "diff",    "text/x-patch" },
    { "patch",   "text/x-patch" },
    { "c",       "text/x-csrc" },
    { "h",       "text/x-chdr" },
    { "o",       "text/x-object" },
    { "ko",      "text/x-object" },

    { "bmp",     "image/bmp" },
    { "gif",     "image/gif" },
    { "png",     "image/png" },
    { "jpg",     "image/jpeg" },
    { "jpeg",    "image/jpeg" },
    { "svg",     "image/svg+xml" },

    { "json",    "application/json" },
    { "jsonp",   "application/javascript" },
    { "zip",     "application/zip" },
    { "pdf",     "application/pdf" },
    { "xml",     "application/xml" },
    { "xsl",     "application/xml" },
    { "doc",     "application/msword" },
    { "ppt",     "application/vnd.ms-powerpoint" },
    { "xls",     "application/vnd.ms-excel" },
    { "odt",     "application/vnd.oasis.opendocument.text" },
    { "odp",     "application/vnd.oasis.opendocument.presentation" },
    { "pl",      "application/x-perl" },
    { "sh",      "application/x-shellscript" },
    { "php",     "application/x-php" },
    { "deb",     "application/x-deb" },
    { "iso",     "application/x-cd-image" },
    { "tar.gz",  "application/x-compressed-tar" },
    { "tgz",     "application/x-compressed-tar" },
    { "gz",      "application/x-gzip" },
    { "tar.bz2", "application/x-bzip-compressed-tar" },
    { "tbz",     "application/x-bzip-compressed-tar" },
    { "bz2",     "application/x-bzip" },
    { "tar",     "application/x-tar" },
    { "rar",     "application/x-rar-compressed" },

    { "mp3",     "audio/mpeg" },
    { "ogg",     "audio/x-vorbis+ogg" },
    { "wav",     "audio/x-wav" },

    { "mpg",     "video/mpeg" },
    { "mpeg",    "video/mpeg" },
    { "avi",     "video/x-msvideo" },

    { "README",  "text/plain" },
    { "log",     "text/plain" },
    { "cfg",     "text/plain" },
    { "conf",    "text/plain" },

    { "pac",      "application/x-ns-proxy-autoconfig" },
    { "wpad.dat", "application/x-ns-proxy-autoconfig" },
    { "appcache", "text/cache-manifest" },
    { "manifest", "text/cache-manifest" },

    { NULL, NULL }
};

const char *file_mime_lookup(const char *path)
{
    const struct mimetype *m = &mime_types[0];
    const char *e;

    while (m->extn) {
        e = &path[strlen(path)-1];

        while (e >= path && *e != '/') {
            if (*e == '.' && !strcasecmp(&e[1], m->extn))
                return m->mime;

            e--;
        }

        m++;
    }

    return "application/octet-stream";
}
