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

#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "file.h"
#include "utils.h"
#include "uhttpd.h"
#include "log.h"

static const struct mimetype uh_mime_types[] = {
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

    { "pac",        "application/x-ns-proxy-autoconfig" },
    { "wpad.dat",   "application/x-ns-proxy-autoconfig" },

    { NULL, NULL }
};

static char *canonpath(const char *path, char *path_resolved)
{
    const char *path_cpy = path;
    char *path_res = path_resolved;

    /* normalize */
    while ((*path_cpy != '\0') && (path_cpy < (path + PATH_MAX - 2))) {
        if (*path_cpy != '/')
            goto next;

        /* skip repeating / */
        if (path_cpy[1] == '/') {
            path_cpy++;
            continue;
        }

        /* /./ or /../ */
        if (path_cpy[1] == '.') {
            /* skip /./ */
            if ((path_cpy[2] == '/') || (path_cpy[2] == '\0')) {
                path_cpy += 2;
                continue;
            }

            /* collapse /x/../ */
            if ((path_cpy[2] == '.') &&
                ((path_cpy[3] == '/') || (path_cpy[3] == '\0'))) {
                while ((path_res > path_resolved) && (*--path_res != '/'));

                path_cpy += 3;
                continue;
            }
        }

next:
        *path_res++ = *path_cpy++;
    }

    /* remove trailing slash if not root / */
    if ((path_res > (path_resolved+1)) && (path_res[-1] == '/'))
        path_res--;
    else if (path_res == path_resolved)
        *path_res++ = '/';

    *path_res = '\0';

    return path_resolved;
}

/* Returns NULL on error.
** NB: improperly encoded URL should give client 400 [Bad Syntax]; returning
** NULL here causes 404 [Not Found], but that's not too unreasonable. */
struct path_info *uh_path_lookup(struct uh_client *cl, const char *url)
{
    static char buf[PATH_MAX];
    static char path_phys[PATH_MAX];
    static char path_info[PATH_MAX];
    static struct path_info p;
    const char *path = cl->get_path(cl);
    const char *query = cl->get_query(cl);

    const char *docroot = cl->srv->docroot;
    int docroot_len = strlen(docroot);
    char *pathptr = NULL;
    bool slash;

    int i = 0;
    int len;

    /* back out early if url is undefined */
    if (url == NULL)
        return NULL;

    memset(&p, 0, sizeof(p));
    path_phys[0] = 0;
    path_info[0] = 0;

    strcpy(buf, docroot);
    strcat(buf, path);

    /* create canon path */
    len = strlen(buf);
    slash = len && buf[len - 1] == '/';
    len = min(len, sizeof(path_phys) - 1);

    for (i = len; i >= 0; i--) {
        char ch = buf[i];
        bool exists;

        if (ch != 0 && ch != '/')
            continue;

        buf[i] = 0;
        exists = !!canonpath(buf, path_phys);
        buf[i] = ch;

        if (!exists)
            continue;

        /* test current path */
        if (stat(path_phys, &p.stat))
            continue;

        snprintf(path_info, sizeof(path_info), "%s", buf + i);
        break;
    }

    /* check whether found path is within docroot */
    if (strncmp(path_phys, docroot, docroot_len) != 0 ||
        (path_phys[docroot_len] != 0 &&
        path_phys[docroot_len] != '/'))
        return NULL;

    /* is a regular file */
    if (p.stat.st_mode & S_IFREG) {
        p.root = docroot;
        p.phys = path_phys;
        p.name = &path_phys[docroot_len];
        p.info = path_info[0] ? path_info : NULL;
        return &p;
    }

    if (!(p.stat.st_mode & S_IFDIR))
        return NULL;

    if (path_info[0])
        return NULL;

    pathptr = path_phys + strlen(path_phys);

    /* ensure trailing slash */
    if (pathptr[-1] != '/') {
        pathptr[0] = '/';
        pathptr[1] = 0;
        pathptr++;
    }

    /* if requested url resolves to a directory and a trailing slash
       is missing in the request url, redirect the client to the same
       url with trailing slash appended */
    if (!slash) {
        cl->redirect(cl, 302, "%s%s%s", &path_phys[docroot_len], query ? "?" : "", query ? query : "");
        p.redirected = 1;
        return &p;
    }

    /* try to locate index file */
    len = path_phys + sizeof(path_phys) - pathptr - 1;
    strcpy(pathptr, cl->srv->index_file);

    if (stat(path_phys, &p.stat) < 0)
        return NULL;

    p.root = docroot;
    p.phys = path_phys;
    p.name = &path_phys[docroot_len];

    return p.phys ? &p : NULL;
}

static char *file_unix2date(time_t ts, char *buf, int len)
{
    struct tm *t = gmtime(&ts);

    strftime(buf, len, "%a, %d %b %Y %H:%M:%S GMT", t);

    return buf;
}

static const char * uh_file_mime_lookup(const char *path)
{
    const struct mimetype *m = &uh_mime_types[0];
    const char *e;

    while (m->extn) {
        e = &path[strlen(path)-1];

        while (e >= path) {
            if ((*e == '.' || *e == '/') && !strcasecmp(&e[1], m->extn))
                return m->mime;
            e--;
        }
        m++;
    }

    return "application/octet-stream";
}

static void uh_file_response_ok_hdrs(struct uh_client *cl, struct stat *s)
{
    char buf[128];

    cl->printf(cl, "Last-Modified: %s\r\n", file_unix2date(s->st_mtime, buf, sizeof(buf)));
    cl->printf(cl, "Date: %s\r\n", file_unix2date(time(NULL), buf, sizeof(buf)));
}

static void uh_file_response_304(struct uh_client *cl, struct stat *s)
{
    cl->send_header(cl, 304, "Not Modified", 0);
    uh_file_response_ok_hdrs(cl, s);
}

static void uh_file_response_200(struct uh_client *cl, struct stat *s)
{
    cl->send_header(cl, 200, "OK", s->st_size);
    uh_file_response_ok_hdrs(cl, s);
}

static int uh_file_if_modified_since(struct uh_client *cl, struct stat *s)
{
    const char *date = kvlist_get(&cl->request.header, "if-modified-since");
    struct tm t;
    
    if (!date)
        return true;
    
    memset(&t, 0, sizeof(t));

    if ((strptime(date, "%a, %d %b %Y %H:%M:%S %Z", &t) ? timegm(&t) : 0) >= s->st_mtime) {
        uh_file_response_304(cl, s);
        return false;
    }

    return true;
}

static void file_write_cb(struct uh_client *cl)
{
    static char buf[4096];
    int fd = cl->dispatch.file.fd;
    int r;

    while (cl->us->w.data_bytes < 256) {
        r = read(fd, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            uh_log_err("read");
        }

        if (r <= 0) {
            cl->request_done(cl);
            return;
        }

        cl->send(cl, buf, r);
    }
}

static void uh_file_free(struct uh_client *cl)
{
    close(cl->dispatch.file.fd);
}

static void uh_file_data(struct uh_client *cl, struct path_info *pi, int fd)
{
    /* test preconditions */
    if ((!uh_file_if_modified_since(cl, &pi->stat))) {
        cl->printf(cl, "\r\n");
        cl->request_done(cl);
        close(fd);
        return;
    }

    /* write status */
    uh_file_response_200(cl, &pi->stat);

    cl->printf(cl, "Content-Type: %s\r\n\r\n", uh_file_mime_lookup(pi->name));

    /* send header */
    if (cl->request.method == UH_HTTP_MSG_HEAD) {
        cl->request_done(cl);
        close(fd);
        return;
    }

    cl->state = CLIENT_STATE_DONE;

    cl->dispatch.file.fd = fd;
    cl->dispatch.write_cb = file_write_cb;
    cl->dispatch.free = uh_file_free;
    file_write_cb(cl);
}

static void uh_file_request(struct uh_client *cl, const char *path, struct path_info *pi)
{
    int fd;

    if (!(pi->stat.st_mode & S_IROTH))
        goto error;

    if (pi->stat.st_mode & S_IFREG) {
        fd = open(pi->phys, O_RDONLY);
        if (fd < 0)
            goto error;

        uh_file_data(cl, pi, fd);
        return;
    }

error:
    cl->send_error(cl, 403, "Forbidden", "You don't have permission to access %s on this server.", path);
}

bool handle_file_request(struct uh_client *cl, const char *path)
{
    struct path_info *pi;

    pi = uh_path_lookup(cl, path);
    if (!pi)
        return false;

    if (pi->redirected)
        return true;

    uh_file_request(cl, path, pi);

    return true;
}

