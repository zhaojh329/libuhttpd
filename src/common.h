#ifndef _COMMON_H
#define _COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
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