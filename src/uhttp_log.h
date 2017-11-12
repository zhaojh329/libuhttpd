#ifndef _UHTTP_LOG_H
#define _UHTTP_LOG_H

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>
#include "uhttp_config.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/*
 * Use the syslog output log and include the name and number of rows at the call
 */
#define uh_log(priority, format...) __uh_log(__FILENAME__, __LINE__, priority, format)

#if (UHTTP_DEBUG)
#define uh_log_debug(format...)		uh_log(LOG_DEBUG, format)
#else
#define uh_log_debug(format...)
#endif

#define uh_log_info(format...)		uh_log(LOG_INFO, format)
#define uh_log_err(format...)		uh_log(LOG_ERR, format)

void  __uh_log(const char *filename, int line, int priority, const char *format, ...);

#endif
