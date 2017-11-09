#include "uhttp_log.h"

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

#ifdef UH_DEBUG
	fprintf(stderr, "%s\n", buf);
#endif
}

