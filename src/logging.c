#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "logging.h"

#ifndef WITHOUT_LOG4C

#include <log4c.h>

#endif

void logging_log(const char *catName, const int priority, const char *format, ...) {
#ifndef WITHOUT_LOG4C
	const log4c_category_t *category = log4c_category_get(catName);
	if (log4c_category_is_priority_enabled(category, priority)) {
		va_list args;
		va_start(args, format);
		log4c_category_vlog(category, priority, format, args);
		va_end(args);
	}
#endif
	return;
}
