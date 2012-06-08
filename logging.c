#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "logging.h"

void logging_log(const char *catName, const int priority, const char *format, ...) {
#ifndef WITHOUT_LOG4C
	va_list args;
	va_start(args, format);
	log4c_category_vlog(log4c_category_get(catName), priority, format, args);
	va_end(args);
#endif
	return;
}
