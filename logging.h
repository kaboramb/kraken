/*
 * Acceptable Log Levels For Log4C:
 *     fatal:    LOG4C_PRIORITY_FATAL
 *     alert:    LOG4C_PRIORITY_ALERT
 *     critical: LOG4C_PRIORITY_CRIT
 *     error:    LOG4C_PRIORITY_ERROR
 *     warning:  LOG4C_PRIORITY_WARN
 *     notice:   LOG4C_PRIORITY_NOTICE
 *     info:     LOG4C_PRIORITY_INFO
 *     debug:    LOG4C_PRIORITY_DEBUG
 *     trace:    LOG4C_PRIORITY_TRACE
 *     notset:   LOG4C_PRIORITY_NOTSET
 *     unknown:  LOG4C_PRIORITY_UNKNOWN
 */

#ifndef _KRAKEN_LOGGING_H
#define _KRAKEN_LOGGING_H

#ifndef WITHOUT_LOG4C

#include <log4c.h>
#define LOGGING_FATAL LOG4C_PRIORITY_FATAL
#define LOGGING_ALERT LOG4C_PRIORITY_ALERT
#define LOGGING_CRITICAL LOG4C_PRIORITY_CRIT
#define LOGGING_ERROR LOG4C_PRIORITY_ERROR
#define LOGGING_WARNING LOG4C_PRIORITY_WARN
#define LOGGING_NOTICE LOG4C_PRIORITY_NOTICE
#define LOGGING_INFO LOG4C_PRIORITY_INFO
#define LOGGING_DEBUG LOG4C_PRIORITY_DEBUG
#define LOGGING_TRACE LOG4C_PRIORITY_TRACE
#define LOGGING_NOTSET LOG4C_PRIORITY_NOTSET
#define LOGGING_UNKNOWN LOG4C_PRIORITY_UNKNOWN

#define LOGGING_QUICK(catName, priority, msg) log4c_category_log(log4c_category_get(catName), priority, msg);
#define LOGGING_QUICK_FATAL(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_FATAL, msg);
#define LOGGING_QUICK_ALERT(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_ALERT, msg);
#define LOGGING_QUICK_CRITICAL(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_CRIT, msg);
#define LOGGING_QUICK_ERROR(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_ERROR, msg);
#define LOGGING_QUICK_WARNING(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_WARN, msg);
#define LOGGING_QUICK_NOTICE(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_NOTICE, msg);
#define LOGGING_QUICK_INFO(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_INFO, msg);
#define LOGGING_QUICK_DEBUG(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_DEBUG, msg);
#define LOGGING_QUICK_TRACE(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_TRACE, msg);
#define LOGGING_QUICK_NOTSET(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_NOTSET, msg);
#define LOGGING_QUICK_UNKNOWN(catName, msg) log4c_category_log(log4c_category_get(catName), LOG4C_PRIORITY_UNKNOWN, msg);

#else

#define LOGGING_FATAL 0
#define LOGGING_ALERT 0
#define LOGGING_CRITICAL 0
#define LOGGING_ERROR 0
#define LOGGING_WARNING 0
#define LOGGING_NOTICE 0
#define LOGGING_INFO 0
#define LOGGING_DEBUG 0
#define LOGGING_TRACE 0
#define LOGGING_NOTSET 0
#define LOGGING_UNKNOWN 0

#define LOGGING_QUICK(catName, priority, msg) ((void) 0);
#define LOGGING_QUICK_FATAL(catName, msg) ((void) 0);
#define LOGGING_QUICK_ALERT(catName, msg) ((void) 0);
#define LOGGING_QUICK_CRITICAL(catName, msg) ((void) 0);
#define LOGGING_QUICK_ERROR(catName, msg) ((void) 0);
#define LOGGING_QUICK_WARNING(catName, msg) ((void) 0);
#define LOGGING_QUICK_NOTICE(catName, msg) ((void) 0);
#define LOGGING_QUICK_INFO(catName, msg) ((void) 0);
#define LOGGING_QUICK_DEBUG(catName, msg) ((void) 0);
#define LOGGING_QUICK_TRACE(catName, msg) ((void) 0);
#define LOGGING_QUICK_NOTSET(catName, msg) ((void) 0);
#define LOGGING_QUICK_UNKNOWN(catName, msg) ((void) 0);

#endif

void logging_log(const char *catName, const int priority, const char *format, ...);

#endif
