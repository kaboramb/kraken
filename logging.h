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

#define LOGGING_STR_LEN 255

#ifndef WITHOUT_LOG4C

#include <log4c.h>
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

#define LOGGING_QUICK(catName, priority, msg)
#define LOGGING_QUICK_FATAL(catName, msg)
#define LOGGING_QUICK_ALERT(catName, msg)
#define LOGGING_QUICK_CRITICAL(catName, msg)
#define LOGGING_QUICK_ERROR(catName, msg)
#define LOGGING_QUICK_WARNING(catName, msg)
#define LOGGING_QUICK_NOTICE(catName, msg)
#define LOGGING_QUICK_INFO(catName, msg)
#define LOGGING_QUICK_DEBUG(catName, msg)
#define LOGGING_QUICK_TRACE(catName, msg)
#define LOGGING_QUICK_NOTSET(catName, msg)
#define LOGGING_QUICK_UNKNOWN(catName, msg)

#endif

#endif
