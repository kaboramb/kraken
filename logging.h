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
