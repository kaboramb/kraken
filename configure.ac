#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([kraken], [0.1], [smcintyre@securestate.net])
AM_INIT_AUTOMAKE([kraken], [0.1])
AC_CONFIG_SRCDIR([src/kraken.c])
AC_ARG_WITH([log4c], AS_HELP_STRING([--without-log4c], [do not use log4c]))

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for Python related things.
AM_PATH_PYTHON
AC_ARG_VAR([PYTHON_INCLUDE], [Include flags for python, bypassing python-config])
AC_ARG_VAR([PYTHON_CONFIG], [Path to python-config])
AS_IF([test -z "$PYTHON_INCLUDE"], [
	AS_IF([test -z "$PYTHON_CONFIG"], [
		AC_PATH_PROGS([PYTHON_CONFIG],
			[python$PYTHON_VERSION-config python-config],
			[no],
			[`dirname $PYTHON`])
		AS_IF([test "$PYTHON_CONFIG" = no], [AC_MSG_ERROR([cannot find python-config for $PYTHON.])])
	])
	AC_MSG_CHECKING([python include flags])
	PYTHON_INCLUDE=`$PYTHON_CONFIG --includes`
	AC_MSG_RESULT([$PYTHON_INCLUDE])
])

# Checks for required libraries.
AC_CHECK_LIB([cares], [ares_library_init], [], [
	AC_MSG_NOTICE([could not find the ares library])
	AC_MSG_NOTICE([please install c-ares >= 1.7.0])
	exit 1
])
AC_CHECK_LIB([curl], [curl_easy_init], [], [
	AC_MSG_NOTICE([could not find the curl library])
	AC_MSG_NOTICE([please install libcurl >= 7.19.1])
	exit 1
])
AC_CHECK_LIB([python$PYTHON_VERSION], [Py_Initialize], [], [
	AC_MSG_NOTICE([could not find the python development headers])
	AC_MSG_NOTICE([please install libpython])
	exit 1
])
AC_CHECK_LIB([uriparser], [uriParseUriA], [], [
	AC_MSG_NOTICE([could not find the uriparser library])
	AC_MSG_NOTICE([please install liburiparser])
	exit 1
])
AC_CHECK_LIB([xml2], [xmlDocGetRootElement], [], [
	AC_MSG_NOTICE([could not find the xml2 library])
	AC_MSG_NOTICE([please install libxml2 >= 2.5.0])
	exit 1
])

# Checks libraries for optional features.
AC_CHECK_LIB([cares], [ares_set_servers], [
	AC_MSG_NOTICE([ares_set_servers support has been enabled])
	AC_DEFINE([HAVE_ARES_SET_SERVERS], [1])
], [
	AC_MSG_NOTICE([old ares library detected])
	AC_MSG_NOTICE([ares_set_servers support has been disabled])
])

# Checks for optional libraries.
AS_IF([test "x$with_log4c" != "xno"], [
	AC_CHECK_LIB([log4c], [log4c_init], [], [
		AC_MSG_NOTICE([could not find the log4c library])
		AC_MSG_NOTICE([please install log4c or use the --without-log4c option])
		exit 1
	])
	AC_MSG_NOTICE([log4c support has been enabled])
], [
	AC_MSG_NOTICE([log4c support has been disabled])
	AC_DEFINE([WITHOUT_LOG4C], [1])
])

# Checks for required modules.
PKG_CHECK_MODULES([LIBXML], [libxml-2.0 >= 2.5.0], [], [])
PKG_CHECK_MODULES([GTK], [gtk+-2.0 >= 2.20.0], [], [
	AC_MSG_NOTICE([could not find the gtk library])
	AC_MSG_NOTICE([please install libgtk+-2.0 >= 2.20.0])
	exit 1
])
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.24.0], [
	PKG_CHECK_MODULES([GLIBX], [glib-2.0 >= 2.32.0], [
		AC_MSG_NOTICE([g_thread_init support has been disabled, usage is deprecated])
	], [
		AC_CHECK_LIB([gthread-2.0], [g_thread_init], [
			AC_MSG_NOTICE([g_thread_init support has been enabled])
			AC_DEFINE([HAVE_GTK_G_THREAD_INIT], [1])
		], [
			AC_MSG_NOTICE([g_thread_init support has been disabled, not available])
		])
	])
], [
	AC_MSG_NOTICE([could not find the glib library])
	AC_MSG_NOTICE([please install libglib2.0 >= 2.24.0])
	exit 1
])

# Checks for standard header files.
AC_CHECK_HEADER([assert.h], [], [
	AC_MSG_NOTICE([could not find assert.h])
	exit 1
])
AC_CHECK_HEADER([arpa/inet.h], [], [
	AC_MSG_NOTICE([could not find arpa/inet.h])
	exit 1
])
AC_CHECK_HEADER([netdb.h], [], [
	AC_MSG_NOTICE([could not find netdb.h])
	exit 1
])
AC_CHECK_HEADER([netinet/in.h], [], [
	AC_MSG_NOTICE([could not find netinet/in.h])
	exit 1
])
AC_CHECK_HEADER([pthread.h], [], [
	AC_MSG_NOTICE([could not find pthread.h])
	exit 1
])
AC_CHECK_HEADER([signal.h], [], [
	AC_MSG_NOTICE([could not find signal.h])
	exit 1
])
AC_CHECK_HEADER([stdlib.h], [], [
	AC_MSG_NOTICE([could not find stdlib.h])
	exit 1
])
AC_CHECK_HEADER([string.h], [], [
	AC_MSG_NOTICE([could not find string.h])
	exit 1
])
AC_CHECK_HEADER([sys/socket.h], [], [
	AC_MSG_NOTICE([could not find sys/socket.h])
	exit 1
])
AC_CHECK_HEADER([sys/time.h], [], [
	AC_MSG_NOTICE([could not find sys/time.h])
	exit 1
])
AC_CHECK_HEADER([unistd.h], [], [
	AC_MSG_NOTICE([could not find unistd.h])
	exit 1
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
# AC_CHECK_FUNCS([])

AC_CONFIG_FILES([Makefile src/Makefile data/Makefile])
AC_OUTPUT
