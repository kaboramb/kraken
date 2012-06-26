#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([kraken], [0.1], [smcintyre@securestate.net])
AM_INIT_AUTOMAKE([kraken], [0.1])
AC_CONFIG_SRCDIR([src/kraken.c])
AC_ARG_WITH([log4c], AS_HELP_STRING([--without-log4c], [Build without logging capabilities]))

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for required libraries.
AC_CHECK_LIB([cares], [ares_library_init])
AC_CHECK_LIB([curl], [curl_easy_init])
AC_CHECK_LIB([uriparser], [uriParseUriA])
AC_CHECK_LIB([xml2], [xmlDocGetRootElement])

# Checks for optional libraries.
AS_IF([test "x$with_log4c" != "xno"], [
	AC_MSG_NOTICE([log4c support has been enabled])
	AC_CHECK_LIB([log4c], [log4c_init])
], [
	AC_MSG_NOTICE([log4c support has been disabled])
	AC_DEFINE([WITHOUT_LOG4C], [1])
])


# Checks for required modules.
PKG_CHECK_MODULES(LIBXML, libxml-2.0 >= 2.5.0, [HAVE_LIBXML2=1], [HAVE_LIBXML2=0])
PKG_CHECK_MODULES(GTK, gtk+-2.0 >= 2.24.8, [HAVE_LIBGTK2=1], [HAVE_LIBGTK2=0])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname memmove memset select socket strchr strncasecmp strstr])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
