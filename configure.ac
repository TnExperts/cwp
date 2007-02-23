dnl Package informations
AC_PREREQ([2.50])
AC_INIT([CWP], [1.0], [b.gaillard@powercode.net], [cwp])
AM_INIT_AUTOMAKE([1.4 foreign dist-bzip2 no-define -Wall])
AC_CONFIG_SRCDIR([wrapper/iptables.c])
AC_CONFIG_HEADER([config.h])

dnl Language
AC_LANG([C])

dnl Checks for programs
AC_PROG_CC

dnl Checks for headers
AC_HEADER_STDC
dnl AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

dnl Check compiler support for const
AC_C_CONST

dnl Checks for iptables and PHP paths
AC_PATH_PROG([ip6tables], [ip6tables], [/bin/false],
	     [/usr/sbin:/sbin:$PATH:/usr/local/sbin])
AC_PATH_PROG([ip4tables], [iptables],  [/bin/false],
	     [/usr/sbin:/sbin:$PATH:/usr/local/sbin])
AC_PATH_PROG([ebtables],  [ebtables],  [/bin/false],
	     [/usr/sbin:/sbin:$PATH:/usr/local/sbin])
AC_PATH_PROG([php],       [php],       [/bin/false],
	     [/usr/bin:/bin:$PATH:/usr/local/bin])

dnl Tables prefix
AC_ARG_WITH(
    [tables-prefix],
    [AS_HELP_STRING([--with-tables-prefix=prefix],
		    [Prepend 'prefix' to tables names @<:@default=cwp_@:>@])],
    [], [with_tables_prefix=cwp_]
)

AC_SUBST([IP6TABLES_PATH], ["$ip6tables"])
AC_SUBST([IP4TABLES_PATH], ["$ip4tables"])
AC_SUBST([EBTABLES_PATH],  ["$ebtables"])
AC_SUBST([PHP_PATH],       ["$php"])
AC_SUBST([TABLES_PREFIX],  ["$with_tables_prefix"])

AC_DEFINE_UNQUOTED([IP6TABLES_PATH], ["$IP6TABLES_PATH"],
		   [The ip6tables executable full path])
AC_DEFINE_UNQUOTED([IP4TABLES_PATH], ["$IP4TABLES_PATH"],
		   [The iptables executable full path])
AC_DEFINE_UNQUOTED([EBTABLES_PATH],  ["$EBTABLES_PATH"],
		   [The ebtables executable full path])
AC_DEFINE_UNQUOTED([TABLES_PREFIX],  ["$TABLES_PREFIX"],
		   [The tables names prefix])

dnl Enable GCC warnings
if test "x$GCC" = xyes; then
    CFLAGS="-ansi -pedantic -Wall -W $CFLAGS"
fi

dnl Makefiles
AC_CONFIG_FILES(
    [Makefile]
    [etc/Makefile]
    [htdocs/Makefile]
    [php/Makefile]
    [php/dirs.php]
    [wrapper/Makefile]
)

dnl Create files
AC_OUTPUT
