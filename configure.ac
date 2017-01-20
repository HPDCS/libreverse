AC_INIT([libreverse], [1.0], [pellegrini@dis.uniroma1.it])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIRS([m4])
# PKG_CHECK_MODULES([CHECK], [check >= 0.9.10])
AM_PROG_AR
LT_INIT
AM_PROG_AS
AC_PROG_CC
AC_CONFIG_FILES([Makefile src/Makefile])

# Debugging symbols
AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug], [Enable debugging symnbols for the library]))

AS_IF([test "x$enable_debug" = "xyes"],
	[CFLAGS="-g3 -pg -Wall -Wextra -O0 -Wswitch-enum -Wcast-align -Wpointer-arith -Wstrict-overflow=5 -Wstrict-prototypes -Winline -Wundef -Wnested-externs -Wshadow -Wunreachable-code -Wfloat-equal -Wredundant-decls -Wold-style-definition -std=gnu99 -fno-omit-frame-pointer -ffloat-store -fno-common -fstrict-aliasing -fgnu89-inline -rdynamic -lm"])


AC_OUTPUT
