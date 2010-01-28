
AC_INIT([pam_combo],[0.1],[wfp5p@virginia.edu])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([pam_combo.c])
AC_CANONICAL_TARGET([])
AM_DISABLE_STATIC
AM_INIT_AUTOMAKE(pam_combo, 0.1)
AM_PROG_LIBTOOL
dnl AC_SUBST(LIBTOOL_DEPS)

dnl Checks for header files.

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(stdlib.h string.h)

AC_CHECK_HEADERS([security/pam_appl.h], [],
  [AC_MSG_ERROR([[PAM header files not found, install libpam-dev.]])])
AC_CHECK_HEADERS([security/pam_modules.h security/_pam_macros.h], [], [],
  [#include <security/pam_appl.h>])

AC_SUBST(PAMDIR, "\$(exec_prefix)/lib/security")
AC_ARG_WITH(pam-dir,
  AC_HELP_STRING([--with-pam-dir=DIR],
                 [Where to install PAM module [[PREFIX/lib/security]]]),
            [case "${withval}" in
            /*) PAMDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
            *)  PAMDIR="\$(exec_prefix)/lib/${withval}";;
            esac])
AC_MSG_NOTICE([PAM installation path $PAMDIR])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T

dnl Checks for library functions.
AC_CHECK_FUNCS(memset)

AC_CONFIG_FILES([Makefile])
dnl AC_SUBST(LTLIBOBJS)
AC_OUTPUT
