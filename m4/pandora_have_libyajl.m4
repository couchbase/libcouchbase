dnl  Copyright (C) 2010 NorthScale
dnl This file is free software; NorthScale
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([_PANDORA_SEARCH_LIBYAJL],[
  AC_REQUIRE([AC_LIB_PREFIX])

  dnl --------------------------------------------------------------------
  dnl  Check for libyajl
  dnl --------------------------------------------------------------------

  AC_ARG_ENABLE([libyajl],
    [AS_HELP_STRING([--disable-libyajl],
      [Build with libyajl support @<:@default=on@:>@])],
    [ac_enable_libyajl="$enableval"],
    [ac_enable_libyajl="yes"])

  AS_IF([test "x$ac_enable_libyajl" = "xyes"],[
    AC_LIB_HAVE_LINKFLAGS(yajl,,[
      #include <yajl/yajl_parse.h>
    ],[
      yajl_handle parser = yajl_alloc(0, 0, 0, 0);
    ])
  ],[
    ac_cv_libyajl="no"
  ])

  AM_CONDITIONAL(HAVE_LIBYAJL, [test "x${ac_cv_libyajl}" = "xyes"])
])

AC_DEFUN([PANDORA_HAVE_LIBYAJL],[
  AC_REQUIRE([_PANDORA_SEARCH_LIBYAJL])
])
