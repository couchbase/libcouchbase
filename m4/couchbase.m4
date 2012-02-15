dnl  Copyright (C) 2011 Couchbase, Inc
dnl This file is free software; Couchbase, Inc
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([COUCHBASE_GENERIC_COMPILER], [
  AC_ARG_ENABLE([warnings],
    [AS_HELP_STRING([--enable-warnings],
            [Enable more compiler warnings. @<:@default=off@:>@])],
    [ac_cv_enable_warnings="yes"],
    [ac_cv_enable_warnings="no"])

  AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror],
            [Treat warnings as errors. @<:@default=off@:>@])],
    [ac_cv_enable_werror="yes"],
    [ac_cv_enable_werror="no"])

  AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
            [Enable debug build (non-optimized). @<:@default=off@:>@])],
    [ac_cv_enable_debug="yes"],
    [ac_cv_enable_debug="no"])

  AC_CACHE_CHECK([whether the C++ compiler works], [ac_cv_prog_cxx_works], [
    AC_LANG_PUSH([C++])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
      [ac_cv_prog_cxx_works=yes],
      [ac_cv_prog_cxx_works=no])
    AC_LANG_POP([C++])])

  C_LANGUAGE_SPEC=c99
  m4_foreach([arg], [$*],
             [
               m4_case(arg, [c89], [C_LANGUAGE_SPEC=c89],
                            [c99], [C_LANGUAGE_SPEC=c99],
                            [cxx], [NEED_CPP=yes])
             ])

  GCC_NO_WERROR="-Wno-error"
  GCC_WERROR="-Werror"
  GCC_C_OPTIMIZE="-O3"
  GCC_CXX_OPTIMIZE="-O3"
  GCC_C_DEBUG="-O0 -g3"
  GCC_CXX_DEBUG="-O0 -g3"
  GCC_VISIBILITY="-DHAVE_VISIBILITY=1 -fvisibility=hidden"
  GCC_CPPFLAGS="-pipe"
  GCC_CFLAGS="-std=gnu99"
  GCC_CXXFLAGS=""
  GCC_C89=-std=c89
  GCC_C99=-std=gnu99
  GCC_LDFLAGS=""
  GCC_CPP_WARNINGS="-Wall -pedantic -Wundef -Wshadow -fdiagnostics-show-option -Wformat -fno-strict-aliasing -Wno-strict-aliasing -Wextra"
  GCC_C_COMPILER_WARNINGS="-Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Wmissing-declarations -Wcast-align"
  GCC_CXX_COMPILER_WARNINGS="-std=gnu++98 -Woverloaded-virtual -Wnon-virtual-dtor -Wctor-dtor-privacy -Wno-long-long -Wno-redundant-decls"

  SPRO_NO_WERROR="-errwarn=%none"
  SPRO_WERROR="-errwarn=%all"
  SPRO_C_OPTIMIZE="-O -xbuiltin=%default"
  SPRO_CXX_OPTIMIZE="-O -xbuiltin=%default"
  SPRO_C_DEBUG="-g3 -traceback=common -xcheck=%all"
  SPRO_CXX_DEBUG="-g3 -traceback=common -xcheck=%all"
  SPRO_VISIBILITY="-xldscope=hidden"
  SPRO_CPPFLAGS="-mt=yes -D_THREAD_SAFE"
  SPRO_CXXFLAGS="-xlang=c99 -compat=5 -library=stlport4 -template=no%extdef"
  SPRO_C89="-Xt -xc99=none"
  SPRO_C99="-D_XOPEN_SOURCE=600 -xc99=all"
  SPRO_CFLAGS=""
  SPRO_CPP_WARNINGS="-errhdr=%user -errfmt=error -errshort=full -errtags "
  SPRO_C_COMPILER_WARNINGS="-v"
  SPRO_CXX_COMPILER_WARNINGS="+w +w2"
  SPRO_LDFLAGS="-mt=yes"

  AC_CHECK_DECL([__SUNPRO_C], [SUNCC="yes"], [SUNCC="no"])
  AC_CHECK_DECL([__GNUC__], [GCC="yes"], [GCC="no"])

  AS_IF([test "x$GCC" = "xyes"],
      [
        AM_CPPFLAGS="$AM_CPPFLAGS $GCC_CPPFLAGS"
        AM_CFLAGS="$AM_CPPFLAGS $GCC_CFLAGS"
        AM_CXXFLAGS="$AM_CPPFLAGS $GCC_CXXFLAGS"
        AS_IF(test "$C_LANGUAGE_SPEC" = c89,
              [AM_CFLAGS="$AM_CPPFLAGS $GCC_C89"],
              AS_IF(test "$C_LANGUAGE_SPEC" = c99,
                    [AM_CFLAGS="$AM_CPPFLAGS $GCC_C99"])
             )
        AM_LDFLAGS="$AM_LDFLAGS $GCC_LDFLAGS"
        NO_WERROR="$GCC_NO_WERROR"
        WERROR="$GCC_WERROR"
        C_OPTIMIZE="$GCC_C_OPTIMIZE"
        CXX_OPTIMIZE="$GCC_CXX_OPTIMIZE"
        C_DEBUG="$GCC_C_DEBUG"
        CXX_DEBUG="$GCC_CXX_DEBUG"
        VISIBILITY="$GCC_VISIBILITY"
        CPP_WARNINGS="$GCC_CPP_WARNINGS"
        C_COMPILER_WARNINGS="$GCC_C_COMPILER_WARNINGS"
        CXX_COMPILER_WARNINGS="$GCC_CXX_COMPILER_WARNINGS"
      ])

  AS_IF([test "x$SUNCC" = "xyes"],
      [
        AM_CPPFLAGS="$AM_CPPFLAGS $SPRO_CPPFLAGS"
        AM_CFLAGS="$AM_CPPFLAGS $SPRO_CFLAGS"
        AM_CXXFLAGS="$AM_CPPFLAGS $SPRO_CXXFLAGS"
        AS_IF(test "$C_LANGUAGE_SPEC" = c89,
              [AM_CFLAGS="$AM_CPPFLAGS $SPRO_C89"],
              AS_IF(test "$C_LANGUAGE_SPEC" = c99,
                    [AM_CFLAGS="$AM_CPPFLAGS $SPRO_C99"])
             )
        AM_LDFLAGS="$AM_LDFLAGS $SPRO_LDFLAGS"
        NO_WERROR="$SPRO_NO_WERROR"
        WERROR="$SPRO_WERROR"
        C_OPTIMIZE="$SPRO_C_OPTIMIZE"
        CXX_OPTIMIZE="$SPRO_CXX_OPTIMIZE"
        C_DEBUG="$SPRO_C_DEBUG"
        CXX_DEBUG="$SPRO_CXX_DEBUG"
        VISIBILITY="$SPRO_VISIBILITY"
        CPP_WARNINGS="$SPRO_CPP_WARNINGS"
        C_COMPILER_WARNINGS="$SPRO_C_COMPILER_WARNINGS"
        CXX_COMPILER_WARNINGS="$SPRO_CXX_COMPILER_WARNINGS"
      ])

  AM_CPPFLAGS="$AM_CPPFLAGS -I\${top_srcdir}/include $VISIBILITY"
  AM_LDFLAGS="$AM_LDFLAGS $VISIBILITY"


  AS_IF([test "$ac_cv_enable_warnings" = "yes"],
        [AM_CPPFLAGS="$AM_CPPFLAGS $CPP_WARNINGS"
         AM_CFLAGS="$AM_CFLAGS $C_COMPILER_WARNINGS"
         AM_CXXFLAGS="$AM_CXXFLAGS $CXX_COMPILER_WARNINGS"])

  AS_IF([test "$ac_cv_enable_werror" = "yes"],
        [
           AM_CPPFLAGS="$AM_CPPFLAGS $WERROR"
        ])

  AS_IF([test "$ac_cv_enable_debug" = "yes"],
        [
           AM_CFLAGS="$AM_CFLAGS $C_DEBUG"
           AM_CXXFLAGS="$AM_CXXFLAGS $CXX_DEBUG"
        ],
        [
           AM_CFLAGS="$AM_CFLAGS $C_OPTIMIZE"
           AM_CXXFLAGS="$AM_CXXFLAGS $CXX_OPTIMIZE"
        ])

  dnl Export GCC variables
  AC_SUBST(GCC_NO_WERROR)
  AC_SUBST(GCC_WERROR)
  AC_SUBST(GCC_C_OPTIMIZE)
  AC_SUBST(GCC_CXX_OPTIMIZE)
  AC_SUBST(GCC_C_DEBUG)
  AC_SUBST(GCC_CXX_DEBUG)
  AC_SUBST(GCC_VISIBILITY)
  AC_SUBST(GCC_CPPFLAGS)
  AC_SUBST(GCC_CPP_WARNINGS)
  AC_SUBST(GCC_C_COMPILER_WARNINGS)
  AC_SUBST(GCC_CXX_COMPILER_WARNINGS)

  dnl Export Sun Studio variables
  AC_SUBST(SPRO_NO_WERROR)
  AC_SUBST(SPRO_WERROR)
  AC_SUBST(SPRO_C_OPTIMIZE)
  AC_SUBST(SPRO_CXX_OPTIMIZE)
  AC_SUBST(SPRO_C_DEBUG)
  AC_SUBST(SPRO_CXX_DEBUG)
  AC_SUBST(SPRO_VISIBILITY)
  AC_SUBST(SPRO_CPPFLAGS)
  AC_SUBST(SPRO_CPP_WARNINGS)
  AC_SUBST(SPRO_C_COMPILER_WARNINGS)
  AC_SUBST(SPRO_CXX_COMPILER_WARNINGS)

  dnl Export the ones we're using
  AC_SUBST(NO_WERROR)
  AC_SUBST(WERROR)
  AC_SUBST(C_OPTIMIZE)
  AC_SUBST(CXX_OPTIMIZE)
  AC_SUBST(C_DEBUG)
  AC_SUBST(CXX_DEBUG)
  AC_SUBST(VISIBILITY)
  AC_SUBST(CPP_WARNINGS)
  AC_SUBST(C_COMPILER_WARNINGS)
  AC_SUBST(CXX_COMPILER_WARNINGS)
  AC_SUBST(AM_LDFLAGS)
  AC_SUBST(AM_CPPFLAGS)
  AC_SUBST(AM_CFLAGS)
  AC_SUBST(AM_CXXFLAGS)
])
