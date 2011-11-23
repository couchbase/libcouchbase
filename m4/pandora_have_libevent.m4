dnl  Copyright (C) 2009 Sun Microsystems
dnl This file is free software; Sun Microsystems
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

#--------------------------------------------------------------------
# Check for libevent
#--------------------------------------------------------------------


AC_DEFUN([_PANDORA_SEARCH_LIBEVENT],[
  AC_REQUIRE([AC_LIB_PREFIX])

  AC_LIB_HAVE_LINKFLAGS(event,,
  [
    #include <sys/types.h>
    #include <sys/time.h>
    #include <stdlib.h>
    #include <event.h>
  ],[
    struct bufferevent bev;

    bufferevent_settimeout(&bev, 1, 1);
    event_init();
    event_loop(EVLOOP_ONCE);
  ])

  AM_CONDITIONAL(HAVE_LIBEVENT, [test "x${ac_cv_libevent}" = "xyes"])

  AS_IF([test "x${ac_cv_libevent}" = "xyes"],[
    save_LIBS="${LIBS}"
    LIBS="${LIBS} ${LTLIBEVENT}"
    AC_CHECK_FUNCS(event_base_new)
    AC_CHECK_FUNCS(event_base_free)
    AC_CHECK_FUNCS(event_base_get_method)
    AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([
        #include <stdlib.h>
        #include <event.h>
        #include <event2/http.h>
      ],[
        struct bufferevent bev;
        struct evbuffer* buf;
        buf = evbuffer_new();
        evbuffer_add_printf(buf, "foo");
        bufferevent_settimeout(&bev, 1, 1);
        evhttp_request_new(NULL, NULL);
        event_init();
        event_loop(EVLOOP_ONCE);
      ])],
      [
        ac_cv_libevent2=yes
        AC_DEFINE([HAVE_LIBEVENT2], [1], [Define if you have the libevent2])
      ],
      [ac_cv_libevent2=no]
    )
    AM_CONDITIONAL(HAVE_LIBEVENT2, [test "x${ac_cv_libevent2}" = "xyes"])
    LIBS="$save_LIBS"
  ])
])

AC_DEFUN([_PANDORA_HAVE_LIBEVENT],[

  AC_ARG_ENABLE([libevent],
    [AS_HELP_STRING([--disable-libevent],
      [Build with libevent support @<:@default=on@:>@])],
    [ac_enable_libevent="$enableval"],
    [ac_enable_libevent="yes"])

  _PANDORA_SEARCH_LIBEVENT
])


AC_DEFUN([PANDORA_HAVE_LIBEVENT],[
  AC_REQUIRE([_PANDORA_HAVE_LIBEVENT])
])

AC_DEFUN([_PANDORA_REQUIRE_LIBEVENT],[
  ac_enable_libevent="yes"
  _PANDORA_SEARCH_LIBEVENT

  AS_IF([test x$ac_cv_libevent = xno],[
    AC_MSG_ERROR([libevent is required for ${PACKAGE}.])
  ])
])

AC_DEFUN([PANDORA_REQUIRE_LIBEVENT],[
  AC_REQUIRE([_PANDORA_REQUIRE_LIBEVENT])
])
