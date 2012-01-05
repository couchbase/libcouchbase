#!/bin/sh

LIBTOOLIZE_FLAGS="--automake --copy --force"
AUTOMAKE_FLAGS="--add-missing --copy --force --foreign --warning=portability"
ACLOCAL_FLAGS="-I m4"
AUTOHEADER_FLAGS="--warnings=error"
AUTOCONF_CLAGS="--warnings=error --force"


ARGV0=$0
ARGS="$@"

die() { echo "$@"; exit 1; }

run() {
  echo "$ARGV0: running \`$@' $ARGS"
  $@ $ARGS
}

# Try to locate a program by using which, and verify that the file is an
# executable
locate_binary() {
  for f in $@
  do
    file=`which $f 2>/dev/null | grep -v '^no '`
    if test -n "$file" -a -x "$file"; then
      echo $file
      return 0
    fi
  done

  echo ""
  return 1
}

if test -f config/pre_hook.sh
then
  . config/pre_hook.sh
fi

if [ -d .git ]
then
   cat > m4/version.m4 <<EOF
m4_define([VERSION_NUMBER], [`git describe | tr '-' '_'`])
m4_define([GIT_CHANGESET],[`git rev-parse HEAD`])
EOF
fi

# Try to detect the supported binaries if the user didn't
# override that by pushing the environment variable
if test x$LIBTOOLIZE = x; then
  LIBTOOLIZE=`locate_binary libtoolize glibtoolize`
  if test x$LIBTOOLIZE = x; then
    die "Did not find a supported libtoolize"
  fi
fi

if test x$ACLOCAL = x; then
  ACLOCAL=`locate_binary aclocal-1.11 aclocal-1.10 aclocal`
  if test x$ACLOCAL = x; then
    die "Did not find a supported aclocal"
  fi
fi

if test x$AUTOMAKE = x; then
  AUTOMAKE=`locate_binary automake-1.11 automake-1.10 automake`
  if test x$AUTOMAKE = x; then
    die "Did not find a supported automake"
  fi
fi

if test x$AUTOCONF = x; then
  AUTOCONF=`locate_binary autoconf`
  if test x$AUTOCONF = x; then
    die "Did not find a supported autoconf"
  fi
fi

if test x$AUTOHEADER = x; then
  AUTOHEADER=`locate_binary autoheader`
  if test x$AUTOHEADER = x; then
    die "Did not find a supported autoheader"
  fi
fi

run $LIBTOOLIZE $LIBTOOLIZE_FLAGS || die "Can't execute libtoolize"
run $ACLOCAL $ACLOCAL_FLAGS || die "Can't execute aclocal"
run $AUTOHEADER $AUTOHEADER_FLAGS || die "Can't execute autoheader"
run $AUTOMAKE $AUTOMAKE_FLAGS  || die "Can't execute automake"
run $AUTOCONF $AUTOCONF_FLAGS || die "Can't execute autoconf"

if test -f config/post_hook.sh
then
  . config/post_hook.sh
fi

echo "---"
echo "Configured with the following tools:"
echo "  * `$LIBTOOLIZE --version | head -1`"
echo "  * `$ACLOCAL --version | head -1`"
echo "  * `$AUTOHEADER --version | head -1`"
echo "  * `$AUTOMAKE --version | head -1`"
echo "  * `$AUTOCONF --version | head -1`"
echo "---"
