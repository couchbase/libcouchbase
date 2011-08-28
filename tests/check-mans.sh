#! /bin/sh
MANPATH=`pwd`/man
export MANPATH

exitcode=0
check_manpage() {
  man -s$1 $2 > /dev/null 2>&1
   if [ $? -ne 0 ]
   then
      echo "Missing: $2($1)" >&2
      exitcode=1
   fi
}

check_manpage 3lib libcouchbase
check_manpage 3head couchbase
check_manpage 3head couchbase.h

libname=
for f in .libs/libcouchbase.so .libs/libcouchbase.dylib
do
  if [ -f $f ]
  then
    libname=$f
  fi
done

if [ "x$libname" = "x" ]
then
  echo "Could not locate library"
  exit 0
fi

for f in `nm -P $libname | grep ' T ' | egrep -v '_init|_fini' | cut -f 1 -d\ `
do
   check_manpage 3couchbase $f
done

exit $exitcode
