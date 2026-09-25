#!/bin/sh

SYSTEM=$( uname -a )
for COMPILER in tcc gcc clang ; do
  if command -v $COMPILER > /dev/null 2>&1 ; then
    VERSION=$( $COMPILER --version | head -1 )
    for FLAGS in -g -O -O1 -O2 -O3 ; do
      $COMPILER -std=c99 $FLAGS -o test test.c
      echo -n $SYSTEM ${COMPILER##*/} $VERSION ${FLAGS} ' - '
      ./test | awk -f verify.awk
      rm -f test test.exe
    done
  fi
done
