#!/bin/bash

VERSION=$( pwd )
VERSION=${VERSION%%/build/win32}
VERSION=${VERSION##*/}
VERSION=$( echo $VERSION | sed 's/\./\-/g' )
echo $VERSION
mkdir $VERSION
cp mararc readme.txt run_maradns.bat pthreads.txt $VERSION
cp ../../server/maradns.exe $VERSION
cp ../../tools/askmara.exe $VERSION
cp ../../doc/en/tutorial/man.askmara.html $VERSION/Askmara.html
cp ../../doc/en/tutorial/win_service.html $VERSION/Service.html
cp ../../../pthreadGC2.dll $VERSION
zip -r $VERSION\-win32.zip $VERSION
