#!/bin/sh

rm -f reference.md
touch reference.md

echo \# MaraDNS reference manual > reference.md
echo >> reference.md
echo This is a reference manual with all of MaraDNS\' >> reference.md
echo manual pages >> reference.md
echo >> reference.md
echo The following manuals are here: >> reference.md
for a in $( ls *md | grep -v mqhash | grep -v reference ) ; do
	echo '* '${a%%.md} man page >> reference.md
done
echo >> reference.md

for a in $( ls *md | grep -v mqhash | grep -v reference ) ; do
	echo \# ${a%%.md} man page >> reference.md
	echo >> reference.md
	cat $a | awk '{
        if(/\<[Pp][Rr][Ee]\>/){inpre=1}
        if(/\<\/[Pp][Rr][Ee]\>/){inpre=0}
        if(inpre == 1) {
          gsub(/^## /,"### ")
	  gsub(/^# /,"## ")
        }print}' >> reference.md
done
