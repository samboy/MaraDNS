#!/bin/sh

rm -f reference.md
touch reference.md

for a in $( ls *md | grep -v mqhash | grep -v reference ) ; do
	echo \# ${a%%.md} >> reference.md
	echo >> reference.md
	cat $a | awk '{gsub(/^## /,"### ");
	gsub(/^# /,"## ");print}' >> reference.md
done
