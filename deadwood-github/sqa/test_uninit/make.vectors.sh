#!/bin/sh

gcc -std=c99 -o nanorg32 nanorg32.c
for Z in @ A B C D E F G H I J K L M N O P Q R S T U V W X Y Z '[' '\' ']' _ 
do
  ./nanorg32 "$Z" | awk '
    {print "a[\"" substr($0,0,16) "\"] = \"\'$Z'\""}' 2> /dev/null
done

rm -f nanorg32 nanorg32.exe
