#!/bin/sh

# Set the language for some translated messages to Spanish
cd server
rm MaraBigHash_locale.h
ln -s MaraBigHash_es.h MaraBigHash_locale.h
cd ../tcp
rm getzone_locale.h
ln -s getzone_es.h getzone_locale.h
