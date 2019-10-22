  
#!/bin/sh

# Set the language for various messages to English

cd server
rm MaraBigHash_locale.h
ln -s MaraBigHash_ru.h MaraBigHash_locale.h
rm MaraDNS_locale.h
ln -s MaraDNS_ru.h MaraDNS_locale.h
cd ../tcp
rm getzone_locale.h
ln -s getzone_ru.h getzone_locale.h
