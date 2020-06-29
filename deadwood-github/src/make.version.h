#!/bin/sh

# Make the version.h file based on the directory name for Deadwood

# If we are a 3.5 release, use that to determine the version number
if pwd | awk -F/ '{print $(NF - 1)}' | awk -F- '{print $2}
                ' | grep 3.5 > /dev/null ; then
        pwd | awk -F/ '{print $(NF - 1)}' | awk -F- '
                {print "#define VERSION \"" $2 "\""}' > version.h
        exit 0
fi

# Otherwise, pull the version number from the git log
if git log -1 > git.commit ; then
        head -1 git.commit | awk '
                {print "#define VERSION \"git-" substr($NF,1,10) "\""}
                ' > version.h
        exit 0
fi

# This code was used by 3.4 and earlier releases; use it as a fallback
# just in case we trigger the code.  We use the bogus version number
# 3.4.99 when testing for bugs.
pwd | awk -F/ '{print $(NF - 1)}' | \
                awk -F- '{
                if($2 == "H" || $2 == "S" || $2 == "Q") {
                print "#define VERSION \""$(NF-3)"-"$(NF-2)"-"$(NF-1)"-"$NF"\""
                } else {
                        print "#define VERSION \""$NF"\""
                        } }' > version.h
