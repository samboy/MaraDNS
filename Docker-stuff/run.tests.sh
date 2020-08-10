#!/bin/sh
# This script is run inside of the Docker image to run the tests
# The script "do.osot.tests" called here is in the directory
# tools/OneSourceOfTruth (off of the top-level directory in the 
# MaraDNS Git repo)
cd /tmp
./do.osot.tests
