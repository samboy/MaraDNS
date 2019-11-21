# What this is

There are tests I run before making a new MaraDNS release.

# Where I run the tests

I run the tests in CentOS 7.

# How to run the tests

Compile MaraDNS as an authoritative-only nameserver:

```
./configure --ipv6
make
```

Become root.

Then run the script `sh ./do.tests` in this directory.

# Original README

This directory contains various tests, mainly ones that detect the 
presence of known MaraDNS bugs that have been fixed.

All of these tests can be run at once by typing in `sh ./do.tests` as
root from this directory after compiling MaraDNS.

These tests can also be run by typing in `sh ./do.test` in the appropriate
directory for the test in question.  MaraDNS needs to be compiled before
these tests can be run.

Note that you must be root to run these tests, since they start up maradns
and what not.  Note also that these tests can be run on a computer not
connected to the internet.  
