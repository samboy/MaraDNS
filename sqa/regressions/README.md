# What this is

There are tests I run before making a new MaraDNS release.

# Where I run the tests

I run the tests in CentOS 7.

# How to run the tests

Compile MaraDNS as an authoritative-only nameserver:

```
./configure --authonly
make
```

Become root.

Then run the script `./do.tests` in this directory.
