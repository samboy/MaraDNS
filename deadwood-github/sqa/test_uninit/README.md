# Using uninitialized memory

In the first 2000s decade, cryptographic code would use allocated but
uninitialized memory as a source of entropy.  OpenSSL did this; MaraDNS
did this.  In MaraDNS 3.5.0039, this practice was stopped, since the C99
specification says using uninitialized memory results in undefined
behavior, and since one person claimed some compilers “optimize out” code 
which uses uninitialized memory, not running said code.

The claims are from social media, and, as such, are unverified.

# What this test does

This test makes sure that there does not exist in the real world a known
compiler which will “optimize out” and not run code which relies on
uninitialized memory.  Should such a compiler ever be found (in said
social media posts, one claimed the as of September 2026 “latest version
of clang on godbolt” optimizes out the use of uninitialized memory,
but I was unable to reproduce the issue with this test using a newer
version of clang than the one on godbolt.org at the time this social media
post was made), I will add a security report that versions of MaraDNS
before 3.5.0039 used uninitialized memory as entropy, something which
results in the entire entropy using code potentially being disabled.

Until I find such a compiler, I will not make a security report.

# Files here

* README.md: This file
* do.test.sh: The script which runs the tests at various optimization levels
  with gcc, tcc, and clang
* make.vectors.sh: This code was used to make the known secure vectors in
  verify.awk
* nanorg32.c: This is used with make.vectors.sh to make the vectors
* outputs.txt: This test run on various systems and compilers
* test.c: The code test which runs RadioGatún[32] against uninitialized
  memory
* verify.awk: An AWK script which makes sure the output of compiled test.c
  ran the RadioGatún[32] code

# Other notes

The code test.c will output the first 64 bits in hex of the RadioGatún[32]
sum of a one-character long stream.  That one character can have one of 
32 values: @ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ (that \ is a literal backslash).


