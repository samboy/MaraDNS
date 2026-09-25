# Using uninitialized memory

In the first 2000s decade, cryptographic code would use allocated but
uninitialized memory as a source of entropy.  OpenSSL did this; MaraDNS
did this.  In MaraDNS 3.5.0039, this practice was stopped, since the C99
specification says using uninitialized memory results in undefined, and
since one person claimed some compilers “optimize out” code which uses
uninitialized memory, not running said code.

The claims are from social media, and, as such, are unverified.

# What this test does

This test makes sure that there does not exist in the real world a known
compiler which will “optimize out” and not run code which relies on 
uninitialized memory.  Should such a compiler ever be found (in said
social media posts, one claimed the as of September 2026 “latest version 
of clang on godbolt” optimizes out the use of uninitialized memory), I
will add a security report that versions of MaraDNS before 3.5.0039
used uninitialized memory as entropy, something which results in the
entire entropy using code potentially being disabled.

Until I find such a compiler, I will not make a security report.
