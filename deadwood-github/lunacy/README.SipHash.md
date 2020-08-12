# SipHash

Lunacy, by default, uses HalfSipHash-1-3 as its hash compression
algorithm.  This has reasonable security, while being very fast
when Lunacy is compiled as a 32-bit or 64-bit binary.

To instead compile Lunacy to use 64-bit SipHash-1-3, edit 
`src/Makefile` to add the flag `-DFullSipHash`, e.g.:

```
CFLAGS= -O3 -Wall $(MYCFLAGS) -DFullSipHash
```

To use 64 bit SipHash-2-4, likewise add `-DSIP24`:

```
CFLAGS= -O3 -Wall $(MYCFLAGS) -DFullSipHash -DSIP24
```

## Why HalfSipHash-1-3 is the default

I have run a number of benchmarks with Lunacy, my fork of Lua 5.1,
to see how much changing the SipHash variant used affects performance,
for both 32-bit (386) and 64-bit (x86_64) binaries.

Conclusion: I will use HalfSipHash31 as the hash compression algorithm,
for both 32-bit and 64-bit builds of Lunacy.

The binaries have been compiled using GCC 8.3.1, in CentOS 8, using an
older Core Duo T8100 chip from 2008.  The benchmark consisted of loading
and processing a bunch of COVID-19 data in to large tables taking up
550 (32-bit) or 750 megs (64-bit) of memory.  This real-world benchmark
(it is the exact same code I use to build an entire COVID-19 tracking
website) was done multiple times, to minimize speed fluctuations from
outside factors, against the following setups:

* “Lunacy32”, which is a 32-bit compile of Luancy
* “Lunacy64”, a 64-bit compile of same

And the following string hash compression functions:

* “noSipHash”: Lua’s default hash compressor
* “SipHash24”: 64-bit SipHash with 2 rounds during input processing,
  followed by 4 rounds after input ends.
* “SipHash13”: 64-bit SipHash with 1 round during input processing,
  followed by 3 rounds after input ends.
* “SipHalf13”: 32-bit HalfSipHash with 1 round during input
  processing, followed by 3 rounds after input ends.

Here are the results, where lower numbers are better (less time needed
to run the benchmark):

```
lunacy64-noSipHash 197.801
lunacy64-sipHash13 203.457
lunacy64-SipHalf13 203.507
lunacy64-sipHash24 210.043
lunacy32-noSipHash 240.898
lunacy32-SipHalf13 246.995
lunacy32-sipHash13 265.916
lunacy32-sipHash24 270.226
```

HalfSipHash-1-3 is as fast as full SipHash-1-3 on 64-bit CPUs, while
being quite a bit faster for 32-bit binaries compared to 64-bit sipHash.

HalfSipHash-1-3 is only 2.5% slower on 32-bit machines (compared to
Lua’s  “stock” hash); it is only 2.9% slower on 64-bit machines.

In Lunacy’s use case, HalfSipHash should provide an adequate security margin;
as per [what its designer has to 
say](http://lkml.iu.edu/hypermail/linux/kernel/1612.2/01666.html):

>HalfSipHash takes its core function from Chaskey and uses the same
>construction as SipHash, so it *should* be secure. Nonetheless it hasn't
>received the same amount of attention as 64-bit SipHash did. So I'm less
>confident about its security than about SipHash's, but it obviously inspires
>a lot more confidence than non-crypto hashes.
>
>Too, HalfSipHash only has a 64-bit key, not a 128-bit key like SipHash, so
>only use this as a mitigation for hash-flooding attacks, where the output of
>the hash function is never directly shown to the caller.

