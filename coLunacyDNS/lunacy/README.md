# What this is

This is a security hardened fork of Lua 5.1.  Yes, this is patched
against CVE-2014-5461.  It also has other security hardening.

As an extension to Lua 5.1, it has support for bit32 to perform bit
operations on numbers.  It also *optionally* has support for lfs (so
one can list files in a directory) and spawner (for opening two-way
pipes with a child process).

This is similar to Lunacy, available here:

>[https://github.com/samboy/lunacy](https://github.com/samboy/lunacy)

However, it has slightly deviated from Lunacy:

* All makefiles force `-std=c99` compile-time flag, as per MaraDNS 
  coding guidelines (for the simple practical reason this minimizes
  the chance a change to the C standard will cause programs to not
  compile again, they way they did with the C23 changes)
* By default, lfs and spawner are disabled

# Choose your Makefile

* Makefile.leaner: No spawner, no LFS, no editline/readline ever
* Makefile.default: No spawner, no LFS, “make linux” for editline
* Makefile: Same as Makefile.default
* Makefile.full: Yes Spawner, yes LFS, “make linux” for editline
* Makefile.win32tcc: This is for an old version of TCC only; ignore otherwise

# Default Makefile

Makefile.leaner is the Makefile that is used when using the “Makefile”
one directory up in the coLunacyDNS directory.

# Make your own Lunacy

```
make -f Makefile.full
```

Is pretty easy to compile anywhere.

If one wants arrow history, in ../../webpage/lunacy there is a file
called `editline-2.0.0.tar.xz`.  Compile and install that, then:

```
make -f Makefile.full linux
```

(The reason for editline instead of readline is to avoid GPL code)

