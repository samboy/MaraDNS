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

