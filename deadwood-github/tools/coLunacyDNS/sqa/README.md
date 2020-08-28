To run tests, on a CentOS 8 system, become root and then 

```
./do.tests
```

# Test coverage

Not every line in `coLunacyDNS.c` is covered by the tests.  There
are a number if `#ifdef GCOV` blocks which hide this code from the tester:

* A test in the IPv6 parser will never be reached, but I have to to keep 
  the IPv6 parser robust.
    
* The code which exits w/o `/dev/random`: I am not going to remove
  `/dev/urandom` system wide for a SQA test.  I *know* this code works;
  it gets invoked when I compile in Windows with the wrong flags.
    
* `rand32()` has a test to make sure we have a RNG state which is never
  run.  I will keep it around so *that* library remains robust (I *could* 
  reach this line by changing the C code to call rand32() *before* 
  init_rng(), but nah)

* We will never reach a block of code which makes an IP `127.0.0.1`

* A couple of tests for bad sockets or bind IPs will never be reached.
  Not “fixing”, I would rather have two checks than zero checks.

