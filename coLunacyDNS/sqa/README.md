To run tests, on a CentOS 8 system, become root and then 

```
./do.tests
```

# Test coverage

Not every line in `coLunacyDNS.c` is covered by the tests.  There
are a number if `#ifdef GCOV` blocks which hide this code from the tester:

* A test in the IPv6 parser will never be reached, but I will keep
  this code to keep the IPv6 parser robust.
    
* The code which exits w/o `/dev/random`: I am not going to remove
  `/dev/urandom` system wide for a SQA test.  I *know* this code works;
  it gets invoked when I compile in Windows with the wrong flags.
    
* `rand32()` has code to make sure we have a RNG state which is never
  run in coLunacyDNS.  I will keep it around so *that* library remains 
  robust (I *could* reach this line by changing the C code to call 
  rand32() *before* init_rng(), but nah)

* We will never reach a block of code which makes an IP `127.0.0.1`
  if unset.

* A couple of tests for bad sockets or bind IPs will never be reached.
  Not “fixing”, I would rather have two checks than zero checks.

* We do not test the sandboxing code which drops root and does a chroot().
  This is for practical reasons: If we drop root, we won’t be able to 
  write to the files used by gcov/gcc to track test coverage.  I have
  verified this code works via hand testing.

* The `dns_udp == 0` sanity test in setup_bind will never be called
  in coLunacyDNS, but I am keeping this code because I would rather
  have a sanity test which is never used.

* `human2DNS` has a sanity check which will never pass.  I will keep this
  check in production code just in case some corner case I haven’t thought
  of triggers it.

