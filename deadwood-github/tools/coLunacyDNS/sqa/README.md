To run tests, on a CentOS 8 system, become root and then 

```
./do.tests
```

# Test coverage

Not every line in `coLunacyDNS.c` is covered by the tests.  These line 
numbers are for coLunacyDNS 1.0.003 (commit 
`148f3f7c66f299bb171427584efbf089fd5eebae`)

* Line 314 will *never* be reached but I am keeping it to keep the
  IPv6 parser robust.
    
* Lines 422-424 will not be covered: I am not going to remove
  `/dev/urandom` system wide for a SQA test (maybe a docker-only one)
  (But these lines are quite useful when I compile a win32 service
  with the wrong flags)
    
* Line 462 can not be reached in any of this code, but I am keeping
  it around so *that* library remains robust (I *could* reach this
  line by changing the C code to call rand32() *before* init_rng(), but
  nah)

* Because of line 1209, we will never reach line 536

* Lines 607-608 and 624-625 are never reached because of lines 1066 
  and 1080.  Not “fixing”, I would rather have two checks than zero 
  checks.


