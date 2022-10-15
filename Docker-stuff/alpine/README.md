To get a better sense of whether MaraDNS’s test framework works on
a POSIX system, we have a tiny alpine Linux version of the test
image.

Right now, the tests do not all pass in Alpine, so the Ubuntu 22.04
Docker image in the parent directory remains the official testing
platform for MaraDNS.  In more detail, while all MaraDNS and Deadwood
tests pass, I am still working on getting the coLunacyDNS tests
to pass in Alpine.
