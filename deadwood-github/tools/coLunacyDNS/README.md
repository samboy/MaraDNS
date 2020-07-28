# coLunacyDNS

coLunacyDNS is my project to make a simple DNS server which uses
Lua as a configuration file.  The server runs a Lua function every
time it gets a DNS query; in that function, the goal is to make
it possible to have the function ask for the C code to solve
a DNS query and then use the answer.

Progress:

* We now have a way of getting a timestamp in a way which is Y2038 
  compliant for both *NIX systems (including ones with 32-bit `time_t`,
  as long as the timestamp returned is the actual time mod `2 ^ 32`;
  this is the case for 64-bit CentOS8 running 32-bit applications,
  Windows XP using the 32-bit Posix API, but it is *not* the case for
  Windows 10 64-bit using the 32-bit Posix API) and Windows systems
  (the Windows 32-bit API has access to Y2038 compliant “filetime” 
  timestamps, which we use when compiling for Windows).
* We now have a way of getting cryptographically strong entropy and
  using it to seed a cryptographically strong random number generator;
  this will give us protection against spoofing attacks.
* I have created calls available to the Lua code to get timestamps and
  random numbers.  Note that the timestamps are in an unusual format
  (256 ticks per second; different epoch).

In progress:

* Call the Lua code in a way which allows a DNS name to be solved, and
  have the solution be available to the Lua code. (Progress: The
  called function is now a co-routine; I have a way of protecting the
  co-routine "threads" from the garbage collector; and we have most of 
  the scaffolding needed to have the code call other DNS servers)

Note that this is under construction; its API and interface is subject to
change.
