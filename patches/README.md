These are security patches applied to versions of MaraDNS after
3.5.0036 (2023); all of these issues were found using 
AI assistance:

* [DNS-over-TCP patch](MaraDNS-sendtcp.patch.txt).  There was a denial of
  service where a trusted user authorized to perform queries could disable 
  DNS-over-TCP until Deadwood was restarted.  The hole only worked when
  DNS-over-TCP was enabled, a non-default configuration.  Date: 2026-06-11
  MaraDNS 3.5.0037 and later has this patch already applied.

* [DNS-over-TCP patch 2](MaraDNS-recvtcp.patch.txt).  Another denial of
  service bug in MaraDNS’s (actually Deadwood’s) DNS-over-TCP code.  The
  only impact was that DNS-over-TCP could be disabled by an attacker;
  DNS-over-UDP was not impacted.  Date: 2026-08-24  MaraDNS 3.5.0039
  and later has this patch already applied.

* [RFC 8482 patch](MaraDNS-rfc8482.patch.txt).  Deadwood, when generating
  a RFC8482 response, would make visible 19 bytes of unallocated memory on
  the heap to the network.  Dated: 2026-09-01  MaraDNS 3.5.0039 and later
  has this patch already applied.

As of 2026-09-01 (commit 0f46565c142377ab415d6c56a0e7ddd488ecc4f6), all 
known (3 of them) security bugs found by AI have been patched.

While these patches do not fix a known security bugs, they are useful

* [Valgrind patch](MaraDNS-valgrind.patch.txt) Let’s clean up
  Deadwood so known Valgrind warnings no longer occur

* [Patch to make sure shift used for netmask doesn’t trigger undefined 
  behavior](MaraDNS-maskShift.patch.txt)

### CVE-2026-40719

CVE-2026-40719 is a difficult to implement denial of service attack which
requires hundreds of specially crafted packets from an IP allowed to perform
recursive queries to temporarily use up all of Deadwood’s resources.

It’s a trivial enough attack, and one which would require a pretty deep
redesign of Deadwood’s recursive resolver to patch, that I am not patching
against this in the default Deadwood install.  Especially since the
recursive resolver is deprecated.

For this attack to work:

* Recursion has to be enabled (not the default)
* The attacking IP has to be authorized to perform recursive queries

The impact is this:

* After sending a large number of packets asking to perform a certain kind
  of recursive query, Deadwood will be unresponsive for about a minute

The workaround:

* Increase `maxprocs` to 4000000.  While this uses over 300 megs of memory,
  the attackers now has to send millions of packet a minute to temporarily
  “knock out” Deadwood.

The patch:

* [MaraDNS-CVE-2026-40719.patch.txt](MaraDNS-CVE-2026-40719.patch.txt) 
  patches Deadwood to not allow recursive queries.  Deadwood still works
  without problem contacting an upstream DNS server (Deadwood’s default
  configuration)

