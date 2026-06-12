These are security patches applied to versions of MaraDNS after
3.5.0036 (2023):

* [DNS-over-TCP patch](MaraDNS-sendtcp.patch.txt).  There was a denial of
  service where a trusted user authorized to perform queries could disable 
  DNS-over-TCP until Deadwood was restarted.  The hole only worked when
  DNS-over-TCP was enabled, a non-default configuration.  Date: 2026-06-11

