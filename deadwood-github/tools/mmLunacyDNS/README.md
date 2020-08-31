# THIS CODE IS DEPRECATED

mmLunacyDNS is deprecated and no longer supported.  I am only
keeping the code here for historical purposes, and may remove it
at a future time.  Anyone using mmLunacyDNS should use coLunacyDNS
instead, which is fully tested, supported, and stable.

# DO NOT USE THIS CODE

# mmLunacyDNS

mmLunacyDNS was a simple DNS server configured with Lunacy, my fork of
Lua 5.1 (the syntax is the same).  This server can only either ignore
DNS queries or reply with "A" (IPv4 IP DNS record) replies.
coLunacyDNS, on the other hand, can send “not there” responses,
query other DNS servers for records, send “server fail” replies,
and has both IPv4 and IPv6 support (mmLunacyDNS is IPv4 only).

Use coLunacyDNS instead.
