# DNS server security comparison

*Last updated: September 14, 2015*

This is a tally of known CVE security issues in four of the "big five" DNS
servers.  BIND has too many CVE security reports for me to bother listing
them all; I presume BIND users are comfortable with its security history.

As may come as a shock to some, while DjbDNS has the best history
(unless you count Deadwood as a separate program), there are, in fact,
security holes with its "dnscache" recursive component.

In terms of total reports, DjbDNS has only three; Unbound and NSD have
10, MaraDNS has 12, and PowerDNS has 18.  Total CVSS score is similar:

```
Server          Total CVSS score
PowerDNS        105.6
MaraDNS          63.1
NSD/Unbound      55.3
DjbDNS           18.6
Deadwood          6.4
```

In terms of unpatched bugs, there are no unpatched bugs I know of at
this time.  No new release of DjbDNS has been made to patch its three
known CVE bugs; while there are third-party forks which patch some of the
bugs, the only third-party DjbDNS release with fixes for all CVE bugs is
N-DJBDNS (which also fixes the two DjbDNS security bugs without CVE
numbers).  DjbDNS' "tinydns" authoritative-only component has no CVE
security bug reports; only the "dnscache" recursive component has CVE
issues.

Deadwood, MaraDNS 2.0's recursive resolver (which shares no code with
MaraDNS 1), has so far one CVE bug: 2012-1570, with a score of 6.4

Of PowerDNS' 18 CVE reports, 11 affect its recursor.  Eight NSD/Unbound
bugs affect Unbound, the recursive resolver; there are two CVE reports
for NSD.  All three DjbDNS CVE reports affect dnscache, its recursive
resolver.

```
CVE number      Score   Package                 Patched
2012-1570       6.4     MaraDNS and Deadwood    Yes
2012-0024       5.0     MaraDNS                 Yes
2011-5056       2.1     MaraDNS                 Yes
2011-5055       5.0     MaraDNS                 Yes
2011-0520       7.5     MaraDNS                 Yes
2010-2444       4.3     MaraDNS                 Yes
2008-0061       5.0     MaraDNS                 Yes
2007-3116       5.0     MaraDNS                 Yes
2007-3115       7.8     MaraDNS                 Yes
2007-3114       5.0     MaraDNS                 Yes
2004-0789       5.0     MaraDNS                 Yes
2002-2097       5.0     MaraDNS                 Yes
2012-1191       6.4     DjbDNS                  3rd-party; untested
2009-0858       5.8     DjbDNS                  Yes (No official release)
2008-4392       6.4     DjbDNS                  3rd-party
2015-1868       7.8     PowerDNS Recursor       Yes
2014-8601       5.0     PowerDNS Recursor       Yes
2014-3614       5.0     PowerDNS Recursor       Yes
2012-1193       6.4     PowerDNS Recursor       Yes (But it took over a year)
2012-0206       5.0     PowerDNS                Yes
2009-4010       7.5     PowerDNS Recursor       Yes
2009-4009       10.0    PowerDNS Recursor       Yes
2008-5277       4.3     PowerDNS                Yes
2008-3337       6.4     PowerDNS                Yes
2008-3217       6.8     PowerDNS Recursor       Yes
2008-1637       6.8     PowerDNS Recursor       Yes
2006-4252       5.0     PowerDNS Recursor       Yes
2006-4251       7.5     PowerDNS Recursor       Yes
2006-2069       5.0     PowerDNS Recursor       Yes
2005-0038       5.0     PowerDNS                Yes
2005-2302       2.1     PowerDNS                Yes
2005-2301       5.0     PowerDNS                Yes
2005-0428       5.0     PowerDNS                Yes
2012-2978       5.0     NSD                     Yes
2009-1755       5.0     NSD                     Yes
2014-8602       4.3     Unbound                 Yes
2012-1192       6.4     Unbound                 Yes
2011-4869       7.8     Unbound                 Yes
2011-4528       5.0     Unbound                 Yes
2009-4008       5.0     Unbound                 Yes
2011-1922       4.3     Unbound                 Yes
2010-0969       5.0     Unbound                 Yes
2009-3602       7.5     Unbound                 Yes
```
