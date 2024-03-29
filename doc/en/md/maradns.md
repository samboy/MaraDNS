```
Erre con erre cigarro 
Erre con erre barril 
Rápido ruedan los carros 
En el ferrocarril 
```

# NAME

maradns - DNS server 

# SYNOPSIS

**maradns [ -v | -f mararc_file_location ]** 

# TABLE OF CONTENTS

This man page has the following sections:

```
Name  
Synopsis 
Table of Contents 
Description 
Usage 
Firewall Configuration 
Frequently Asked Questions 
Bugs 
Unimplemented Features 
Legal Disclaimer 
Authors 
```

# DESCRIPTION

**maradns** is a DNS server written with security, simplicity, and 
performance in mind. 

**maradns** has two forms of arguments, both of which are optional. 

The first is the location of a **mararc** file which MaraDNS obtains 
all configuration information from. The default location of this file 
is **/etc/mararc**. This is specified in the form **maradns -f 
mararc_file_location**; *mararc_file_location* is the location of the 
mararc file. 

It is also possible to have MaraDNS display the version number and 
exit. This is specified by invoking maradns in the form **maradns -v** 
or **maradns --version** 

# USAGE

MaraDNS consists of two programs: maradns, an authoritative-only 
nameserver, and Deadwood, a recursive name server. Deadwood has its own 
man page. 

In order for MaraDNS to function as an authoritative nameserver, two or 
more files need to be set up: the mararc file and one or more "csv2" 
(or "csv1") zone files. 

The format of a csv2 zone file can be obtained from the **csv2(5)** 
manual page. The configuration format of the mararc file can be 
obtained from the **mararc(5)** manual page. 

Please note that, in order to reload a zone file, it is necessary to 
restart MaraDNS and reload all zone files. MaraDNS uses a hash data 
format which loads records very quickly from memory, but requires a 
restart to update. 

In order to have MaraDNS run as a daemon, the duende program is used to 
daemonize MaraDNS. See the **duende(8)** manual page for details. 

# FIREWALL CONFIGURATION

When using the maradns authoritative nameserver, allow UDP connections 
from all hosts on the internet to UDP port 53 for the IP that the 
authoritative nameserver uses. 

When using the Deadwood recursive nameserver: 

* Allow UDP connections from the Deadwood server to any machine on the 
  internet where the UDP destination port is 53

* Allow UDP connections from any machine on the internet to the IP of 
  the recursive server, where the source port from the remote 
  server is 53, and the destination port is between 15000 and 19095 
  (inclusive)

* Allow UDP connections from IPs that use Deadwood as a recursive DNS 
  server to port 53

Deadwood uses a strong secure RNG (RadioGatun[32]) for both the query 
(16 bits of entropy) and the source port of the query (12 bits of 
entropy). This makes spoofing replies to a Deadwood recursive server 
more difficult, since the attacker has only a one in 250 million chance 
that a given spoofed reply will be considered valid.

# FREQUENTLY ASKED QUESTIONS

## INDEX

1. I'm using an older version of MaraDNS

2. How do I try out MaraDNS?

3. What license is MaraDNS released under?

4. How do I report bugs in MaraDNS?

5. Some of the postings to the mailing list do not talk about MaraDNS!

6. How do I get off the mailing list?

7. How do I set up reverse DNS on MaraDNS?

8. I am on a slow network, and MaraDNS can not process recursive queries

9. When I try to run MaraDNS, I get a cryptic error message.

10. After I start MaraDNS, I can not see the process when I run netstat -na

11. What string library does MaraDNS use?

12. Why does MaraDNS use a multi-threaded model?

13. I feel that XXX feature should be added to MaraDNS

14. I feel that MaraDNS should use another documentation format

15. Is there any process I need to follow to add a patch to MaraDNS?

16. Can MaraDNS act as a primary nameserver?

17. Can MaraDNS act as a secondary nameserver?

18. What is the difference between an authoritative and a recursive DNS server?

19. The getzone client isn't allowing me to add certain hostnames to my zone

20. Is MaraDNS portable?

21. Can I use MaraDNS in Windows?

22. MaraDNS freezes up after being used for a while

23. What kind of Python integration does MaraDNS have

24. Doesn't "kvar" mean "four" in Esperanto?

25. How scalable is MaraDNS?

26. I am having problems setting `upstream_servers`

27. Why doesn't the MaraDNS.org web page validate?

28. How do MX records work?

29. Does MaraDNS have support for SPF?

30. I'm having problems resolving CNAMES I have set up.

31. I have a NS delegation, and MaraDNS is doing strange things.

32. I am transferring a zone from another server, but the NS records 
are these strange "synth-ip" records.

33. Where is the root.hints file?

34. Are there any plans to use autoconf to build MaraDNS?

35. How do I change the compiler or compile-time flags with MaraDNS' 
build process?

36. Will you make a package for the particular Linux distribution I am using?

37. I am using the native Windows port of MaraDNS, and some features 
are not working.

38. MaraDNS isn't starting up

39. You make a lot of releases of MaraDNS; at our ISP/IT department, 
updating software is non-trivial.

40. I have star records in my zones, and am having problems with 
NXDOMAINs/IPV6 resolution

41. I have a zone with only SOA/NS records, and the zone is not working.

42. I am having problems registering my domain with AFNIC (the 
registrar for .fr domains)

43. I can't see the full answers for subdomains I have delegated

44. MaraDNS 1 has a problem resolving a domain

45. MaraDNS 1.2 has issues with NXDOMAINS and case sensitivity.

46. Can MaraDNS offer protection from phishing and malicious sites?

47. Does maradns support star (wildcard) records?

48. I'm having problems using MaraDNS with some *NIX command line 
applications like telnet

49. My virus scanner reports that MaraDNS or Deadwood has a virus

50. I can not subscribe to the MaraDNS mailing list

51. How does MaraDNS respond to EDNS (RFC2671) packets?

52. How to I get MaraDNS to always give the same IP to all DNS queries?

53. Why did you change MaraDNS' tagline?

54. How do you stop MaraDNS from taking part in a distributed 
denial-of-service attack?

55. What about DNS-over-TCP?

56. How do I use MaraDNS with systemd?

57. Why doesn't MaraDNS use IP_FREEBIND?

58. Is there a web interface for MaraDNS?

59. What does the message “don’t forget the trailing dot” mean?

60. Does MaraDNS support newer top level domains?

61. Can MaraDNS handle IDN domain names?

## ANSWERS

## 1. I'm using an older version of MaraDNS

Upgrade to MaraDNS 2.0. Here is an upgrade guide. 

MaraDNS 1 is no longer supported; support ended on June 21, 2015. 

## 2. How do I try out MaraDNS?

Read the quick start guide, which is the file named 0QuickStart in the 
MaraDNS distribution.

## 3. What license is MaraDNS released under?

MaraDNS is released with the following two-clause BSD-type license: 

Copyright (c) 2002-2016 Sam Trenholme and others 

TERMS 

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are 
met: 

1. Redistributions of source code must retain the above copyright 
notice, this list of conditions and the following disclaimer. 

2. Redistributions in binary form must reproduce the above copyright 
notice, this list of conditions and the following disclaimer in the 
documentation and/or other materials provided with the distribution. 

This software is provided 'as is' with no guarantees of correctness or 
fitness for purpose. 

## 4. How do I report bugs in MaraDNS?

Post your bug report as a Github issue. 

## 5. Some of the postings to the mailing list do not talk about MaraDNS!

As of September 2013, the mailing list has become moderated and only 
postings on the mailing list are relevant MaraDNS announcements. 

## 6. How do I get off the mailing list?

Send an email to list-unsubscribe@maradns.org, or an email to 
list-request@maradns.org with "unsubscribe" as the subject line. 

The mailing list will send you an email confirming the unsubscribe 
request; this email needs to be replied to in order to get off the 
list. 

## 7. How do I set up reverse DNS on MaraDNS?

Reverse DNS (sometimes called "reverse mapping") is set up by using PTR 
(pointer) records. For example, the PTR record which performs the 
reverse DNS lookup for the ip 10.2.3.4 looks like this in a CSV2 zone 
file: 

` 4.3.2.10.in-addr.arpa. PTR www.example.com. ` 

It is also possible to use a special "FQDN4" which automatically sets 
up the reverse mapping of a given record: 

` www.example.com. FQDN4 10.2.3.4 ` 

If you wish to have a PTR (reverse DNS lookup; getting a DNS name from 
a numeric IP) record work on the internet at large, it is not a simple 
matter of just adding a record like this to a MaraDNS zonefile. One 
also needs control of the appropriate in-addr.arpa. domain. 

While it could make logical sense to contact the IP 10.11.12.13 when 
trying to get the reverse DNS lookup (fully qualified domain name) for 
a given IP, DNS servers don't do this. DNS server, instead, contact the 
root DNS servers for a given in-addr.arpa name to get the reverse DNS 
lookup, just like they do with any other record type. 

When an internet service provider is given a block of IPs, they are 
also given control of the DNS zones which allow them to control reverse 
DNS lookups for those IPs. While it is possible to obtain a domain and 
run a DNS server without the knowledge or intervention of an ISP, being 
able to control reverse DNS lookups for those IPs requires ISP 
intervention. 

## 8. I am on a slow network, and Deadwood can not process recursive queries

Deadwood, by default, only waits two seconds for a reply from a remote 
DNS server. This default can be increased by adding a line like this in 
the mararc file:

```
timeout_seconds = 5 
```

Note that making this too high will slow MaraDNS down when DNS servers 
are down, which is, alas, all too common on today's internet. 

## 9. When I try to run MaraDNS, I get a cryptic error message.

There is usually some context of where there is a syntax error in a 
data file before the cryptic error message. For example, when there is 
a syntax error in a csv2 zone file, MaraDNS will tell you exactly at 
what point it had to terminate parsing of the zone file. 

If MaraDNS does return a cryptic error message without letting you know 
what is wrong, let us know in a Github issueso that we can fix the bug. 
MaraDNS is designed to be easy to use; cryptic error messages go 
against this spirit. 

## 10. After I start MaraDNS, I can not see the process when I run 
netstat -na 

Udp services do not have a prominent "LISTEN" when netstat is run. 

When MaraDNS is up, the relevant line in the netstat output looks like 
this: ` udp 0 0 127.0.0.1:53 0.0.0.0:* ` 

While on the topic of netstat, if you run `netstat -nap` as root on 
Linux and some other *nix operating systems, you can see the names of 
the processes which are providing internet services. 

## 11. What string library does MaraDNS use?

MaraDNS uses its own string library, which is called the "js_string" 
library. Man pages for most of the functions in the js_string library 
are in the folder `doc/man` of the MaraDNS distribution

## 12. Why does MaraDNS use a multi-threaded model?

MaraDNS 2.0 no longer uses threads. 

It took me three years to rewrite MaraDNS' recursive resolver as a 
separate non-threaded daemon. This has been done, and now all recursion 
is done with Deadwood which does not need threads. 

## 13. I feel that XXX feature should be added to MaraDNS

There are no plans to add new features to MaraDNS or Deadwood at this 
time. 

## 14. I feel that MaraDNS should use another documentation format

The reason that MaraDNS uses its own documentation format is to satisfy 
both the needs of translators to have a unified document format and my 
own need to use a documentation format that is simple enough to be 
readily understood and which I can add features on an as needed basis. 

The documentation format is essentially simplified HTML with some 
special tags added to meet MaraDNS' special needs. 

This gives me more flexibility to adapt the documentation format to 
changing needs. For example, when someone pointed out that it's not a 
good idea to have man pages with hi-bit characters, it was a simple 
matter to add a new HIBIT tag which allows man pages to be without 
hi-bit characters, and other document formats to retain hi-bit 
characters. 

Having a given program have its own documentation format is not without 
precedent; Perl uses its own "pod" documentation format. 

## 15. Is there any process I need to follow to add a patch to MaraDNS?

I no longer accept third party patches

## 16. Can MaraDNS act as a primary nameserver?

Yes. 

The `zoneserver` program serves zones so that other DNS servers can be 
secondaries for zones which MaraDNS serves. This is a separate program 
from the `maradns` server, which processes authoritative UDP DNS 
queries, and Deadwood which processes recursive DNS queries. 

See the DNS masterdocument in the MaraDNS tutorial for details. 

## 17. Can MaraDNS act as a secondary nameserver?

Yes. 

Please read the DNS slavedocument, which is part of the MaraDNS 
tutorial. 

## 18. What is the difference between an authoritative and a recursive 
DNS server?

A recursive DNS server is a DNS server that is able to contact other 
DNS servers in order to resolve a given domain name label. This is the 
kind of DNS server one points to in `/etc/resolv.conf`. MaraDNS uses 
the Deadwood daemon to process recursive DNS queries. 

An authoritative DNS server is a DNS server that a recursive server 
contacts in order to find out the answer to a given DNS query. The 
maradns daemon processes authoritative DNS queries. 

## 19. The fetchzone client isn't allowing me to add certain hostnames 
to my zone

For security reasons, MaraDNS' fetchzone client does not add records 
which are not part of the zone in question. For example, if someone has 
a zone for example.com, and this record in the zone: 

` 1.1.1.10.in-addr.arpa. PTR dns.example.com. ` 

MaraDNS will not add the record, since the record is out-of-bailiwick. 
In other words, it is a host name that does not end in .example.com. 

There are two workarounds for this issue: 

* Create a zone file for 1.1.10.in-addr.arpa., and put the PTR records 
  there.

* Use rcp, rsync, or another method to copy over the zone files in 
  question.

## 20. Is MaraDNS portable?

MaraDNS is developed in CentOS 6 and Windows 7. MaraDNS may or may not 
compile and run on other systems. 

## 21. Can I use MaraDNS in Windows?

Yes. There is both a partial mingw32 (native win32 binary) port and a 
full Cygwin port of MaraDNS; both of these ports are part of the native 
build of MaraDNS. Deadwood has full Windows support, including the 
ability to run as a service. 

## 22. MaraDNS freezes up after being used for a while

If using your ISP's name servers or some other name servers which are 
not, in fact, root name servers, please make sure that you are using 
the upstream_servers dictionary variable instead of the root_servers 
dictionary variable. 

If you still see MaraDNS freeze up after making this correction, please 
send a bug report as a Github issue. 

## 23. What kind of Python integration does MaraDNS have

The mararc file uses the same syntax that Python uses; in fact, Python 
can parse a properly formatted mararc file. 

There is no other integration with Python. 

## 24. Doesn't "kvar" mean "four" in Esperanto?

Indeed, it does. However the use of "kvar" in the MaraDNS source code 
only coincidentally is an Esperanto word. "kvar" is short for "Kiwi 
variable"; a lot of the parsing code comes from the code used in the 
Kiwi spam filter project. 

## 25. How scalable is MaraDNS?

MaraDNS is optimized for serving a small number of domains as quickly 
as possible. That said, MaraDNS is remarkably efficnent for serving a 
large number of domains, as long as the server MaraDNS is on has the 
memory to fit all of the domains, and as long as the startup time for 
loading a large number of domains can be worked around. 

The "big-O" or "theta" growth rates for various MaraDNS functions are 
as follows, where N is the number of authoritative host names being 
served:

```
Startup time                            N 
Memory usage                            N 
Processing incoming DNS requests        1 
```

As can be seen, MaraDNS will process 1 or 100000 domains in the same 
amount of time, once the domain names are loaded in to memory. 

## 26. I am having problems setting `upstream_servers`

`upstream_servers` is only supported by Deadwood, and is no longer 
supported in MaraDNS 2.0. The `upstream_servers` dwood3rc variable is 
set thusly: 

`upstream_servers["."] = "10.3.28.79, 10.2.19.83"` 

Note the `["."]`. 

Note that the `upstream_servers` variable needs to be initialized 
before being used via `upstream_servers = {}` (the reason for this is 
so that a dwood3rc file has 100% Python-compatible syntax). A complete 
dwood3rc file that uses `upstream_servers` may look like this:

```
ipv4_bind_addresses = "127.0.0.1" 
chroot_dir = "/etc/maradns" 
recursive_acl = "127.0.0.1/8" 
upstream_servers = {} 
upstream_servers["."] = "10.1.2.3, 10.2.4.6" 
```

## 27. Why doesn't the MaraDNS.org web page validate?

HTML pages on the MaraDNS.org web site should validate as HTML 4.0 
Transitional. However, the CSS will not validate. 

I have designed MaraDNS' web page to be usable and as attractive as 
possible in any major browser released in the last ten years. 
Cross-browser support is more important than strict W3 validation. The 
reason why the CSS does not validate is because I need a way to make 
sure there is always a scrollbar on the web page, even if the content 
is not big enough to merit one; this is to avoid the content jumping 
from page to page. There is no standard CSS tag that lets me do this. 
I'm using a non-standard tag to enable this in Gecko (Firefox's 
rendering engine); this is enabled by default in Trident (Internet 
Explorer's rendering engine). The standards are deficient and blind 
adherence to them would result in an inferior web site. 

There are also two validation warnings generated by redefinitions which 
are needed as part of the CSS filters used to make the site attractive 
on older browsers with limited CSS support. 

On a related note, the reason why I use tables instead of CSS for some 
of the layout is because Microsoft Internet Explorer 6 and other 
browsers do not have support for the `max-width` CSS property. Without 
this property, the web page will not scale down correctly without using 
tables. Additionally, tables allow a reasonably attractive header in 
browsers without CSS support. 

## 28. How do MX records work?

How MX records work: 

* The mail transport agent (Sendmail, Postfix, Qmail, MS Exchange, 
  etc.) looks up the MX record for the domain

* For each of the records returned, the MTA (mail transport agent) 
  looks up the IP for the names.

* It will choose, at random, any of the MXes with the lowest priority 
  number.

* Should that server fail, it will try another server with the same 
  priority number.

* Should all MX records with a given priority number fail, the MTA 
  will try sending email to any of the MX records with the 
  second-lowest priority value.

As an aside, do not have MX records point to CNAMEs. 

## 29. Does MaraDNS have support for SPF?

SPF, or sender policy framework, is method of using DNS that makes it 
more difficult to forge email. MaraDNS has full support for SPF, both 
via TXT records and RFC4408 SPF records. 

SPF configuration is beyond the scope of MaraDNS' documentation. 
However, at the time this FAQ entry was last updated (July, 2013), 
information and documentation concerning SPF is available at 
http://openspf.org. The BIND examples will work in MaraDNS csv2 zone 
files as long as the double quotes (") are replaced by single quotes 
('). For example, a SPF TXT record that looks like `example.net. IN TXT 
"v=spf1 +mx a:colo.example.com/28 -all"` in a BIND zone file will look 
like `example.net. TXT 'v=spf1 +mx a:colo.example.com/28 -all'` in a 
MaraDNS zone file. MaraDNS can also make the corresponding SPF record, 
which will have the syntax `example.net. SPF 'v=spf1 +mx 
a:colo.example.com/28 -all'`. 

Use '\x7e' to put a tilde ("~" character) in a SPF record: 

`example.com. SPF 'v=spf1 +mx a:colo.example.com/28 '\x7e'all'` 

## 30. I'm having problems resolving CNAMES I have set up.

This is probably because you have set up what MaraDNS calls a dangling 
CNAME record. 

Let us suppose we have a CNAME record without an A record in the local 
DNS server's database, such as:

```
	google.example.com. CNAME www.google.com. 
```

This record, which is a CNAME record for "google.example.com", points 
to "www.google.com". Some DNS servers will recursively look up 
www.google.com, and render the above record like this:

```
	google.example.com. CNAME www.google.com. 
	www.google.com. A 66.102.7.104 
```

For security reasons, MaraDNS doesn't do this. Instead, MaraDNS will 
simply output:

```
	google.example.com. CNAME www.google.com. 
```

Some stub resolvers will be unable to resolve google.example.com 
as a consequence. 

If you set up MaraDNS to resolve CNAMEs thusly, you will get a warning 
in your logs about having a dangling CNAME record. 

If you want to remove these warnings, add the following to your mararc 
file:

```
	no_cname_warnings = 1 
```

Information about how to get MaraDNS to resolve dangling CNAME records 
is in the tutorial file dangling.html

## 31. I have a NS delegation, and MaraDNS is doing strange things.

This is only an issue in MaraDNS 1.4. MaraDNS 2.0 does not allow the 
same IP to both authoritatively and recursively resolve records. 

## 32. I am transferring a zone from another server, but the NS records 
are these strange "synth-ip" records. 

MaraDNS expects, in csv2 zone files, for all delegation NS records to 
be between the SOA record and the first non-NS record. 

If a zone looks like this:

```
example.net. +600 soa ns1.example.net.  
hostmaster@example.net 10 10800 3600 604800 1080 
example.net. +600 mx 10 mail.example.net. 
example.net. +600 a 10.2.3.5 
example.net. +600 ns ns1.example.net. 
example.net. +600 ns ns3.example.net. 
mail.example.net. +600 a 10.2.3.7 
www.example.net. +600 a 10.2.3.11 
```

Then the NS records will be "synth-ip" records. 

The zone should look like this:

```
example.net. +600 soa ns1.example.net.  
hostmaster@example.net 10 10800 3600 604800 1080 
example.net. +600 ns ns1.example.net. 
example.net. +600 ns ns3.example.net. 
example.net. +600 mx 10 mail.example.net. 
example.net. +600 a 10.2.3.5 
mail.example.net. +600 a 10.2.3.7 
www.example.net. +600 a 10.2.3.11 
```

This will remove the "synth-ip" records. 

To automate this process, this awk script is useful:

```
fetchzone whatever.zone.foo 10.1.2.3 | awk ' 
{if($3 ~ /ns/ || $3 ~ /soa/){print} 
else{a = a "\n" $0}} 
END{print a}' > zonefile.csv2 
```

Replace "whatever.zone.foo" with the name of the zone you are 
fetchin 10.1.2.3 with the IP address of the DNS master, and 
zonefile.csv2 with the name of the zone file MaraDNS loads. 

## 33. Where is the root.hints file?

MaraDNS (actually, Deadwood), unlike BIND, does not need a complicated 
root.hints file in order to have custom root servers. In order to 
change the root.hints file, add something like this to your dwood3rc 
file:

```
root_servers["."] =  "131.161.247.232," 
root_servers["."] += "208.185.249.250," 
root_servers["."] += "66.227.42.140," 
root_servers["."] += "66.227.42.149," 
root_servers["."] += "65.243.92.254" 
```

Note that there is no "+=" in the first line, and the last line 
does not have a comma at the end. Read the recursive tutorial document 
for more information. 

## 34. Are there any plans to use autoconf to build MaraDNS?

No. 

In more detail, MaraDNS does not use autoconf for the following 
reasons: 

* Autoconf is designed to solve a problem that existed in the mid 
  1990s but does not exist today: A large number of different 
  incompatible C compilers and libc implementations. These days, 
  most systems are using gcc as the compiler and some version of 
  glibc as the libc. There is no longer a need, for example, to 
  figure out whether a given implementation of `getopt()` allows 
  '`--`' options. MaraDNS's `./configure` script can be run in only 
  a second or two; compare this to the 3-5 minute process 
  autoconf's `./configure` needs.

* Autoconf leaves GPL-tained files in a program's build tree. MaraDNS 
  is licensed under a BSD license that is *not* GPL-compatible, so 
  MaraDNS can not be distributed with these GPL-licensed files.

This leads us to the next question: 

## 35. How do I change the compiler or compile-time flags with MaraDNS' 
build process?

To change the compiler used by MaraDNS: 

* Run the `./configure` script

* Open up the file `Makefile` with an editor

* Look for a line that starts with `CC`

* If there is no line that starts with `CC`, create one just before 
  the line that starts with `FLAGS`

* Change (or create) that line to look something like `CC=gcc296` In 
  this example, the 2.96 version of gcc is used to compile MaraDNS.

* Note that it is important to **not** remove anything from this line 
  you do not understand; doing so will make MaraDNS unable to 
  compile or run. So, if the CC line looks like 
  `CC=gcc&nbsp;$(LDFLAGS)&nbsp;-DNO_FLOCK` and you want to compile 
  with gcc 2.96, change the line to look like 
  `CC=gcc296&nbsp;$(LDFLAGS)&nbsp;-DNO_FLOCK` retaining the flags 
  added by the configuration script.

Changing compile-time flags is a similar process: 

* Run the `./configure` script

* Open up the file `Makefile` with an editor

* Look for a line that starts with `FLAGS`

* Change (or create) that line to look something like `FLAGS=-O3` In 
  this example, MaraDNS is compiled with the -O3 option.

* Note that it is important to **not** remove anything from this line 
  you do not understand; doing so will make MaraDNS unable to 
  compile or run. So, if the FLAGS line looks like 
  `FLAGS=-O2&nbsp;-Wall&nbsp;-DSELECT_PROBLEM` and you want to 
  compile at optimization level three, change this line to look 
  like `FLAGS=-O2&nbsp;-Wall&nbsp;-DSELECT_PROBLEM` retaining the 
  flags added by the configuration script. `-DSELECT_PROBLEM` for 
  example, is needed in the Linux compile or MaraDNS will have 
  problems with freezing up.

## 36. Will you make a package for the particular Linux distribution I 
am using?

No. 

There is, however, a CentOS 5-compatible RPM spec file in the build 
directory. 

## 37. I am using the native Windows port of MaraDNS, and some features 
are not working.

Since Windows 32 does not have some features that *NIX OSes have, the 
native Windows port does not have all of the features of the *NIX 
version of MaraDNS. In particular, the following features are disabled: 

* ipv6 (this is actually a mingw32, not a Windows deficiency)

* The `chroot_dir` mararc variable

* The `maradns_gid` and `maradns_uid` mararc variables

* The `maxprocs` mararc variable

* The `synth_soa_serial` variable can not have a value of 2

* There is no DNS-over-TCP support

If any of the above features are desired, try compiling MaraDNS using 
Cygwin. Note that the Cygwin port of MaraDNS does not have ipv6 
support, and that while `chroot_dir` works in Cygwin, it does not have 
the security that the *NIX chroot() call has. 

## 38. MaraDNS isn't starting up

This is usually caused by a syntax error in one's mararc file, or by 
another MaraDNS process already running. To see what is happening, look 
at your system log (`/var/log/messages` in Centos 3) to see what errors 
MaraDNS reports. If you do not know how to look at a system log, you 
can also invoke MaraDNS from the command line as root; any errors will 
be visible when starting MaraDNS. 

## 39. You make a lot of releases of MaraDNS; at our ISP/IT department, 
updating software is non-trivial.

Regularly updating software is required to keep something as 
complicated as a DNS server secure; there is not a DNS server out there 
so secure that it never needs to be updated. 

Since MaraDNS is finished, updates usually only happen about once a 
year. 

The last security bug which required a MaraDNS update was made before 
September 28, 2015. 

## 40. I have star records in my zones, and am having problems with 
NXDOMAINs/IPV6 resolution

This was a bug in MaraDNS 1.2 which has long since been fixed. 

## 41. I have a zone with only SOA/NS records, and the zone is not working.

MaraDNS 1.2 had a bug where it did not correctly process zones without 
any "normal" records. Upgrade to MaraDNS 2.0. 

## 42. I am having problems registering my domain with AFNIC (the 
registrar for .fr domains)

Because of an issue with AFNIC (who, annoyingly enough, check the RA 
bit when registering a domain), in order to register a domain with 
AFNIC using MaraDNS as your DNS server, the following steps need to be 
followed: 

* MaraDNS version 1.4 or 2.0 needs to be used; if you're using an 
  older version of MaraDNS, upgrade.

* It is necessary to have recursion disabled, if using MaraDNS 1.4, 
  either by compiling MaraDNS without recursive support 
  (./configure --authonly ; make), or by making sure MaraDNS does 
  not have recursion enabled (by not having `recursive_acl` set in 
  one's MaraDNS 1.4 mararc file)

If one wishes to both register domains with AFNIC and use MaraDNS 1.4 
as a recursive DNS server, it is required to have the recursive server 
be a separate instance of MaraDNS on a separate IP. It is not possible 
to have the same DNS server both send DNS packets in a way that both 
makes AFNIC happy and allows recursive queries. 

Note also: AFNIC gives warnings about reverse DNS lookups; more 
information about this issue can be found in the FAQ entry about 
reverse DNS mappings(question 7). In addition, AFNIC requires 
DNS-over-TCP to work; information on configuring MaraDNS to have this 
can be found in the DNS-over-TCP tutorial. 

## 43. I can't see the full answers for subdomains I have delegated

To have the subdomains be visible to MaraDNS 1.4 recursive nameservers, 
add the following to your mararc file: 

`recurse_delegation = 1` 

## 44. MaraDNS 1 has a problem resolving a domain

This issue should be fixed in MaraDNS 2.0. 

Here's what happening: I have rewritten the recursive resolver for 
MaraDNS. The old code was always designed to be a placeholder until I 
wrote a new recursive resolver. 

The new recursive resolver is called "Deadwood"; right now it's fully 
functional and part of MaraDNS 2.0. More information is here: 

http://maradns.blogspot.com/search/label/Deadwood

http://maradns.samiam.org/deadwood/

Since the old recursive code is a bit difficult to maintain, and since 
I in the process of rewriting the recursive code, my rule is that I 
will only resolve security issues with MaraDNS 1.0's recursive 
resolver.

## 45. MaraDNS 1.2 had issues with NXDOMAINS and case sensitivity.

There was a known bug in MaraDNS 1.2.12 where, should a client ask for 
a non-existent record in all caps, MaraDNS 1.2.12 will return a 
NXDOMAIN instead of a "not there" reply. Upgrade to 2.0. 

## 46. Can MaraDNS offer protection from phishing and malicious sites?

Deadwood can block up to about 20,000 domains. More details are in the 
Deadwood FAQ. 

## 47. Does maradns support star (wildcard) records?

Yes. 

MaraDNS supports both having stars at the beginning of records and the 
end of records. For example, to have *anything*.example.com. have the 
IP 10.1.2.3, add this line to the zone file for example.com: 

`*.example.com. A 10.1.2.3` 

To have stars at the end of records, `csv2_default_zonefile` has to be 
set. The mararc parameter `bind_star_handling` affects how star records 
are handled. More information is in the mararc man page. 

## 48. I'm having problems using MaraDNS with some *NIX command line 
applications like telnet.

Some *NIX command line networking applications, such as telnet and ssh, 
try to do either a reverse DNS lookup (IP-to-host name conversion) or 
an IPv6 lookup. This slows things down and sometimes causes the 
applications to not work at all. 

For people who do not need IPv6 lookups, add the following line to 
one's mararc file to have MaraDNS respond to all IPv6 lookups with a 
bogus "not found" reply: 

`reject_aaaa = 1` 

If knowing the hostname a given IP has isn't important, these kinds of 
lookups can also be disabled: 

`reject_ptr = 1` 

## 49. My virus scanner reports that MaraDNS or Deadwood has a virus

This can be caused either by a poorly written anti-virus program 
reporting a false positive, or because a virus on your system has 
infected your copy of MaraDNS/Deadwood. 

Please use GPGto verify that the file which your scanner reports having 
a virus in has not been altered. In addition, please scan the file with 
AVG (free for non-commercial use) to verify your virus scanner has not 
reported a false positive. 

If you have verified the GPG signature of the program and AVG reports a 
virus, please let us know with a Github issue. Otherwise, please use a 
better virus scanner and make sure there are no viruses on your 
computer. 

## 50. I can not subscribe to the MaraDNS mailing list

*Please note that the mailing list is no longer used to handle MaraDNS 
support requests. Please file a Github issue at 
https://github.com/samboy/MaraDNS/issuesto file a MaraDNS bug report.* 

The procedure for subscribing to the mailing list is as follows: 

* Send an email to list-request@maradns.org with "Subscribe" as the 
  subject, or an email to list-subscribe@maradns.org

* You will get an email from list-request@maradns.org asking you to 
  confirm your subscription. This can be done by replying to the 
  message, or, more simply, by clicking on the link in the message.

* Once you click on that link, click on the button marked "subscribe 
  to list list"

* You will now get a message stating 'Welcome to the "list" mailing 
  list'.

* Note that the mailing list is moderated and only relevant MaraDNS 
  announcements are approved. People who need help should read the 
  manualsor search the MaraDNS webpagefor support.

If you get an email from list-request@maradns.org with the subject "The 
results of your email commands", you did not correctly send an email to 
list-request@maradns.org with the subject "Subscribe". 

If you do not get the email from list-request@maradns.org asking you 
for a confirmation, ensure that this email is not in your "spam" or 
"junk mail" folder. If you are unable to get these emails at your email 
address, please get a gmail email account, which can successfully 
subscribe to the MaraDNS mailing list. Note that subscription 
confirmation emails may be in Gmail's "promotions" tab. 

## 51. How does MaraDNS respond to EDNS (RFC2671) packets?

MaraDNS 2 (both the authoritative maradns server and the recursive 
Deadwood server) responds to EDNS packets by ignoring the OPT record 
and acting as if it the packet did not have an OPT record. 

MicroDNS(available in the `tools/misc` directory of any MaraDNS 2 
release) responds to EDNS queries the same way Deadwood 2.9.03 did: By 
giving back "NOTIMPL" instead of answering the query with the default 
IP. NanoDNS, in the interest of minimizing code side, responds to EDNS 
requests by returning NOTIMPL in the header, giving the OPT query in 
the AN section of the response, and giving the default IP in the AR 
section of the DNS reply packet. 

## 52. How to I get MaraDNS to always give the same IP to all DNS queries?

There are three ways to have MaraDNS always give the same IP in reply 
to any DNS query given to it: 

* The best way to do this is to set up a default zonefilethat causes 
  any and all A queries to always give the IP (and also allows all 
  AAAA queries to always give out the same IP6, all SPF or TXT 
  queries to give out the same SPF record, etc.).

* Another possibility, if someone just wants a simple DNS server that 
  always gives out the same IP address to any and all DNS queries, 
  is to use the MicroDNS program, available in `tools/misc`, as 
  well as having its own web page.

* If MicroDNS is too bloated, there is also NanoDNS, which I will 
  include the source code of below:

```
#include <arpa/inet.h> 
#include <string.h> 
#include <stdint.h> 
#define Z struct sockaddr 
#define Y sizeof(d) 
int main(int a,char **b){uint32_t i;char q[512] 
,p[17]="\xc0\f\0\x01\0\x01\0\0\0\0\0\x04";if(a> 
1){struct sockaddr_in d;socklen_t f=511;bzero(& 
d,Y);a=socket(AF_INET,SOCK_DGRAM,0);*((uint32_t 
*)(p+12))=inet_addr(b[1]);d.sin_family=AF_INET; 
d.sin_port=htons(53);bind(a,(Z*)&d,Y);for(;;){i 
=recvfrom(a,q,255,0,(Z*)&d,&f);if(i>9&&q[2]>=0) 
{q[2]|=128;q[11]?q[3]|=4:1;q[7]++;memcpy(q+i,p, 
16);sendto(a,q,i+16,0,(Z*)&d,Y);}}}return 0;} 
```

NanoDNS takes one argument: The IP we return. This program binds 
to all IP addresses a given machine has on the UDP DNS port (port 53). 
For example, to make a DNS server that binds to all IPs your system has 
and return the IP 10.11.12.13 to any UDP DNS queries sent to it, 
compile the above C program, call it `NanoDNS`, and invoke it with 
`NanoDNS 10.11.12.13` Note that NanoDNS does not daemonize, nor log 
anything, nor have any other space-wasting features.

## Why did you change MaraDNS' tagline?

I have changed MaraDNS' tagline from "MaraDNS: A security-aware DNS 
server" to "MaraDNS: A small open-source DNS server" because MaraDNS 
does not support DNSSEC. I have blogged about this: 

http://samiam.org/blog/20120326.html

## How do you stop MaraDNS from taking part in a distributed 
denial-of-service attack?

While I do not have time to implement rate limiting, CentOS 6 does 
support response rate limiting at the firewall level. The following 
iptables commands allow a given IP to only send MaraDNS/Deadwood 20 DNS 
queries every four seconds: 

`iptables -A INPUT -p udp --dport 53 -m state --state NEW -m recent 
--set --name DDOS --rsource`

`iptables -A INPUT -p udp --dport 53 -m state --state NEW -m recent 
--update --seconds 4 --hitcount 20 --name DDOS --rsource -j DROP`

To verify they are applied: 

`iptables --list`

To save these commands in CentOS so they are applied at system boot 
time: 

`iptables-save > /etc/sysconfig/iptables`

*Disclaimer* 

These incantations work in CentOS 6 but may or may not work in other 
versions of Linux. I do not support non-CentOS6 Linux installs of 
MaraDNS. 

## What about DNS-over-TCP?

For people who want DNS-over-TCP, instructions are in the DNS-over-TCP 
tutorial. Note that Windows users will have to use Cygwin to have 
DNS-over-TCP. 

However, DNS-over-TCP is not necessary. DNS-over-TCP is optional as per 
section 6.1.3.2 of RFC1123; any program or web service that considers 
no DNS-over-TCP an error is not RFC-compliant. 

Not having DNS-over-TCP is more secure, because it gives attackers a 
smaller surface to attack. 

## How do I use MaraDNS with systemd?

While I like systemd, it is not part of CentOS 6 nor, obviously, 
Windows 7. That in mind, I have no plans to support systemd until 2017, 
when I plan to update MaraDNS' supported operating systems. 

However, Tomasz Torcz has kindly made some systemd files for MaraDNS, 
which people are free to use. 

As an aside, I do not like the fact that Debian will probably not make 
systemd the default init; I do not think this kind of fragmentation is 
good for Linux. 

## Why doesn't MaraDNS use IP_FREEBIND?

IP_FREEBIND is a non-POSIX Linux-specific extension to POSIX's 
netinet/in.h, and, as such, has no place in MaraDNS' code. MaraDNS 
strives to use POSIX-compliant calls so that it can compile on as many 
systems as possible. 

When I say that Windows 7 and CentOS 6 are the only supported operating 
systems for MaraDNS, this does not mean that MaraDNS will not compile 
and run on other systems; it merely means that I can not provide 
support for Github bug reportsfor people who want to run MaraDNS in 
Minix, one of the open-source BSD variants, or what not. 

## Is there a web interface for MaraDNS?

The Kloxo-MRcontrol panel has MaraDNS support. 

## What does the message “don’t forget the trailing dot” mean?

It means to not forget the tailing dot. 

Hostnames in zone files need to be properly terminated; if a hostname 
is in the form “foo.example.com”, this name will not parse and return 
an error with a note to not forget the trailing dot. 

To fix this, put a trailing dot at the end of the hostname, so it looks 
like “foo.example.com.” (observe that dot at the end) instead of 
“foo.example.com” 

## Does MaraDNS support newer top level domains?

MaraDNS does not impose any limitations on the top level domain used in 
zone files and other places, as is fully compatible with newer top 
level domains like “today.” 

Note that, if using an internationalized domain name, it needs to be 
translated in to Punycode first. For example, if using the domain name 
“ñ.com.”, it needs to be in the form “xn--ida.com.” in MaraDNS’ mararc 
and zone files. 

## Can MaraDNS handle IDN domain names?

Yes, but the internationalized domain name (IDN) needs to be translated 
in to Punycode first. For example, if using the domain name “ñ.com.”, 
it needs to be in the form “xn--ida.com.” in MaraDNS’ mararc and zone 
files.

# BUGS

In the unusual case of having a csv2 zone file with Macintosh-style 
newlines (as opposed to DOS or UNIX newlines), while the file will 
parse, any errors in the file will be reported as being on line 1. 

The system startup script included with MaraDNS assumes that the only 
MaraDNS processes running are started by the script; it stops *all* 
MaraDNS processes running on the server when asked to stop MaraDNS. 

MaraDNS needs to use the **zoneserver** program to serve DNS records 
over TCP. See **zoneserver(8)** for usage information. 

MaraDNS does not use the zone file ("master file") format specified in 
chapter 5 of RFC1035. 

MaraDNS default behavior with star records is not RFC-compliant. In 
more detail, if a wildcard MX record exists in the form 
"*.example.com", and there is an A record for "www.example.com", but no 
MX record for "www.example.com", the correct behavior (based on RFC1034 
§4.3.3) is to return "no host" (nothing in the answer section, SOA in 
the authority section, 0 result code) for a MX request to 
"www.example.com". Instead, MaraDNS returns the MX record attached to 
"*.example.com". This can be changed by setting `bind_star_handling` to 
1. 

Star records (what RFC1034 calls "wildcards") can not be attached to NS 
records. 

MaraDNS, like every other known DNS implementation, only supports a 
QDCOUNT of 0 or 1. 

# UNIMPLEMENTED FEATURES

*These are features which I do not plan to implement in MaraDNS.* 

MaraDNS does not have a disk-based caching scheme for authoritative 
zones. 

MaraDNS' UDP server only loads zone files while MaraDNS is first 
started. UDP Zone information can only be updated by stopping MaraDNS, 
and restarting MaraDNS again. Note that TCP zone files are loaded from 
the filesystem at the time the client requests a zone. 

MaraDNS does not have support for allowing given host names to only 
resolve for a limited range of IPs querying the DNS server, or for host 
names to resolve differently, depending on the IP querying the host 
name. 

MaraDNS only allows wildcards at the beginning or end of a host name. 
E.g. names with wildcards like "foo.*.example.com". "www.*" will work, 
however, if a default zonefile is set up. Likewise, MaraDNS does not 
have regular expression hostname substitution. 

MaraDNS does not have support for MRTG or any other SNMP-based logging 
mechanism. 

# LEGAL DISCLAIMER

THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS OR 
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE. 

# AUTHORS

Sam Trenholme (http://www.samiam.org) is responsible for this man page. 

MaraDNS is written by me, Sam Trenholme, with a little help from my 
friends. Naturally, all errors in MaraDNS are my own (but read the 
disclaimer above). 

Here is a partial list of people who have provided assistance: 

Floh has generously set up a FreeBSD 4, FreeBSD 6, and Mac OS X system 
so that I can port MaraDNS to more platforms. 

Albert Lee has provided countless bug reports, and, nicely enough, 
patches to fix said bugs. He has also made improvements to the code in 
the tcp "zoneserver". 

Franky Van Liedekerke has provided much invaluable assistance. As just 
one example, he provided invaluable assistance in getting MaraDNS to 
compile on Solaris. In addition, he has provided much valuable SQA 
help. 

Christian Kurz, who has provided invaluable bug reports, especially 
when I had to re-implement the core hashing algorithm. 

Remmy, who is providing both the web space and a mailing list for 
maradns.org. 

Phil Homewood, who provided invaluable assistance with finding and 
fixing bugs in the authoritative portion of the MaraDNS server. He 
helped me plug memory leaks, find uninitialized variables being used, 
and found a number of bugs I was unable to find. 

Albert Prats kindly provided Spanish translations for various text 
files. 

Shin Zukeran provided a patch to recursive.c which properly makes a 
normal null-terminated string from a js_string object, to send as an 
argument to open() so we can get the rijndael key for the PRNG. 

D Richard Felker III has provided invaluable bug reports. By looking at 
his bug reports, I have been able to hunt down and fix many problems 
that the recursive nameserver had, in addition to at least one problem 
with the authoritative nameserver. 

Ole Tange has also given me many valuable MaraDNS bug reports. 

Florin Iucha provided a tip in the FAQ for how to compile MaraDNS on 
OpenBSD. 

Roy Arends (one of the BIND developers, as it turns out) found a 
serious security problem with MaraDNS, where MaraDNS would answer 
answers, and pointed it out to me. 

Code used as the basis for the psudo-random-number generator was 
written by Vincent Rijmen, Antoon Bosselaers, and Paulo Barreto. I 
appreciate these programmers making the code public domain, which is 
the only license under which I can add code to MaraDNS under. 

Ross Johnson and others have made a Win32 port of the Pthreads library; 
this has made a native win32 port of MaraDNS possible. 

I also appreciate the work of Dr. Brian Gladman and Fritz Schneider, 
who have both written independent implementations of AES from which I 
obtained test vectors. With the help of their hard work, I was able to 
discover a subtle security problem that previous releases of MaraDNS 
had.  

