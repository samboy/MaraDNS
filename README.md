# What is MaraDNS

MaraDNS is a free open-source computer program written by Sam Trenholme.

MaraDNS implements the Domain Name System (DNS), an essential internet
service. MaraDNS is open source software: This means that anyone is
free to download, use, and modify the program free of charge, as per
its license.

People like MaraDNS because it’s small, lightweight, easy to set up,
and remarkably secure. It’s also cross platform — the program runs
both in Windows and in UNIX clones.

# 2021 Updates

Deadwood has a new parameter: `source_ip4`.  This optional parameter
is used to specify the source IP when sending queries upstream.  The
majority of users should be able to leave this untouched; this is for
cases when Deadwood is multi-homed and we need to specify which IP
to use when querying root or upstream DNS servers.

One line change to zoneserver.c to make it work better with systemd.

Synthetic IP generator example added to `coLunacyDNS`

# 2020 Updates

I have updated things so that the Git version of MaraDNS is the 
authoritative “One source of truth” for MaraDNS’s source code.
MaraDNS’s Git tree is now hosted at 
[GitHub](https://github.com/samboy/MaraDNS),
[GitLab](https://gitlab.com/maradns/maradns), 
[Bitbucket](https://bitbucket.org/maradns/maradns/),
[SourceForge](https://sourceforge.net/p/maradns-git/code/),
and 
[SourceHut](https://git.sr.ht/~samiam/MaraDNS)
(Please use GitHub for bug reports).  The Git code is,
every time a new MaraDNS release is made,
converted in to tarballs (with full Git history) which can be
downloaded at [Sourceforge](https://sourceforge.net/projects/maradns/)
and [MaraDNS’s web page](https://maradns.samiam.org/download.html).

I have added block list support to Deadwood, to allow a large list
of host names to be blocked.

I have created a new service: `coLunacyDNS`, a simple Lua-based DNS server
which can return IPv4 (`A`) and IPv6 (`AAAA`) DNS records.  It has the
ability to query other DNS servers, and customize the answer given to
the client based on the contents of a Lua script.  All programs have IPv6
support in Linux as well as *NIX clones, and the Windows 32-bit binary of
`coLunacyDNS` has IPv6 support.

# ABOUT

MaraDNS is a small and lightweight cross-platform open-source DNS
server. The server is remarkably easy to configure for someone
comfortable editing text configuration files. MaraDNS is released under
a BSD license.

I wrote MaraDNS while I was a college student and a travelling English
teacher during the first 2000s decade. 

Now that I have been furloughed during the COVID-19 pandemic, I have
been actively adding new features to MaraDNS, most notably the new
`coLunacyDNS` service which uses Lua to customize DNS replies.

## Table of contents

* Supported OSes
* Important note for Windows users
* What is DNS
* MaraDNS' History
* Overview
* Internals
* Other DNS servers
* MaraDNS' future

## Supported OSes

   There are no “supported OSes” for MaraDNS.  I currently use Ubuntu 20.04
   to develop MaraDNS, and a Windows XP virtual machine to make the
   Windows binary.

   Distribution-specific issues should be forwarded to the bug processing
   system for your distribution.

## Important note for Windows users

   Users of Microsoft Windows are better off downloading a prebuilt Windows
   binary: http://maradns.samiam.org/download.html (or, look in the
   folder `maradns-win32` here) 
   Be sure to download the file with the .zip extension.

   Only Deadwood and coLunacyDNS binaries are provided.  

   The Deadwood has passed Y2038 tests in Windows 10.

## What is DNS

   The internet uses numbers, not names, to find computers. DNS is the
   internet’s directory service: It takes a name, like “www.maradns.org”,
   and converts that name in to an “IP” number that your computer can use
   to connect to www.maradns.org.

   DNS is one of these things many take for granted that is essential to
   using today’s internet. Without DNS, the internet breaks. It is
   critical that a DNS server keeps the internet working in a secure and
   stable manner.

## MaraDNS' History

   MaraDNS was started in 2001 in response to concerns that there were
   only two freely available DNS servers (BIND and DjbDNS) at the time.
   MaraDNS 1.0 was released in mid-2002, MaraDNS 1.2 was released in late
   2005, and MaraDNS 2.0 was released in the fall of 2010.

   MaraDNS 1.0 used a recursive DNS server that was implemented rather
   quickly and had difficult-to-maintain code. This code was completely
   rewritten for the MaraDNS 2.0 release, which now uses a separate
   recursive DNS server.

   MaraDNS was fully maintained and actively developed without needing
   contributions from 2001 until 2010, and in 2020 during the COVID-19
   crisis.

## Overview

   MaraDNS 3.5 consists of two primary components: A UDP-only
   authoritative DNS server for hosting domains, and a UDP and TCP-capable
   recursive DNS server for finding domains on the internet. MaraDNS’
   recursive DNS server is called Deadwood, and it shares no code with
   MaraDNS’ authoritative DNS server.

   Newly added during the COVID-19 crisis is “coLunacyDNS”, a Lua-based
   name server which uses a combination of C (for the heavy lifting of
   binding to DNS sockets, processing DNS requests, and handling pending
   replies from upstream DNS servers) and Lua (for deciding how to respond
   to a given query) to have both performance and flexibility.

   In more detail: MaraDNS has one daemon, the authoritative daemon
   (called “maradns”), that provides information to recursive DNS servers
   on the internet, and another daemon, the recursive daemon (called
   “Deadwood”), that gets DNS information from the internet for web
   browsers and other internet clients.

   A simplified way to look at it: MaraDNS puts your web page on the
   Internet; Deadwood looks for web pages on the Internet.

   Since MaraDNS’ authoritative daemon does not support TCP, MaraDNS
   includes a separate DNS-over-TCP server called “zoneserver” that
   supports both standard DNS-over-TCP and DNS zone transfers.

   Neither MaraDNS nor the UNIX version of Deadwood have support for
   daemonization; this is handled by a separate program included with
   MaraDNS called Duende. Deadwood's Windows port, on the other hand,
   includes support for running as a Windows service.

   MaraDNS also includes a simple DNS querying tool called “askmara” and a
   number of other miscellaneous tools: Scripts for processing MaraDNS'
   documentation, a simple webpage password generator, some Unicode
   conversion utilities, scripts for building and installing MaraDNS,
   automated SQA tests, etc.

   MaraDNS is a native UNIX program with a partial Windows port. Deadwood,
   MaraDNS' recursive resolver, is a fully cross-platform application with
   a full Windows port.

   MaraDNS 2.0 has full (albeit not fully tested) IPv6 support.

## Internals

   MaraDNS 3.5’s authoritative server uses code going all the way back 
   to 2001. The core DNS-over-UDP server has a number of components,
   including two different zone file parsers, a mararc parser, a secure
   random number generator, and so on.

   MaraDNS is written entirely in C. No objective C nor C++ classes are
   used in MaraDNS’ code.

   MaraDNS 2.0’s “Deadwood” recursive server was started in 2007 and has
   far cleaner code. Its random number generator, for example, uses a
   smaller, simpler, and more secure cryptographic algorithm; its
   configuration file parser uses a finite state machine interpreter; its
   handling of multiple simultaneous pending connections is done using
   select() and a state machine instead of with threads.

   Deadwood’s source code can be browsed online, and there are a
   number of documents describing its internals available.

## Other DNS servers

   The landscape of open-source DNS servers has changed greatly since 2001
   when MaraDNS was started. There are now a number of different DNS
   servers still actively developed and maintained: BIND, Power DNS,
   NSD/Unbound, as well as MaraDNS. DjbDNS is no longer being updated and
   the unofficial forks have limited support; notably it took nearly five
   months for someone to come up with a patch for CVE-2012-1191.

   MaraDNS’ strength is that it’s a remarkably small, lightweight, easy to
   configure, and mostly cross-platform DNS server. Deadwood is a tiny DNS
   server with full recursion support, perfect for embedded systems.

   MaraDNS’ weakness is that it does not have some features other DNS
   servers have. For example, while Deadwood has the strongest spoof
   protection available without cryptography, it does not have support for
   DNSSEC.

   As another example, MaraDNS does not have full zone transfer support;
   while MaraDNS can both serve zones and receive external zone files from
   other DNS servers, MaraDNS needs to be restarted to update its database
   of DNS records.

## MaraDNS’ future

   During the COVID-19 crisis, I had some free time, so I decided to add
   skills to my resume by writing `coLunacyDNS`, a Lua-based DNS server
   (which shares some code with Deadwood, but is configured with Lua).
   The skills I acquired doing this got me the current job I have
   as an embedded Lua developer.  Since I was able to find work again,
   MaraDNS is on the back burner again.

# Y2038 statement

MaraDNS is fully Y2038 compliant on systems with a 64-bit time_t.

Deadwood, in addition, for its Windows 32-bit binary, uses Windows
filetime to generate internal timestamps; filetime stamps will not run
over until the year 30827 or so.  Deadwood, when compiled under Windows,
uses a 32-bit `stat()` in one piece of code, but Y2038 testing does not
indicate any issues with this code.

coLunacyDNS, likewise, uses Windows filetime for timestamps with its
Win32 binary.

Both Deadwood and coLunacyDNS make some effort to generate accurate
timestamps on *NIX systems with a 32-bit time_t until later than
2106; this code assumes that 32-bit systems will have the time
stamp “wrap around” after 2038 but still have the 32-bit time be 
updated.
