# 2020 Updates

I have updated things so that the Git version of MaraDNS is the 
authoritative “One source of truth” for MaraDNS’s source code.
MaraDNS’s Git tree is now hosted at 
[GitHub](https://github.com/samboy/MaraDNS),
[GitLab](https://gitlab.com/maradns/maradns), 
[Bitbucket](https://bitbucket.org/maradns/maradns/),
and 
[SourceHut](https://git.sr.ht/~samiam/MaraDNS)
(Please use GitHub for bug reports).  The Git code is
converted in to tarballs (with full Git history) which can be
downloaded at [Sourceforge](https://sourceforge.net/projects/maradns/)
and [MaraDNS’s web page](https://maradns.samiam.org/download.html).

# ABOUT

   MaraDNS is a small and lightweight cross-platform open-source DNS
   server. The server is remarkably easy to configure for someone
   comfortable editing text configuration files. MaraDNS is released under
   a BSD license.

   I wrote MaraDNS while I was a college student and a travelling English
   teacher during the first 2000s decade. Now that I’m working as
   a professional software developer, I have much less time to devote
   to MaraDNS.

   Since MaraDNS is open source, there is nothing stopping anyone from 
   forking this repository; I ask such users to please not call any such 
   forks “MaraDNS”.

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

   There are no “supported OSes” for MaraDNS.  I currently use CentOS 7
   to develop MaraDNS, and a Windows XP virtual machine to make the
   Windows binary.

   Distribution-specific issues should be forwarded to the bug processing
   system for your distribution.

## Important note for Windows users

   Users of Microsoft Windows are better off downloading a prebuilt Windows
   binary: http://maradns.samiam.org/download.html
   Be sure to download the file with the .zip extension.

## What is DNS

   The internet uses numbers, not names, to find computers. DNS is the
   internet's directory service: It takes a name, like "www.maradns.org",
   and converts that name in to an "IP" number that your computer can use
   to connect to www.maradns.org.

   DNS is one of these things many take for granted that is essential to
   using today's internet. Without DNS, the internet breaks. It is
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
   contributions from 2001 until 2010. MaraDNS 2.0 is the final release
   that will be made without significant financial support being made.
   Security and other critical bugs are still taken care of, but there is
   no guarantee of any technical support above and beyond that.

## Overview

   MaraDNS 2.0 consists of two primary components: A UDP-only
   authoritative DNS server for hosting domains, and a UDP and TCP-capable
   recursive DNS server for finding domains on the internet. MaraDNS'
   recursive DNS server is called Deadwood, and it shares no code with
   MaraDNS' authoritative DNS server.

   In more detail: MaraDNS has one daemon, the authoritative daemon
   (called "maradns"), that provides information to recursive DNS servers
   on the internet, and another daemon, the recursive daemon (called
   "Deadwood"), that gets DNS information from the internet for web
   browsers and other internet clients.

   A simplified way to look at it: MaraDNS puts your web page on the
   Internet; Deadwood looks for web pages on the Internet.

   Deadwood has its own webpage and release schedule. When new MaraDNS
   releases are made, they bundle the current stable version of Deadwood
   in the source code tree; the build scripts compile both MaraDNS and
   Deadwood at the same time.

   Since MaraDNS' authoritative daemon does not support TCP, MaraDNS
   includes a separate DNS-over-TCP server called "zoneserver" that
   supports both standard DNS-over-TCP and DNS zone transfers.

   Neither MaraDNS nor the UNIX version of Deadwood have support for
   daemonization; this is handled by a separate program included with
   MaraDNS called Duende. Deadwood's Windows port, on the other hand,
   includes support for running as a Windows service.

   MaraDNS also includes a simple DNS querying tool called "askmara" and a
   number of other miscellaneous tools: Scripts for processing MaraDNS'
   documentation, a simple webpage password generator, some Unicode
   conversion utilities, scripts for building and installing MaraDNS,
   automated SQA tests, etc.

   MaraDNS is a native UNIX program with a partial Windows port. Deadwood,
   MaraDNS' recursive resolver, is a fully cross-platform application with
   a full Windows port.

   MaraDNS 2.0 has full (albeit not fully tested) IPv6 support.

## Internals

   MaraDNS 2.0's authoritative server uses code going all the way back 
   to 2001. The core DNS-over-UDP server has a number of components,
   including two different zone file parsers, a mararc parser, a secure
   random number generator, and so on.

   MaraDNS is written entirely in C. No objective C nor C++ classes are
   used in MaraDNS' code.

   MaraDNS 2.0's "Deadwood" recursive server was started in 2007 and has
   far cleaner code. Its random number generator, for example, uses a
   smaller, simpler, and more secure cryptographic algorithm; its
   configuration file parser uses a finite state machine interpreter; its
   handling of multiple simultaneous pending connections is done using
   select() and a state machine instead of with threads.

   Deadwood's source code can be browsed online, and there are a
   number of documents describing its internals available.

## Other DNS servers

   The landscape of open-source DNS servers has changed greatly since 2001
   when MaraDNS was started. There are now a number of different DNS
   servers still actively developed and maintained: BIND, Power DNS,
   NSD/Unbound, as well as MaraDNS. DjbDNS is no longer being updated and
   the unofficial forks have limited support; notably it took nearly five
   months for someone to come up with a patch for CVE-2012-1191.

   MaraDNS' strength is that it's a remarkably small, lightweight, easy to
   configure, and mostly cross-platform DNS server. Deadwood is a tiny DNS
   server with full recursion support, perfect for embedded systems.

   MaraDNS' weakness is that it does not have some features other DNS
   servers have. For example, while Deadwood has the strongest spoof
   protection available without cryptography, it does not have support for
   DNSSEC.

   As another example, MaraDNS does not have full zone transfer support;
   while MaraDNS can both serve zones and receive external zone files from
   other DNS servers, MaraDNS needs to be restarted to update its database
   of DNS records.

## MaraDNS' future

   *2019 update*: There have been been some changes in my personal life
   which make it possible for me to work on MaraDNS and Deadwood again
   for a couple of hours each week.  

   My plans for MaraDNS in 2019 is to fix at least two bugs (I have already
   fixed one and released Deadwood 3.2.14), and to add at least one new
   feature to MaraDNS. While I now have a little more time to look at
   non-critical bugs and to add small features, I do not have enough
   free time for MaraDNS to do significant overhauls (e.g. DNSSEC).

   It would require some large company or government agency paying me a
   full-time living wage to add significant new features to MaraDNS. 

   Feel free to fork this repository, but please do not name your fork
   "MaraDNS".

