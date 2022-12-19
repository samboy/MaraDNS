# MaraDNS reference manual

This is a reference manual with all of MaraDNS'
manual pages

The following manuals are here:
* Deadwood man page
* askmara man page
* blockHashMake man page
* blockHashRead man page
* coLunacyDNS man page
* csv1 man page
* csv2 man page
* csv2_txt man page
* duende man page
* fetchzone man page
* getzone man page
* maradns man page
* mararc man page
* zoneserver man page

# Deadwood man page

# NAME

Deadwood - A fully recursive caching DNS resolver 

# DESCRIPTION

Deadwood is a fully recursive DNS cache. This is a DNS server with the 
following features: 

* Full support for both DNS recursion and DNS forwarding caching

* Small size and memory footprint suitable for embedded systems

* Simple and clean codebase

* Secure design

* Spoof protection: Strong cryptography used to determine the Query ID 
  and source port

* Ability to read and write the cache to a file

* Dynamic cache that deletes entries not recently used

* Ability to use expired entries in the cache when it is impossible to 
  contact upstream DNS servers.

* IPv6 support can be compiled in if desired

* Both DNS-over-UDP and DNS-over-TCP are handled by the same daemon

* Built-in dnswall functionality

* The ability to assign names to IPv4 IPs as specified in one's 
  dwood3rc file.

* The ability to quickly load and use a large blocklist of names to 
  not resolve.

# COMMAND LINE ARGUMENTS

Deadwood has a single optional command line argument: The location of 
the configuration file that Deadwood uses, specified with the "-f" 
flag. If this is not defined, Deadwood uses the file "/etc/dwood3rc" as 
the configuration file. 

In other words, invoking Deadwood as **Deadwood** will cause Deadwood 
to use /etc/dwood3rc as the configuration file; invoking Deadwood as 
**Deadwood -f foobar** will cause Deadwood to use the file "foobar" in 
the current working directory (the directory one is in when starting 
Deadwood) as the configuration file. 

# CONFIGURATION FILE FORMAT

The Deadwood configuration file is modeled after Python 2's syntax. 
However, since Python 2 is no longer supported by the Python Software 
Foundation, and since Deadwood configuration files can sometimes fail 
to parse in Python 3, Deadwood does not strictly follow Python 2 
syntax. 

In particular, leading whitespace is allowed in Deadwood configuration 
files. 

# PARAMETER TYPES

Deadwood has three different parameter types: 

* Numeric parameters. Numeric parameters must not be surrounded by 
  quotes, such as this example:

```
filter_rfc1918 = 0 
```

If a numeric parameter is surrounded by quotes, the error message 
"Unknown dwood3rc string parameter" will appear. 

* String parameters. String parameters must be surrounded by quotes, 
  such as in this example:

```
bind_address = "127.0.0.1" 
```

* Dictionary parameters. All dictionary parameters must be initialized 
  before use, and dictionary parameters must have both the 
  dictionary index and the value for said index surrounded by 
  quotes, such as in this example:

```
upstream_servers = {} 
upstream_servers["."]="8.8.8.8, 8.8.4.4" 
```

All dwood3rc parameters *except* the following are numeric parameters: 

* bind_address (string)

* blocked_hosts_hash_file (string)

* cache_file (string)

* chroot_dir (string)

* ip4 (dictionary)

* ip6 (dictionary)

* ip_blacklist (string)

* ip_blocklist (string)

* ipv4_bind_addresses (string)

* random_seed_file (string)

* recursive_acl (string)

* root_servers (dictionary)

* source_ip4 (string)

* upstream_servers (dictionary)

# SUPPORTED PARAMETERS

The Deadwood configuration file supports the following parameters: 

## allow_block_hash_zero_key

If this numeric parameter has a value of 1, we allow a blocked hosts 
hash file to have a key which is 0. Otherwise, if a blocked hosts file 
has a 0 key, Deadwood will terminate when loading the blocked hosts 
file with the error message "Zero key block hash not allowed by 
default". 

There is a security risk if we allow a blocked hosts file to have a 0 
key: An attacker with access to a recursive instance of Deadwood could 
have Deadwood use more resources than necessary if they know the block 
hash file being used. Since the block hash file is read only, hash 
flooding attacks are *not* possible, but an attacker could form queries 
which use more resources to resolve as not being present in the block 
hash. 

Deadwood should *never* be an open recursor and this attack is limited 
in scope. But be aware of the risks before setting this parameter to 1. 

## bind_address

This is the IP (or possibly IPv6) address we bind to. 

## blocked_hosts_hash_file

A blocked hosts hash file allows Deadwood to block a large number of 
host names while using relatively little memory: While using a list of 
over 200,000 hosts to block in a `dwood3rc` file uses over 200 
megabytes of memory, the same list in a block hash file uses only 7 
megabytes of memory. 

The block hash file is in a special binary format so that a large 
number of host names can be blocked quickly using little memory. 

This parameter, if set, is the filename for a block hash file. The file 
will be located in the directory set by `chroot_dir` (usually, 
`/etc/deadwood`). The file name can have lower case letters, the '-' 
character (dash), the '_' character (underscore), the '.' character 
(dot or period), and the '/' character (slash). If the file name has 
the '.' character (dot/period) in it, it can not have a '/' (slash) 
after the '.' (dot). 

The `blockHashMake` program generates the block hash file. The contents 
of a block hash file can be looked at and read using the 
`blockHashRead` program. See the man pages **blockHashMake (1)** and 
**blockHashRead (1)** for more details. 

Block hash files have wildcard support. For example, if "example.com" 
is in the block hash file, then deadwood will block "example.com", 
"anyname.example.com", "anything.else.example.com", 
"12345.example.com", and so on. 

Note that wildcards only work for domain names which are one, two, or 
three labels long in the database. If "really.bad.example.com" is in 
the database, "buzz.really.bad.example.com" will *not* match, since 
"really.bad.example.com" has four (i.e. more than three) labels. 

One usable block hash file is available at the repo at 
https://github.com/samboy/BlockHash 

## cache_file

This is the filename of the file used for reading and writing the cache 
to disk; this string can have lowercase letters, the '-' symbol, the 
'_' symbol, and the '/' symbol (for putting the cache in a 
subdirectory). All other symbols become a '_' symbol. 

This file is read and written as the user Deadwood runs as. 

## chroot_dir

This is the directory the program will run from. 

## deliver_all

This affects behavior in Deadwood 2.3, but has no effect in Deadwood 3. 
This variable is only here so Deadwood 2 rc files can run in Deadwood 
3. 

## dns_port

This is the port Deadwood binds to and listens on for incoming 
connections. The default value for this is the standard DNS port: port 
53 

## filter_rfc1918

When this has a value of 1, a number of different IP ranges are not 
allowed to be in DNS A replies: 

* 192.168.x.x

* 172.[16-31].x.x

* 10.x.x.x

* 127.x.x.x

* 169.254.x.x

* 224.x.x.x

* 0.0.x.x

If one of the above IPs is detected in a DNS reply, and filter_rfc1918 
has a value of 1, Deadwood will return a synthetic "this host does not 
reply" response (a SOA record in the NS section) instead of the A 
record. 

The reason for this is to provide a "dnswall" that protects users for 
some kinds of attacks, as described at http://crypto.stanford.edu/dns/ 

Please note that Deadwood only provides IPv4 "dnswall" functionality 
and does not help protect against IPv6 answers. If protection against 
certain IPv6 AAAA records is needed, either disable all AAAA answers by 
setting reject_aaaa to have a value of 1, or use an external program to 
filter undesired IPv4 answers (such as the dnswall program). 

The default value for this is 1 

## handle_noreply

When this is set to 0, Deadwood sends no reply back to the client (when 
the client is a TCP client, Deadwood closes the TCP connection) when a 
UDP query is sent upstream and the upstream DNS never sends a reply. 

When this is set to 1, Deadwood sends a SERVER FAIL back to the client 
when a UDP query is sent upstream and the upstream DNS never sends a 
reply. 

The default value for this is 1 

## handle_overload

When this has a value of 0, Deadwood sends no reply when a UDP query is 
sent and the server is overloaded (has too many pending connections); 
when it has a value of 1, Deadwood sends a SERVER FAIL packet back to 
the sender of the UDP query. The default value for this is 1. 

## hash_magic_number

This used to be used for Deadwood's internal hash generator to keep the 
hash generator somewhat random and immune to certain types of attacks. 
In Deadwood 3.0, entropy for the hash function is created by looking at 
the contents of /dev/urandom (secret.txt on Windows machines) and the 
current timestamp. This parameter is only here so older configuration 
files do not break in Deadwood 3.0. 

## ip4

This is a dictionary variable which allows us to have given names 
resolve to bogus IPv4 addresses. Here, we have the name "maradns.foo" 
resolve to "10.10.10.10" and "kabah.foo" resolve to "10.11.11.11", 
regardless of what real values these DNS records may have:

```
ip4 = {} 
ip4["maradns.foo."] = "10.10.10.10" 
ip4["kabah.foo."] = "10.11.11.11" 
```

Note that a given name can only resolve to a single IP, and that 
the records have a fixed TTL of 30 seconds. 

It is also possible to use ip4 to set up a blocklist by using "X" for 
the IP. When this is done, an IPv4 request for a given hostname results 
in a synthetic "this name does not exist" response. In addition, the 
corresponding IPv6 request will *also* return that "name does not 
exist" reply. For example:

```
ip4 = {} 
ip4["evil.example.com."] = "X" 
```

Here, both the IPv4 *and* the IPv6 query for "evil.example.com" 
will not resolve in Deadwood. 

## ip6

Like ip4, ip6 uses a similar syntax to have bogus IPv6 addresses. We 
don't use standard notation for IPv6 addresses. Instead, we we use 
32-character hex addresses (case insensitive); to make it easier to 
count long strings of "0"s, the "_" acts like a 0; we also ignore "-" 
(dash) and " " (space) in ip6 strings. Here is an example:

```
ip6 = {} 
ip6["maradns.foo."] = "20010db84d617261444e530000001234" 
ip6["kabah.foo."] = "2001-0DB8-4D61-7261 444E-5300-__00-2345" 
```

## ip_blocklist

This is a list of IPs that we do not allow to be in the answer to a DNS 
request. The reason for this is to counteract the practice some ISPs 
have of converting a "this site does not exist" DNS answer in to a page 
controlled by the ISP; this results in possible security issues. 

This parameter only accepts individual IPs, and does not use netmasks. 

Note that this parameter used to be called ip_blacklist; while the 
ip_blacklist name still works as before, ip_blocklist is the current 
name. 

## maradns_uid

The user-id Deadwood runs as. This can be any number between 10 and 
16777216; the default value is 707 (a system UID which should be 
unused). This value is not used on Windows systems. 

## maradns_gid

The group-id Deadwood runs as. This can be any number between 10 and 
16777216; the default value is 707. This value is not used on Windows 
systems. 

## max_ar_chain

Whether resource record rotation is enabled. If this has a value of 1, 
resource record rotation is enabled, otherwise resource record rotation 
is disabled. 

Resource record rotation is usually desirable, since it allows DNS to 
act like a crude load balancer. However, on heavily loaded systems it 
may be desirable to disable it to reduce CPU usage. 

The reason for the unusual name for this variable is to retain 
compatibility with MaraDNS mararc files. 

The default value is 1: Resource record rotation enabled. 

## max_inflights

The maximum number of simultaneous clients we process at the same time 
for the same query. 

If, while processing a query for, say, "example.com.", another DNS 
client sends to Deadwood another query for example.com, instead of 
creating a new query to process example.com, Deadwood will attach the 
new client to the same query that is already "in flight", and send a 
reply to both clients once we have an answer for example.com. 

This is the number of simultaneous clients a given query can have. If 
this limit is exceeded, subsequents clients with the same query are 
refused until an answer is found. If this has a value of 1, we do not 
merge multiple requests for the same query, but give each request its 
own connection. 

The default value is 8. 

## max_ttl

The maximum amount of time we will keep an entry in the cache, in 
seconds (also called "Maximum TTL"). 

This is the longest we will keep an entry cached. The default value for 
this parameter is 86400 (one day); the minimum value is 300 (5 minutes) 
and the maximum value this can have is 7776000 (90 days). 

The reason why this parameter is here is to protect Deadwood from 
attacks which exploit there being stale data in the cache, such as the 
"Ghost Domain Names" attack. 

## maximum_cache_elements

The maximum number of elements our cache is allowed to have. This is a 
number between 32 and 16,777,216; the default value for this is 1024. 
Note that, if writing the cache to disk or reading the cache from disk, 
higher values of this will slow down cache reading/writing. 

The amount of memory each cache entry uses is variable depending on the 
operating system used and the size of memory allocation pages assigned. 
In Windows XP, for example, each entry uses approximately four 
kilobytes of memory and Deadwood has an overhead of approximately 512 
kilobytes. So, if there are 512 cache elements, Deadwood uses 
approximately 2.5 megabytes of memory, and if there are 1024 cache 
elements, Deadwood uses approximately 4.5 megabytes of memory. Again, 
these numbers are for Windows XP and other operating systems will have 
different memory allocation numbers. 

Please note that, as of Deadwood 3.5.0004, is is no longer needed to 
increase maximum_cache_elements to store upstream_server and 
root_server entries. 

## maxprocs

This is the maximum number of pending remote UDP connections Deadwood 
can have. The default value for this is 1024. 

## max_tcp_procs

This is the number of allowed open TCP connections. Default value: 8 

## min_ttl

The minimum amount of time we will keep an entry in the cache, in 
seconds (also called "Minimum TTL"). 

## num_retries

The number of times we retry to send a query upstream before giving up. 
If this is 0, we only try once; if this is 1, we try twice, and so on, 
up to 32 retries. Note that each retry takes timeout_seconds seconds 
before we retry again. Default value: 5 

## ns_glueless_type

The RR type we send to resolve glueless records. This should always be 
1 (A; i.e. IPv4 DNS servers). This should *never* be ANY, see RFC8482. 
This should not be any other value, since only A glueless NS referrals 
have ever been tested with Deadwood. 

The reason why this exists is because, often times in DNS, we get a 
reply like "The name server for this foo.example.com and no I do not 
have the IP for foo.example.com" when recursively solving an answer. 
So, the question is this: Is foo.example.com an IPv4 DNS server, an 
IPv6 server, or both? 

On today's internet (mid-2020, during the COVID-19 crisis), the answer 
is that the name server in question is only on the IPv4 Internet. IPv6 
is now mainstream (e.g. my ISP gives me a /64 and I no longer have to 
tunnel through he.net to try out IPv6), but most servers are still IPv4 
only (e.g. my domains are only on IPv4, and amazon.com does not have an 
IPv6 address). 

The reason this parameter exists is because, when I was writing the 
recursive code for Deadwood, I was thinking of a future where IPv6 is 
prevalent enough that we would have DNS servers with only IPv6 
addresses, and glueless NS referrals (the "foo.example.com" case above) 
would point to servers with IPv6, but not IPv4, addresses. 

That day may yet come, but preparing Deadwood to still be a viable DNS 
server when that day comes will require more than changing the RR type 
sent when it gets a glueless NS referral. 

## random_seed_file

This is a file that contains random numbers, and is used as a seed for 
the cryptographically strong random number generator. Deadwood will try 
to read 256 bytes from this file (the RNG Deadwood uses can accept a 
stream of any arbitrary length). 

Note that the hash compression function obtains some of its entropy 
before parsing the mararc file, and is hard-coded to get entropy from 
/dev/urandom (secret.txt on Windows systems). Most other entropy used 
by Deadwood comes from the file pointed to by random_seed_file. 

## recurse_min_bind_port

The lowest numbered port Deadwood is allowed to bind to; this is a 
random port number used for the source port of outgoing queries, and is 
not 53 (see dns_port above). This is a number between 1025 and 32767, 
and has a default value of 15000. This is used to make DNS spoofing 
attacks more difficult. 

## recurse_number_ports

The number of ports Deadwood binds to for the source port for outgoing 
connections; this is a power of 2 between 256 and 32768. This is used 
to make DNS spoofing attacks more difficult. The default value is 4096. 

## recursive_acl

This is a list of who is allowed to use Deadwood to perform DNS 
recursion, in "ip/mask" format. Mask must be a number between 0 and 32 
(for IPv6, between 0 and 128). For example, "127.0.0.1/8" allows local 
connections. 

## reject_aaaa

If this has a value of 1, a bogus SOA "not there" reply is sent 
whenever an AAAA query is sent to Deadwood. In other words, every time 
a program asks Deadwood for an IPv6 IP address, instead of trying to 
process the request, when this is set to 1, Deadwood pretends the host 
name in question does not have an IPv6 address. 

This is useful for people who aren't using IPv6 but use applications 
(usually *NIX command like applications like "telnet") which slow 
things down trying to find an IPv6 address. 

This has a default value of 0. In other words, AAAA queries are 
processed normally unless this is set. 

## reject_mx

When this has the default value of 1, MX queries are silently dropped 
with their IP logged. A MX query is a query that is only done by a 
machine if it wishes to be its own mail server sending mail to machines 
on the internet. This is a query an average desktop machine (including 
one that uses Outlook or another mail user agent to read and send 
email) will never make. 

Most likely, if a machine is trying to make a MX query, the machine is 
being controlled by a remote source to send out undesired "spam" email. 
This in mind, Deadwood will not allow MX queries to be made unless 
reject_mx is explicitly set with a value of 0. 

Before disabling this, please keep in mind that Deadwood is optimized 
to be used for web surfing, not as a DNS server for a mail hub. In 
particular, the IPs for MX records are removed from Deadwood's replies 
and Deadwood needs to perform additional DNS queries to get the IPs 
corresponding to MX records, and Deadwood's testing is more geared for 
web surfing (almost 100% A record lookup) and not for mail delivery 
(extensive MX record lookup). 

## reject_ptr

If this has a value of 1, a bogus SOA "not there" reply is sent 
whenever a PTR query is sent to Deadwood. In other words, every time a 
program asks Deadwood for "reverse DNS lookup" -- the hostname for a 
given IP address -- instead of trying to process the request, when this 
is set to 1, Deadwood pretends the IP address in question does not have 
a hostname. 

This is useful for people who are getting slow DNS timeouts when trying 
to perform a reverse DNS lookups on IPs. 

This has a default value of 0. In other words, PTR queries are 
processed normally unless this is set. 

## resurrections

If this is set to 1, Deadwood will try to send an expired record to the 
user before giving up. If it is 0, we don't. Default value: 1 

## rfc8482

If this is set to 1, Deadwood will not allow ANY or HINFO queries, 
sending a RFC8482 response if one is given to Deadwood. If this is 0, 
ANY and HINFO queries are allowed. Default value: 1 

If ANY queries are enabled, since Deadwood does not support EDNS nor 
DNS-over-TCP for upstream queries, Deadwood may not get meaningful 
replies from upstream servers. 

## root_servers

This is a list of root servers; its syntax is identical to 
upstream_servers (see below). This is the type of DNS service ICANN, 
for example, runs. These are servers used that do not give us complete 
answers to DNS questions, but merely tell us which DNS servers to 
connect to to get an answer closer to our desired answer. 

As of Deadwood 3.5.0004, it is no longer needed to increase 
maximum_cache_elements to store root_server entries. 

Please be aware that this parameter is deprecated. While there are no 
plans to remove this parameter, Deadwood is no longer being updated to 
resolve DNS resolution issues when using root_servers to resolve names 
on the internet. Please use upstream_servers instead. 

## source_ip4

With certain complicated networks, it may be desirable to set the 
source IP of queries sent to upstream or root DNS servers. If so, set 
this parameter to have the dotted decimal IPv4 address to use when 
sending IPv4 queries to an upstream DNS server. 

Use this parameter with caution; Deadwood can very well become 
non-functional if one uses a source IPv4 address which Deadwood is not 
bound to. 

## tcp_listen

In order to enable DNS-over-TCP, this variable must be set and have a 
value of 1. Default value: 0 

## timeout_seconds

This is how long Deadwood will wait before giving up and discarding a 
pending UDP DNS reply. The default value for this is 1, as in 1 second, 
unless Deadwood was compiled with FALLBACK_TIME enabled. 

## timeout_seconds_tcp

How long to wait on an idle TCP connection before dropping it. The 
default value for this is 4, as in 4 seconds. 

## ttl_age

Whether TTL aging is enabled; whether entries in the cache have their 
TTLs set to be the amount of time the entries have left in the cache. 

If this has a value of 1, TTL entries are aged. Otherwise, they are 
not. The default value for this is 1. 

## upstream_port

This is the port Deadwood uses to connect or send packets to the 
upstream servers. The default value for this is 53; the standard DNS 
port. 

## upstream_servers

This is a list of DNS servers that the load balancer will try to 
contact. This is a *dictionary variable* (array indexed by a string 
instead of by a number) instead of a simple variable. Since 
upstream_servers is a dictionary variable, it needs to be initialized 
before being used. 

Deadwood will look at the name of the host that it is trying to find 
the upstream server for, and will match against the longest suffix it 
can find. 

For example, if someone sends a query for "www.foo.example.com" to 
Deadwood, Deadwood will first see if there is an upstream_servers 
variable for "www.foo.example.com.", then look for "foo.example.com.", 
then look for "example.com.", then "com.", and finally ".". 

Here is an example of upstream_servers:

```
upstream_servers = {} # Initialize dictionary variable 
upstream_servers["foo.example.com."] = "192.168.42.1" 
upstream_servers["example.com."] = "192.168.99.254" 
upstream_servers["."] = "10.1.2.3, 10.1.2.4" 
```

In this example, anything ending in "foo.example.com" is resolved 
by the DNS server at 192.168.42.1; anything else ending in 
"example.com" is resolved by 192.168.99.254; and anything not ending in 
"example.com" is resolved by either 10.1.2.3 or 10.1.2.4. 

**Important:** the domain name upstream_servers points to must end in a 
"." character. This is OK:

```
upstream_servers["example.com."] = "192.168.42.1" 
```

But this is **not** OK:

```
upstream_servers["example.com"] = "192.168.42.1" 
```

The reason for this is because BIND engages in unexpected 
behavior when a host name doesn't end in a dot, and by forcing a dot at 
the end of a hostname, Deadwood doesn't have to guess whether the user 
wants BIND's behavior or the "normal" behavior. 

If neither root_servers nor upstream_servers are set, Deadwood sets 
upstream_servers to use the https://quad9.net servers, as follows:

```
9.9.9.9 
149.112.112.112 
```

Please note that, as of Deadwood 3.5.0004, is is no longer needed to 
increase maximum_cache_elements to store upstream_server entries. 

## verbose_level

This determines how many messages are logged on standard output; larger 
values log more messages. The default value for this is 3. 

# ip/mask format of IPs

Deadwood uses a standard ip/netmask formats to specify IPs. An ip is in 
dotted-decimal format, e.g. "10.1.2.3" (or in IPv6 format when IPv6 
support is compiled in). 

The netmask is used to specify a range of IPs. The netmask is a single 
number between 1 and 32 (128 when IPv6 support is compiled in), which 
indicates the number of leading "1" bits in the netmask. 

**10.1.1.1/24** indicates that any ip from 10.1.1.0 to 10.1.1.255 will 
match. 

**10.2.3.4/16** indicates that any ip from 10.2.0.0 to 10.2.255.255 
will match. 

**127.0.0.0/8** indicates that any ip with "127" as the first octet 
(number) will match. 

The netmask is optional, and, if not present, indicates that only a 
single IP will match. 

# DNS over TCP

DNS-over-TCP needs to be explicitly enabled by setting tcp_listen to 1. 

Deadwood extracts useful information from UDP DNS packets marked 
truncated which almost always removes the need to have DNS-over-TCP. 
However, Deadwood does not cache DNS packets larger than 512 bytes in 
size that need to be sent using TCP. In addition, DNS-over-TCP packets 
which are "incomplete" DNS replies (replies which a stub resolver can 
not use, which can be either a NS referral or an incomplete CNAME 
reply) are not handled correctly by Deadwood. 

Deadwood has support for both DNS-over-UDP and DNS-over-TCP; the same 
daemon listens on both the UDP and TCP DNS port. 

Only UDP DNS queries are cached. Deadwood does not support caching over 
TCP; it handles TCP to resolve the rare truncated reply without any 
useful information or to work with very uncommon non-RFC-compliant 
TCP-only DNS resolvers. In the real world, DNS-over-TCP is almost never 
used. 

# Parsing other files

It is possible to have Deadwood, while parsing the dwood3rc file, read 
other files and parse them as if they were dwood3rc files. 

This is done using **execfile**. To use execfile, place a line like 
this in the dwood3rc file: 

execfile("path/to/filename") 

Where path/to/filename is the path to the file to be parsed like a 
dwood3rc file. 

All files must be in or under the directory /etc/deadwood/execfile. 
Filenames can only have lower-case letters and the underscore character 
("_"). Absolute paths are not allowed as the argument to execfile; the 
filename can not start with a slash ("/") character. 

If there is a parse error in the file pointed to by execfile, Deadwood 
will report the error as being on the line with the execfile command in 
the main dwood3rc file. To find where a parse error is in the sub-file, 
use something like 
"Deadwood&nbsp;-f&nbsp;/etc/deadwood/execfile/filename" to find the 
parse error in the offending file, where "filename" is the file to to 
parsed via execfile. 

# IPV6 support

This server can also be optionally compiled to have IPv6 support. In 
order to enable IPv6 support, add '-DIPV6' to the compile-time flags. 
For example, to compile this to make a small binary, and to have IPv6 
support:

```
	export FLAGS='-Os -DIPV6' 
	make 
```

# SECURITY

Deadwood is a program written with security in mind. 

In addition to use a buffer-overflow resistant string library and a 
coding style and SQA process that checks for buffer overflows and 
memory leaks, Deadwood uses a strong pseudo-random number generator 
(The 32-bit version of RadioGatun) to generate both the query ID and 
source port. For the random number generator to be secure, Deadwood 
needs a good source of entropy; by default Deadwood will use 
/dev/urandom to get this entropy. If you are on a system without 
/dev/urandom support, it is important to make sure that Deadwood has a 
good source of entropy so that the query ID and source port are hard to 
guess (otherwise it is possible to forge DNS packets). 

The Windows port of Deadwood includes a program called 
"mkSecretTxt.exe" that creates a 64-byte (512 bit) random file called 
"secret.txt" that can be used by Deadwood (via the "random_seed_file" 
parameter); Deadwood also gets entropy from the timestamp when Deadwood 
is started and Deadwood's process ID number, so it is same to use the 
same static secret.txt file as the random_seed_file for multiple 
invocations of Deadwood. 

Note that Deadwood is not protected from someone on the same network 
viewing packets sent by Deadwood and sending forged packets as a reply. 

To protect Deadwood from certain possible denial-of-service attacks, it 
is best if Deadwood's prime number used for hashing elements in the 
cache is a random 31-bit prime number. The program RandomPrime.c 
generates a random prime that is placed in the file DwRandPrime.h that 
is regenerated whenever either the program is compiled or things are 
cleaned up with make clean. This program uses /dev/urandom for its 
entropy; the file DwRandPrime.h will not be regenerated on systems 
without /dev/urandom. 

On systems without direct /dev/urandom support, it is suggested to see 
if there is a possible way to give the system a working /dev/urandom. 
This way, when Deadwood is compiled, the hash magic number will be 
suitably random. 

If using a precompiled binary of Deadwood, please ensure that the 
system has /dev/urandom support (on Windows system, please ensure that 
the file with the name secret.txt is generated by the included 
mkSecretTxt.exe program); Deadwood, at runtime, uses /dev/urandom 
(secret.txt in Windows) as a hardcoded path to get entropy (along with 
the timestamp) for the hash algorithm. 

# COMMENTS

Deadwood's configuration file format supports two kinds of comments:

```
# This is a comment 
```

Here, a comment starts with the # character and continues until 
the end of the line. In some circumstances, a comment can start after a 
variable is set, for example:

```
bind_address="127.0.0.1" # IP we bind to 
```

The second comment type supports multi-line comments. For 
example:

```
_rem={} 
_rem={ #_rem --[=[ 
""" 
 We are now in a multi-line comment. 
 This allows a long explanation to be 
 in a Deadwood configuration file 
""" # ]=] 
} 
```

The actual format is _rem={ at the start of a line, which begins 
a multi-line comment. The comment continues until a } is seen. The 
reason for this unusual format is that it allows a Deadwood 
configuration file to have multi-line comments in a form which are 
compatible with both Lua and Python, as can be seen in the above 
example. 

# DAEMONIZATION

Deadwood does not have any built-in daemonization facilities; this is 
handled by the external program Duende or any other daemonizer. 

# Example configuration file

Here is an example dwood3rc configuration file:

```
# This is an example deadwood rc file  
# Note that comments are started by the hash symbol 
 
bind_address="127.0.0.1" # IP we bind to 
 
# The following line is disabled by being commented out 
#bind_address="::1" # We have optional IPv6 support 
 
# Directory we run program from (not used in Win32) 
chroot_dir = "/etc/deadwood"  
 
# The following upstream DNS servers are Google's  
# (as of December 2009) public DNS servers.  For  
# more information, see the page at 
# http://code.google.com/speed/public-dns/ 
# 
# If neither root_servers nor upstream_servers are set, 
# Deadwood will use the default ICANN root servers. 
#upstream_servers = {} 
#upstream_servers["."]="8.8.8.8, 8.8.4.4"  
 
# Who is allowed to use the cache.  This line 
# allows anyone with "127.0" as the first two 
# digits of their IP to use Deadwood 
recursive_acl = "127.0.0.1/16"  
 
# Maximum number of pending requests 
maxprocs = 2048 
 
# Send SERVER FAIL when overloaded 
handle_overload = 1  
 
maradns_uid = 99 # UID Deadwood runs as 
maradns_gid = 99 # GID Deadwood runs as 
 
maximum_cache_elements = 60000 
 
# If you want to read and write the cache from disk,  
# make sure chroot_dir above is readable and writable  
# by the maradns_uid/gid above, and uncomment the  
# following line.  
#cache_file = "dw_cache" 
 
# If your upstream DNS server converts "not there" DNS replies 
# in to IPs, this parameter allows Deadwood to convert any reply 
# with a given IP back in to a "not there" IP.  If any of the IPs 
# listed below are in a DNS answer, Deadwood converts the answer 
# in to a "not there" 
#ip_blocklist = "10.222.33.44, 10.222.3.55" 
 
# By default, for security reasons, Deadwood does not allow IPs in  
# the 192.168.x.x, 172.[16-31].x.x, 10.x.x.x, 127.x.x.x,  
# 169.254.x.x, 224.x.x.x, or 0.0.x.x range.  If using Deadwood  
# to resolve names on an internal network, uncomment the  
# following line: 
#filter_rfc1918 = 0 
```

# BUGS

Deadwood does not follow RFC2181's advice to ignore DNS responses with 
the TC (truncated) bit set, but instead extracts the first RR. If this 
is not desired, set the undocumented parameter truncation_hack to 0 
(but read the DNS over TCP section of this man page). 

Deadwood can not process DNS resource record types with numbers between 
65392 and 65407. These RR types are marked by the IANA for "private 
use"; Deadwood reserves these record types for internal use. This is 
only 16 record types out of the 65536 possible DNS record types (only 
71 have actually been assigned by IANA, so this is a non-issue in the 
real world). 

In addition, Deadwood will, by default, respond to both ANY and HINFO 
requests with a RFC8482 compliant packet instead of trying to resolve 
the record. 

It is not clear whether the DNS RFCs allow ASCII control characters in 
DNS names. Even if they were, Deadwood does not allow ASCII control 
characters (bytes with a value less then 32) in DNS names. Other 
characters (UTF-8, etc.) are allowed. 

Combining a CNAME record with other records is prohibited in RFC1034 
section 3.6.2 and RFC1912 section 2.4; it makes an answer ambiguous. 
Deadwood handles this ambiguity differently than some other DNS 
servers. 

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

Sam Trenholme (http://www.samiam.org) is responsible for this program 
and man page. He appreciates all of Jean-Jacques Sarton's help giving 
this program IPv6 support.  

# askmara man page

# NAME

askmara - do simple dns queries 

# DESCRIPTION

**askmara** queries the user-specified dns server for records, and 
outputs the reply in a csv2-compatible format (csv2 is the format of 
zone files that **maradns** uses). 

# USAGE

**askmara** [-n] [ -v | -t timeout] query [ server ] 

# OPTIONS

`-t` If this is present, the following argument is the askmara timeout, 
in seconds. Note that **askmara** can not both have a user-defined 
timeout and verbose output. 

`-v` If this is set, **askmara** will verbosely output the complete 
reply that the server sent. Note that this verbose output is not 
csv2-compatible. 

`-n` If this is set, **askmara**, when sending out a query, will not 
request DNS recursion; in other words, askmara will request that the 
remote DNS server not contact other DNS servers to answer the query in 
question. 

`query` dns record to be queried. The query has two sections: The type 
of record we desire, and the hostname we want this record for. 

The type of query can have two forms: A one-letter mnemonic, or a 
numeric rtype followed by a colon. This is immediately concatenated by 
the full name of the host name we wish to look up. 

For example, to ask for the IP of 'example.com.', we can use the 
one-letter mnemonic, in the form 'Aexample.com.', or we can use the 
numeric RR followed by a colon, giving the query '1:example.com.' 
(since A has the record type of one). Note that the query name needs 
the trailing dot at the end. 

Askmara supports a handful one-letter mnemonics, as follows: 

**A** signifies a request for an A (ipv4 address) RR 

**N** signifies a NS RR 

**C** signifies that we are asking for a CNAME RR 

**S** signifies that we want a SOA RR 

**P** signifies that we want a PTR RR 

**@** signifies that we mant a MX RR 

**T** signifies that we want a TXT RR 

**Z** signifies that we want to ask for all RRs. 

`server` IP address of the dns server to be queried. If no server is 
given, askmara will query 127.0.0.1.  

# EXAMPLES

Asking the server with the ip 127.0.0.1 for the IP address of 
example.com:

```
askmara Aexample.com. 
```

Asking the server with the ip 198.41.0.4 for the IP address of 
example.com:

```
askmara Aexample.com. 198.41.0.4 
```

Asking the server with the ip address 127.0.0.1 for the IP 
address of example.com, using the rr_number:query format:

```
askmara 1:example.com.  
```

Asking the server with the ip address 127.0.0.1 for a SRV record. 
In particular, we ask for the "http over tcp" service for example.net. 
Since askmara doesn't have a mnemonic for SRV record types, we use the 
numeric code (33 for SRV):

```
askmara 33:_http._tcp.example.net. 
```

Asking the server with the ip address 127.0.0.1 for the AAAA 
(ipv6 ip) record for example.net:

```
askmara 28:example.net.  
```

Note that the output will be a raw DNS packet in the SRV example, 
but askmara shows an IPv6 address (albeit without :: to collapse 0 
quads) in the AAAA example. 

# BUGS

When askmara is asked for an SOA record, the output of **askmara** 
closely resembles the format of a csv2 file, but can not be parsed as a 
csv2 file without modification. 

askmara outputs multi-chunk ("character-string") TXT records 
incorrectly (it only outputs the first chunk). 

# SEE ALSO

**maradns(8)** 
 http://www.maradns.org

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

# AUTHOR

MaraDNS is written by Sam Trenholme. Jaakko Niemi used 5 minutes to 
roll this manpage together, which Sam has subsequently revised.  

# blockHashMake man page

# NAME

blockHashMake - Make a block hash file for Deadwood 

# DESCRIPTION

blockHashMake is a stand alone command line tool which converts a list 
of host names in to a *block hash file* which Deadwood can read to 
block a large number of hosts quickly while using a minimum amount of 
memory to store the list of blocked hosts. 

A block hash file uses a special binary format for storing a list of 
blocked host names. 

blockHashMake reads the list of host names from the standard input and 
generates a binary file. 

# COMMAND LINE ARGUMENTS

blockHashMake can be invoked without command line arguments. If invoked 
without arguments, blockHashMake reads the list of host names to block 
from standard input and outputs the block hash to a file name 
"bigBlock.bin" 

blockHashMake can be invoked with a single "--help" or "--version" 
command line argument (e.g. "blockHashMake --version") which will 
output the version number of blockHashMake and provide basic usage 
information. 

The command line arguments are as follows:

```
blockHashMake [filename] [sip hash key] [hash bucket count] 
```

The **filename** is the name of the file we output the block hash 
to. If not specified, blockHashMake will output to the file named 
"bigBlock.bin". blockHashMake should not clobber an already existing 
file; if a file named "bigBlock.bin" (or the filename specified on the 
command line) already exists, be sure to delete the file before 
invoking blockHashMake to recreate the file. 

The **sip hash key** is usually set by the blockHashMake program, 
which, by default, uses /dev/urandom to generate a random 64-bit key 
for the block hash file (the Windows port of blockHashMake uses the 
CryptGenRandom function to get a random 64-bit key). If the **sip hash 
key** is given a value of 0, this can make a block hash file which can 
be shared on the internet. 

*Warning*: For security purposes, please set the sip hash key to 0 if 
sharing a block hash file on the internet! 

Deadwood will only load a block hash file with a sip hash key of 0 if 
allow_block_hash_zero_key has a value of 1. 

A user specified sip hash key only has up to 16 bits of entropy. **sip 
hash key** should *not* be used if a secret key for the hash 
compression algorithm is desired. 

The **hash bucket count** is the number of hash buckets the resulting 
block hash file will have. Having more hash buckets makes the block 
hash file larger, but sometimes allows searching for a string in a 
block hash to be a little faster. The default value, which is 125% of 
the number of host names given to blockHashMake, is a reasonable 
compromise between speed and size. 

# HOST LIST FORMAT

After being invoked, blockHashMake reads a list of host names from the 
standard input. The format is a single host name per line of input, 
such as the following:

```
porn.example.com 
naughty.foo 
evil.host.invalid 
```

Each line is a host name. Should there be a duplicate host name, 
blockHashMake will only store one instance of the host name in 
question. Host names are case insensitive; upper case ASCII letters are 
converted in to lower case letters beofre adding the host name to the 
block hash generated by blockHashMake. 

blockHashMake has no support for Punycode. Please use another program 
to convert international domain names with non-ASCII characters in to 
their punycode representation before adding them to a block hash with 
blockHashMake. 

# LIMITATIONS

The block hash format that blockHashMake uses is a 32-bit format, and 
the resulting block hash file should be under 2,147,483,648 bytes in 
size. This is a limitation of around 30 million host names. 

# LEGAL DISCLAIMERS

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

This is a project developed on a strictly volunteer, non-commercial 
basis. It has been developed outside the course of a commercial 
activity, developed entirely in the Americas (i.e. *outside of Europe*) 
and therefore is not subject to the restrictions or conditions of the 
proposed EU Cyber Resilience Act. Someone selling a product that uses 
any component of this may be subject to this act and may need to handle 
any and all necessary compliance. 

# AUTHORS

Sam Trenholme (https://www.samiam.org) is responsible for this program 
and man page.  

# blockHashRead man page

# NAME

blockHashRead - Read a block hash file 

# DESCRIPTION

blockHashRead is a stand alone command line tool which converts a 
*block hash file* in to a list of hostnames. This way, a binary block 
hash file can be converted in to an ASCII list of host names, edited, 
and then converted back in to a binary block hash file with the 
**blockHashMake** utility. 

A block hash file uses a special binary format for storing a list of 
blocked host names. 

# USAGE

blockHashRead is invoked as follows:

```
blockHashRead --dump bigBlock.bin 
```

Replace "bigBlock.bin" with the filename for the block hash file. 

Doing this will output, on standard output, a list of host names in the 
block hash file. Each line will contain a single host name. When 
compiled for *NIX, the output will use *NIX line feeds; the Windows 
port of blockHashRead uses DOS line feeds. 

blockHashRead can be invoked with a single "--help" or "--version" 
command line argument (e.g. "blockHashRead --version") which will 
output the version number of blockHashRead and provide basic usage 
information. 

# HOST LIST FORMAT

After being invoked, blockHashRead writes a list of host names to the 
standard output. The format is a single host name per line of input, 
such as the following:

```
porn.example.com 
naughty.foo 
evil.host.invalid 
```

Each line is a host name. 

blockHashRead has no support for Punycode. Please use another program 
to convert international domain names with non-ASCII characters in to 
their non-punycode representation if seeing correct international 
domain names is desired. 

# LIMITATIONS

The block hash format that blockHashRead looks at is a 32-bit format, 
and the resulting block hash file should be under 2,147,483,648 bytes 
in size. This is a limitation of around 30 million host names. 

# LEGAL DISCLAIMERS

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

This is a project developed on a strictly volunteer, non-commercial 
basis. It has been developed outside the course of a commercial 
activity, developed entirely in the Americas (i.e. *outside of Europe*) 
and therefore is not subject to the restrictions or conditions of the 
proposed EU Cyber Resilience Act. Someone selling a product that uses 
any component of this may be subject to this act and may need to handle 
any and all necessary compliance. 

# AUTHORS

Sam Trenholme (https://www.samiam.org) is responsible for this program 
and man page.  

# coLunacyDNS man page

==== coLunacyDNS ====

# NAME

coLunacyDNS - A DNS server configured by Lua 

# DESCRIPTION

coLunacyDNS is a simply IPv4 and IPv6 forwarding DNS server (with 
support only for IPv4 and IPv6 IP records) controlled by a Lua script. 
It allows a lot of flexibility because it uses a combination of C for 
high performance and Lua for maximum control. 

The current version of coLunacyDNS is version 1.0.011, made in January 
of 2021. 

All example configuration files here are public domain. 

# Getting started

On a CentOS 8 Linux system, this gets us started:

```
	make 
	su 
	./coLunacyDNS -d 
```

If one has `clang` instead of GCC:

```
	make CC="clang" 
```

Here, we use `coLunacyDNS.lua` as the configuration file. 

Since coLunacyDNS runs on port 53, we need to start it as root. As soon 
as coLunacyDNS binds to port 53 and seeds its internal secure pseudo 
random number generator, it calls chroot and drops root privileges. It 
runs as the user and group with the user ID of 707; this value can be 
changed by altering UID and GID in the source code. 

Cygwin users may use `make -f Makefile.cygwin` (or, if one prefers, 
`make CFLAGS="-O3 -DCYGWIN"` also works) to compile coLunacyDNS, since 
Cygwin does not have the same sandboxing Linux has. The Windows binary 
does not have sandboxing, but other measures are taken to minimize 
security risks. 

# Configration file examples

In this example, we listen on 127.0.0.1, and, for any IPv4 query, we 
return the IP of that query as reported by 9.9.9.9.

```
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1 
function processQuery(Q) -- Called for every DNS query received 
   -- Connect to 9.9.9.9 for the query given to this routine 
   local t = coDNS.solve({name=Q.coQuery, type="A",  
                          upstreamIp4="9.9.9.9"}) 
   -- Return a "server fail" if we did not get an answer 
   if(t.error or t.status ~= 1) then return {co1Type = "serverFail"} end 
   -- Otherwise, return the answer 
   return {co1Type = "A", co1Data = t.answer} 
end 
```

As an even simpler example, we always return "10.1.1.1" for any 
DNS query given to us:

```
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1 
function processQuery(Q) -- Called for every DNS query received 
  return {co1Type = "A", co1Data = "10.1.1.1"} 
end 
```

We can also set the AA (authoritative answer) flag, the RA 
(recursion available) flag, and the TTL (time to live) for our answer. 
In this example, both the AA and RA flags are set, and the answer is 
given a time to live of one hour (3600 seconds).

```
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1 
function processQuery(Q) -- Called for every DNS query received 
  return {co1Type = "A", co1Data = "10.1.1.1",  
          co1AA = 1, co1RA = 1, co1TTL = 3600} 
end 
```

In this example, where we bind to both IPv4 and IPv6 localhost, 
we return 10.1.1.1 for all IPv4 A queries, 
2001:db8:4d61:7261:444e:5300::1234 for all IPv6 AAAA queries, and "not 
there" for all other query types:

```
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1 
bindIp6 = "::1" -- Localhost for IPv6 
function processQuery(Q) -- Called for every DNS query received 
  if Q.coQtype == 28 then 
    return {co1Type = "ip6", 
            co1Data="2001-0db8-4d61-7261 444e-5300-0000-1234"} 
  elseif Q.coQtype == 1 then 
    return {co1Type = "A", co1Data = "10.1.1.1"} 
  else 
    return {co1Type = "notThere"} 
  end 
end 
```

Note that coLunacyDNS *always* binds to an IPv4 address; if 
bindIp is not set, coLunacyDNS will bind to 0.0.0.0 (all available IPv4 
addresses). In this example, we contact the DNS server 9.9.9.9 for IPv4 
queries, and 149.112.112.112 for IPv6 queries:

```
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1 
bindIp6 = "::1" -- Localhost for IPv6 
function processQuery(Q) -- Called for every DNS query received 
  local t 
  if Q.coQtype == 28 then -- Request for IPv6 IP 
    t = coDNS.solve({name=Q.coQuery,type="ip6",  
                     upstreamIp4="149.112.112.112"}) 
  elseif Q.coQtype == 1 then -- Request for IPv4 IP 
    t = coDNS.solve({name=Q.coQuery, type="A",  
                     upstreamIp4="9.9.9.9"}) 
  else 
    return {co1Type = "notThere"} 
  end 
  if t.error then 
    return {co1Type = "serverFail"} 
  end 
  if t.status == 28 then 
    return {co1Type = "ip6", co1Data = t.answer} 
  elseif t.status == 1 then 
    return {co1Type = "A", co1Data = t.answer} 
  else 
    return {co1Type = "notThere"} 
  end  
end 
```

Here is an example where we can synthesize any IP given to us:

```
-- This script takes a query like 10.1.2.3.ip4.internal. and returns the 
-- corresponding IP (e.g. 10.1.2.3 here) 
-- We use "internal" because this is the fourth-most commonly used 
-- bogus TLD (#1 is "local", #2 is "home", and #3 is "dhcp") 
 
-- Change this is a different top level domain as desired.  So, if this 
-- becomes "test", the this configuration script will resolve  
-- "10.1.2.3.ip4.test." names to their IP. 
TLD="internal" 
-- Change these IPs to the actual IPs the DNS server will run on 
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1 
bindIp6 = "::1" -- Localhost for IPv6 
 
function processQuery(Q) -- Called for every DNS query received 
  if Q.coQtype == 1 then 
    local query = Q.coQuery 
    if query:match("^%d+%.%d+%.%d+%.%d+%.ip4%." .. TLD .. "%.$") then 
      local ip = query:gsub("%.ip4%." .. TLD .. "%.$","") 
      return {co1Type = "A", co1Data = ip} 
    end 
  else 
    return {co1Type = "notThere"} 
  end 
  return {co1Type = "notThere"} 
end 
```

Here is an example of using a block list to block bad domains. 
The block list is stored in a file with a Deadwood compatible block 
list; see the file `make.blocklist.sh` in the upper level directory for 
the tool used to make the file we read to find domains to block.

```
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1 
bindIp6 = "::1" -- Localhost for IPv6 
 
-- Open up block list to know which domains to block 
blockList = {} 
if coDNS.open1("blocklist") then 
  line = coDNS.read1() 
  while line do 
    local name, seen = string.gsub(line,'^ip4%["([^"]+)".*$','%1') 
    if seen > 0 then 
      blockList[name] = "X" 
    end 
    line = coDNS.read1() 
  end 
end 
 
function processQuery(Q) -- Called for every DNS query received 
  local upstream = "9.9.9.9" 
  local t 
 
  -- Log query 
  coDNS.log("Got query for " .. Q.coQuery .. " from " .. 
            Q.coFromIP .. " type " ..  Q.coFromIPtype) 
 
  -- Process blocklist 
  if blockList[Q.coQuery] == "X" then 
    coDNS.log("Name is on block list.") 
    return {co1Type = "notThere"} 
  end 
 
  if Q.coQtype ~= 1 and Q.coQtype ~= 28 then -- If not IPv4/6 query 
    return {co1Type = "notThere"} -- Send "not there" (like NXDOMAIN) 
  end 
 
  -- Look for the answer upstream 
  if Q.coQtype == 1 then 
    t = coDNS.solve({name=Q.coQuery, type="A", upstreamIp4=upstream}) 
  else 
    t = coDNS.solve({name=Q.coQuery, type="ip6", upstreamIp4=upstream}) 
  end 
  -- Handle errors; it is not possible to call coDNS.solve() again 
  -- in an invocation of processQuery if t.error is set. 
  if t.error then 
    coDNS.log(t.error) 
    return {co1Type = "serverFail"} 
  end 
 
  -- If we got an answer we can use, send it to them 
  if t.status > 0 and t.answer then 
    if t.status == 1 then 
      return {co1Type = "A", co1Data = t.answer}  
    elseif t.status == 28 then 
      return {co1Type = "ip6", co1Data = t.answer} 
    else -- Send notThere for unknown query type 
      return {co1Type = "notThere"} 
    end 
  end 
  coDNS.log("Unknown issue (or record not found)") 
  return {co1Type = "notThere"} 
end 
```

Here is a complex coLunacyDNS example, which uses a number of 
features:

```
-- coLunacyDNS configuration 
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1 
 
-- Examples of three API calls we have: timestamp, rand32, and rand16 
coDNS.log(string.format("Timestamp: %.1f",coDNS.timestamp()))  
coDNS.log(string.format("Random32: %08x",coDNS.rand32()))  
coDNS.log(string.format("Random16: %04x",coDNS.rand16()))  
-- Note that it is *not* possible to use coDNS.solve here; if we attempt 
-- to do so, we will get an error with the message 
-- "attempt to yield across metamethod/C-call boundary".   
 
function processQuery(Q) -- Called for every DNS query received 
  -- Because this code uses multiple co-routines, always use "local" 
  -- variables 
  local returnIP = nil 
  local upstream = "9.9.9.9" 
 
  -- Log query 
  coDNS.log("Got IPv4 query for " .. Q.coQuery .. " from " .. 
            Q.coFromIP .. " type " ..  Q.coFromIPtype)  
 
  -- We will use 8.8.8.8 as the upstream server if query ends in ".tj" 
  if string.match(Q.coQuery,'%.tj%.$') then 
    upstream = "8.8.8.8" 
  end 
 
  -- We will use 4.2.2.1 as the upstream server if the query comes from  
  -- 192.168.99.X 
  if string.match(Q.coFromIP,'^192%.168%.99%.') then 
    upstream = "4.2.2.1" 
  end 
 
  if Q.coQtype ~= 1 then -- If it is not an A (ipv4) query 
    -- return {co1Type = "ignoreMe"} -- Ignore the query 
    return {co1Type = "notThere"} -- Send "not there" (like NXDOMAIN) 
  end 
 
  -- Contact another DNS server to get our answer 
  local t=coDNS.solve({name=Q.coQuery, type="A", upstreamIp4=upstream}) 
 
  -- If coDNS.solve returns an error, the entire processQuery routine is 
  -- "on probation" and unable to run coDNS.solve() again (if an attempt 
  -- is made, the thread will be aborted and no DNS response sent  
  -- downstream).   
  if t.error then	 
    coDNS.log(t.error) 
    return {co1Type = "serverFail"}  
  end 
 
  -- Status being 0 means we did not get an answer from upstream 
  if t.status ~= 0 and t.answer then 
    returnIP = t.answer 
  end 
 
  if string.match(Q.coQuery,'%.invalid%.$') then 
    -- Answer for anything.invalid 
    return {co1Type = "A", co1Data = "10.1.1.1"}  
  end 
  if returnIP then 
    return {co1Type = "A", co1Data = returnIP}  
  end 
  return {co1Type = "notThere"}  
end 
```

# Security considerations

Since the Lua file is executed as root, some effort is made to restrict 
what it can do: 

* Only the math, string, and bit32 libraries are loaded from Lua's 
  standard libs. (bit32 actually is another Bit library, but with a 
  bit32 interface.)

* A special coDNS library is also loaded.

* The program is designed to give Lua very limted access to the 
  filesystem nor be able to do anything malicious.

* coDNS.open1() can only open a file in the directory coLunacyDNS is 
  called from; it can not open files in other directories.

* All DNS ANY and HINFO queries are given a RFC8482 response.

# Limitations

coLunacyDNS only processes requests for DNS A queries and DNS AAAA 
queries -- queries for IPv4 and IPv6 IP addresses. Information about 
other query types is not available to coLunacyDNS, and it can only 
return A queries, AAAA queries, “server fail”, or “this name is not 
here” in its replies. 

coLunacyDNS, likewise, can only send A (IPv4 IP) and AAAA (IPv6 IP) 
requests to upstream servers. While coLunacyDNS can process and forward 
IPv6 DNS records, and while coLunacyDNS can bind to IPv4 and IPv6 IPs, 
it can not send queries to upstream DNS servers via IPv6, and 
coLunacyDNS must always have an IPv4 address to bind to. 

# The API available to the Lua script

coLunacyDNS, when running Lua code, has access to the Lua 5.1 versions 
of the math and string libraries. The math library has the functions 
math.abs, math.acos, math.asin, math.atan, math.atan2, math.ceil, 
math.cos, math.cosh, math.deg, math.exp, math.floor, math.fmod, 
math.frexp, math.huge, math.ldexp, math.log, math.log10, math.max, 
math.min, math.modf, math.pi, math.pow, math.rad, math.random, 
math.randomseed, math.sin, math.sinh, math.sqrt, math.tan, and 
math.tanh. Almost all of them are the same as they are in Lua 5.1; the 
only one which is different is math.random, which uses RadioGatun[32] 
instead of rand to generate random numbers, math.randomseed, which 
takes a string as the random seed (if a number is given, Lua uses 
coercion to convert the number in to a string), and math.rand16() (not 
available in stock Lua) which returns a 16-bit random integer between 0 
and 65535. 

coLunacyDNS also has access to the string library: string.byte, 
string.char, string.dump, string.find, string.format, string.gmatch, 
string.gsub, string.len, string.lower, string.match, string.rep, 
string.reverse, string.sub, and string.upper. All of these are as per 
Lua 5.1. 

string.match(str, pattern), for example, looks for the regular 
expression pattern in the string `str; regular expression are non-Perl 
compatible Lua regular expressions. There are number of changes; one 
being that, instead of using a backslash to escape characters, Lua 
regular expressions use % (so "%." matches against a literal dot, while 
"." matches against any character). 

While Lua 5.1 does not include the bit32 library, coLunacyDNS uses a 
bit manipulation library with an interface like bit32: The numbers are 
32-bit numbers, and the function calls are bit32.arshift, bit32.band, 
bit32.bnot, bit32.bor, bit32.bxor, bit32.lshift, bit32.rshift, and 
bit32.rrotate. 

coLunacyDNS also includes a few functions in its own coDNS space: 

* coDNS.log This takes a single string as its input, and logs the 
  string in question. The logging method depends on the OS being 
  used: In Windows it writes to a log file; in *NIX it currently 
  outputs the message on standard output. If logLevel is 0, its 
  output on *NIX is buffered; if logLevel is 1 or higher, its 
  output is flushed after every call to coDNS.log.

* coDNS.timestamp This returns coLunacyDNS's internal time 
  representation. This is not a standard *NIX timestamp; instead 
  it's a special timestamp generated by coLunacyDNS in a 
  Y2038-compliant manner (in places where time_t is 32-bit and we 
  do not have an alternate API to get numbers, we assume negative 
  timestamps are in the future; on Windows 32-bit, we use the Y2038 
  compatible 64-bit Windows NT fileTime timestamps; and on places 
  with a 64-bit time_t, we consider the timestamp accurate and 
  merely convert it). Each second has 256 ticks.

* coDNS.rand32 This returns a random integer between 0 and 4294967295.

* coDNS.rand16 This returns a random integer between 0 and 65535.

* coDNS.solve This function, which can only be called inside of 
  processQuery, requests a DNS record from another DNS server, and 
  returns once the data is available (or if the DNS server does not 
  respond, or if it gives us a reply that we did not get a record). 
  This function is described in more detail in the following 
  section.

* coDNS.open1, coDNS.read1, and coDNS.close1 can be used to read a 
  text file in the same directory that coLunacyDNS is being run 
  from. Details are below, after the coDNS.solve section.

# coDNS.solve

This function is given a table with three members: 

* name, which is the DNS name in human format like example.com. The 
  final dot is mandatory

* type, which can be A (IPv4) or ip6 (IPv6)

* upstreamIp4, which is the IP connect to; this is a string in IPv4 
  dotted decimal format, like 10.1.2.3 or 9.9.9.9. If upstreamIp4 
  is not present, coLunacyDNS looks for a global variable called 
  upstreamIp4 to see if a default value is available.

It outputs a table with a number of possible elements: 

* error: If this is in the return table, an error happened which makes 
  it not possible to have coDNS.solve run. Errors include giving 
  coDNS.solve a bad query for its DNS name; not giving coDNS.solve 
  a table when calling it; not having the element type in the table 
  given to coDNS.solve; etc. Once an error is returned, it is not 
  possible to run coDNS.solve again in the current thread; if one 
  calls coDNS.solve a second time after getting an error, the 
  thread will be terminated and the client will not receive a DNS 
  reply.

* status: If we got an IPv4 address from the upstream server, this 
  returns the number 1. If we got an IPv6 address from the upstream 
  server, this returns the number 28 (the DNS number for an IPv6 
  reply). Otherwise, this returns the number 0.

* answer: This is the answer we got from the upstream DNS server. If 
  the answer is an IPv4 IP, the answer is a string with a standard 
  dotted decimal IP in it, such as 10.4.5.6. If the answer is an 
  IPv6 IP, the answer is a string with the IPv6 IP in it, in the 
  form XXXX-XXXX-XXXX-XXXX XXXX-XXXX-XXXX-XXXX, where each X is a 
  hexadecimal digit, such as 2001-0db8-4d61-7261 
  444e-5300-0000-0001 All 32 hexadecimal digits that comprise an 
  IPv6 address will be present in the reply string. Should there be 
  a timeout or error getting an answer from the upstream DNS 
  server, this string will have the value DNS connect error. Should 
  we get a reply from the upstream DNS server, but an answer was 
  not seen (usually, because we asked for a DNS record which does 
  not exist), the answer field will have the string DNS answer not 
  seen.

* rawpacket: If the global variable logLevel has a value of 0, this 
  will always be nil. If logLevel is 1, this will be nil if we were 
  able to extract an answer from the upstream DNS server; 
  otherwise, this will be an escaped form of the raw packet sent to 
  us from upstream. If logLevel is 2 or higher, this will always be 
  an escaped raw packet from upstream. In an escaped packet, 
  characters which are between ASCII 0 and z will be shown as is; 
  otherwise, they will be in the form {1f}, where the hex value of 
  the byte is shown between the brackets ({ and } have an ASCII 
  value above z).

Since this function allows other Lua threads to run while it awaits a 
DNS reply, global variables may change in value while the DNS record is 
being fetched. 

# Reading files

We have an API which can be used to read files. For example:

```
if not coDNS.open1("filename.txt") then 
  return {co1Type = "serverFail"} 
end 
local line = "" 
while line do 
  if line then coDNS.log("Line: " .. line) end 
  line = coDNS.read1() 
end 
```

The calls are: coDNS.open1(filename), coDNS.read1(), and 
coDNS.close1(). 

Only a single file can be open at a time. If coDNS.open1() is called 
when a file is open, the currently open file is closed before we 
attempt to open the new file. If coDNS.solve() is called while a file 
is open, the file is closed before we attempt to solve the DNS query. 
If we exit processQuery() while a file is open, the file is closed as 
we exit the function. Files are also closed when we finish parsing the 
Lua configuration file used by coLunacyDNS, before listening to DNS 
queries. 

The filename must start with an ASCII letter, number, or the _ 
(underscore) character. The filename may contain only ASCII letters, 
numbers, instances of . (the dot character), or the _ character. In 
particular, the filename may not contain /, \, or any other commonly 
used directory separator. 

If the file is not present, or the filename contains an illegal 
character, or the file can not be opened, coDNS.open1 will return a 
false boolean value. Otherwise, open1 returns the true boolean. 

The file has to be in the same directory that coLunacyDNS is run from. 
The file may only be read; writing to the file is not possible. 

coDNS.read1() reads a single line from the file. Any newline is 
stripped from the end (unlike Perl, coLunacyDNS does not require a 
chop); NUL characters in the line also truncate the string read. If a 
line is read from the file, coDNS.read1() returns the line which was 
read. Otherwise, coDNS.read1() returns the false Lua boolean value. 

coDNS.read1() assumes that a single line will be under 500 bytes in 
size. Behavior is undefined when trying to read a longer line. 

coDNS.close1() closes an open file; a file is also closed when opening 
another file, ending processQuery(), or calling coDNS.solve(). It is 
mainly here to give programmers trained to close open files a function 
which does so. 

# processQuery

Every time coLunacyDNS gets a query, it runs the lua function 
processQuery, which takes as its input a table with the following 
members: 

* coQuery: This is the DNS name requested, in the form of a string 
  like caulixtla.com. or samiam.org. (observe the dot at the end of 
  the mmQuery string). If the string has anything besides an ASCII 
  letter, an ASCII number, the - character (dash), or the _ 
  character (underline), the character will be a two-digit 
  hexadecimal number in brackets. If we get the raw UTF-8 query 
  ñ.samiam.org (where the first character is a n with a tilde), 
  coQuery will look like {c3}{b1}.samiam.org.

* coQtype: The is the numeric DNS query type requested. This is a 
  number between 0 and 65535, and corresponds to the DNS query type 
  made. A list of DNS query type numbers is available at 
  https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml 
  1 is "A", i.e. a request for an IPv4 IP address.

* coFromIP: This is a string containing, in human-readable format, the 
  IP the query came from. The string will look like 10.9.8.7.

* coFromIPtype: This is the string IPv4

The processQuery function returns as its output a table with the 
following parameters: 

* co1Type: This is a string which can have the following values: 
  "ignoreMe" (no DNS reply will be sent back to the client), 
  "notThere" (tell the client that this DNS name does not exist for 
  the query type requested), "serverFail" (send a "server fail" to 
  the client), "A" (send an IPv4 IP answer back to the client), or 
  "ip6" (send an IPv6 IP answer back to the client). Please note 
  that "ignoreMe" does not guarantee that coLunacyDNS ignores all 
  DNS queries; coLunacyDNS will always respond to ANY or HINFO 
  queries in a RFC8482 manner; if one wishes to drop all DNS 
  packets, this can be done at the firewall level. This field is 
  mandatory.

* co1Data: This is to be a string. When co1Type is "A", this is an 
  IPv4 IP in dotted decimal format, e.g. 10.1.2.3. When co1type is 
  "ip6", and co1data is either a standard IPv6 string, such as 
  "2001:db8:1234::5678", or a string with 32 hexadecimal digits, 
  the IPv6 IP in the string is returned to the client. If the 
  character _ is in the ip6 string and the character : is *not* 
  present in the string, this is treated as if it were the number 
  0; the characters " " (space) and - (dash) are ignored. For 
  example, both "2001:db8::8" and "2001-0db8-4d61-7261 
  444e-5300-0000-__01" (without linefeed) are allowed values for 
  co1data when co1type is "ip6". This field is mandatory when 
  co1type is "A" or "ip6".

* co1AA: This field, when set with the numeric value of 1, gives the 
  AA flag in the DNS reply a value of true; in other words, the DNS 
  answer is marked as “authoritative”. This field is optional; if 
  not set, the reply is *not* marked authoritative.

* co1RA: This field, when set with the numeric value of 1, gives the 
  RA flag in the DNS reply a value of true, indicating that the 
  coLunacyDNS server can process recursive queries. This field is 
  optional; if not set, the reply is *not* marked as having 
  recursion available.

* co1TTL: This numeric field, if set, determines the DNS TTL 
  (suggested time to live for the record) of the reply. This is the 
  TTL in raw seconds, and can have a value between 0 (do not cache) 
  and 7777777 (cache for just over 90 days). This field is 
  optional; if not set, the TTL returned will be 0 (do not cache).

# Global settings

coLunacyDNS Lua scripts have three special global variables which are 
read to adjust settings in coLunacyDNS: 

* bindIp: This is the IPv4 IP that coLunacyDNS will use as a DNS 
  server. If this is not set, then coLunacyDNS will bind to the IP 
  0.0.0.0 (all IP addresses the machine running coLunacyDNS has)

* bindIp6: This is the IPv6 IP that coLunacyDNS will bind to. If this 
  is not set, coLunacyDNS will only bind to IPv4. The IP address is 
  in standard IPv6 format, e.g. "2001:0db8:f00:ba4::2020" or in 
  MaraDNS-specific format, e.g. "2001-0db8-0f00-0ba4 
  00__00__00__2020"

* logLevel: If this is set, more information will be logged and passed 
  to Lua scripts which can be used for debugging purposes. This can 
  have a value between 0 and 10; higher values result in more 
  logging. If logLevel has a value of 0, log messages generated 
  with coDNS.log are buffered and will not immediately be visible; 
  if logLevel has a value more than 0, `coDNS.log` messages are 
  immediately flushed (unbuffered).

# Test coverage

coLunacyDNS is feature complete and stable. 

coLunacyDNS is a stable and fully tested DNS server. Test coverage is 
at or very near 100% 

Note: Some blocks of code, sanity tests to make sure we’re not in a 
corner case which can not be readily replicated, have been removed from 
the testing code via `#ifdef`. Read sqa/README.md for details.  

# csv1 man page

# NAME

csv1 - Format of the csv1 zone file that MaraDNS uses 

# SPECIAL NOTE

The csv1 zone file format is supported primarily for MaraDNS users who 
already have zone files in the csv1 format. MaraDNS now supports a csv2 
zone file format. Note that the csv1 zone file format will continue to 
function as long as I am MaraDNS' maintainer. 

# SPECIAL CHARACTERS

`|` This delimits fields 

`#` This signifies a comment. Lines starting with this are ignored, 
otherwise it has no significance 

`%` This, in domain names, signifies that the rest of the domain name 
should be the name of this zone 

`*` This is translated to mean "any host name that otherwise does not 
resolve". It must be at the beginning of a domain name. 

`\` This is used as an escape character, either to escape octal values 
such as '\045' for %, or to escape the '%' character so it has no 
special meaning, or to escape the backslash character.  

# NOTES ON PROCESSING

All domain-name labels are converted to their lower-case equivalents 
before processing is done. This is because domain-name literals in the 
database with one or more upper-case letters in them are 
case-sensitive. This is my way to resolve RFC1035's desire to both 
allow binary domain labels and be case-insensitive. 

The file must first have a SOA record, followed by one or more NS 
records, followed by other records. The initial NS and SOA records must 
be RR for this zone. NS records after any non-NS record must be part of 
another zone. The resolution algorithm will not break if non-CNAME 
records share records with a CNAME record, but this is not a good idea 
to do.

# RR FORMAT

A domain name is a one-letter designation of its type, followed by the 
domain name separated by dots, ending with either a % or a trailing 
dot. If the domain name does not end with a % or trailing dot, an error 
is returned. 

# SUPPORTED RR TYPES

MaraDNS only supports the following types of resource records (RRs) in 
csv1 files. More resource records types are supported in csv2 zone 
files; see **csv2(5)** for details. 
 
```
	Letter	Type	RFC1035 section 3.2.2 value
 	A	A	1
 	N	NS	2
 	C	CNAME	5
 	S	SOA	6
 	P	PTR	12
 	@	MX	15
 	T	TXT	16
 	U	any	determined in third field of line
 
```

# FORMAT OF SUPPORTED RR TYPES

Here are the formats, shown by letter name:

```
A: Has three fields 
field one: the domain name 
field two: the ttl for the name in seconds 
field three: the ip address, in dotted decimal notation 
Example: 
Ahost.example.com.|7200|10.1.2.3 
```

A records are described with grueling detail in RFC1035. In 
short, an A record is an IP address for a given host name.

```
N: Has three fields 
field one: the domain name of the record 
field two: the ttl for the name in seconds 
field three: the domain name this NS points to.   
Example: 
Nexample.com.|86400|ns.example.com. 
```

NS (N here) records are described in RFC1035

```
C: Has three fields 
field one: the domain name of the record 
field two: the ttl for the name in seconds 
field three: the domain this CNAME record points to 
Example: 
Calias.example.org.|3200|realname.example.org. 
```

CNAME (which C is short for) records are described in RFC1035

```
S: Has nine fields 
field one: the domain name of the record 
field two: the TTL of the record 
field three: the origin of the domain.  In other words, the name of the 
             primary name server for the domain. 
field four: the email address for this domain (in the RFC822, not  
            BIND format) 
field five: the serial for the domain 
field six: the refresh (how often to see updates) for the domain 
field seven: the retry (how often to try when down) for the domain 
field eight: the expire (how long before the slave gives up) for the  
             domain 
field nine: the minimum (and default) TTL for the domain 
Example: 
Sexample.net.|86400|%|hostmaster@%|19771108|7200|3600|604800|1800 
```

SOA (S here) records are described in RFC1035

```
P: has three fields 
field one: the IP we wish to point to (in in-addr.arpa form) 
field two: the ttl for the name in seconds 
field three: the FQDN for the IP in question   
Example: 
P3.2.1.10.in-addr.arpa.|86400|ns.example.com. 
```

PTR (P here) records, which are used for reverse DNS lookups, are 
described in RFC1035. Note that one needs control of the appropriate 
in-addr.arpa subdomain to make PTR records visible on the internet at 
large.

```
@: has four fields 
field one: The host that people send email to 
field two: the ttl for this record 
field three: The preference for this MX host 
field four: The name of this MX host 
Example: 
@example.com.|86400|10|mail.example.com. 
```

MX (@ here) records are described in RFC1035

```
T: has three fields 
field one: The host someone wants to get additional information about 
field two: the ttl for this record 
field three: The desired text.  Any data becomes the record up until a  
             new line is reached.  The new line is not part of the TXT  
             record 
Example: 
Texample.com.|86400|Example.com: Buy example products online 
```

TXT (T here) records are described in RFC1035

```
U: has four fields 
field one: The host someone wants a data type normally unsupported by  
           MaraDNS for 
field two: the ttl for this record 
field three: The numeric code for this data type (33 for SRV, etc.) 
field four: The raw binary data for this data type 
Example: 
Uexample.com.|3600|40|\010\001\002Kitchen sink data 
```

The above example is a "Kitchen Sink" RR (see 
draft-ietf-dnsind-kitchen-sink-02.txt) with a "meaning" of 8, a 
"coding" of 1, a "subcoding" of 2, and a data string of "Kitchen sink 
data". Since this particular data type is not formalized in a RFC at 
this time, the most appropriate method of storing this data is by using 
the catch-all "unsupported" syntax. 

# EXAMPLE CSV1 ZONE FILE

```
 
# Example CSV1 zone file 
 
# This is what is known as a SOA record.  All zone files need to have one 
# of these 
S%|86400|%|hostmaster@%|19771108|7200|3600|604800|1800 
# These are known as authoritative NS records.  All zone files need one or 
# more of these 
N%|86400|ns1.% 
N%|86400|ns2.% 
 
# Some IP addresses 
Ans1.%|86400|10.0.0.1 
Ans2.%|86400|192.168.0.1 
A%|86400|10.1.2.3 
Amx.%|86400|10.1.2.4 
 
# An 'IN MX' record 
@%|86400|10|mx.% 
 
```

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

# AUTHOR

Sam Trenholme http://www.samiam.org/ 

# csv2 man page

# NAME

csv2 - Description of the csv2 zone file that MaraDNS uses 

# DESCRIPTION

The csv2 zone file format is MaraDNS' standard zone file format. This 
zone file format uses any kind of whitespace (space, tab, and carriage 
return), or the '|' character, to delimit fields. 

## Tilde delimitation

In newer MaraDNS releases, the tilde ('~') character is used to delimit 
records in csv2 zone files; in order to maintain maximum compatibility 
with older MaraDNS zone files, this feature is only enabled if a tilde 
is placed between the first and second record. Otherwise, tildes are 
not allowed in zone files (except in comments). 

Most older MaraDNS csv2 zone files without the tilde character are 
compatible with the updated csv2 parser, unless csv2_tilde_handling is 
set to 3. All older MaraDNS csv2 zone files will parse in MaraDNS if 
csv2_tilde_handling has a value of 0. Older MaraDNS releases also 
supported the csv2_tilde_handling variable (as long as it had a value 
of 0); this allowed the same configuration and zone files to be used in 
older and newer MaraDNS releases. 

## Resource record format

This zone file format has records in the following form: 

name [+ttl] [rtype] rdata ~ 

The name is the name of the record we will add, such as 
"www.example.net.". This must be placed at the beginning of a line. The 
rtype is the record type for the record, such as "A" (ipv4 IP address), 
"MX" (mail exchanger), or "AAAA" (ipv6 IP address). The ttl is how long 
other DNS servers should store this data in their memory (in seconds); 
this field needs a '+' as its initial character. The rdata is the 
actual data for this record; the format for the rdata is type-specific. 

Anything in square brackets is an optional field. If the ttl is not 
specified, the ttl is set to the default ttl value (see "Default TTL" 
below). If the rtype is not specified, it is set to be an "A" (ipv4 
address) record. 

The zone file supports comments; comments are specified by having a '#' 
anywhere between fields or records; when a '#' is seen, the csv2 parser 
ignores any character it sees (with the exception of the '{', which is 
not allowed in comments) until a newline. A '#' can usually be placed 
inside a field, and indicates the end of a field when placed there. 

A '{' character can never be placed in a comment. A '~' character is 
always allowed in a comment, and has no special meaning when placed in 
a comment. 

The following record types are supported; a description of the record 
data format accommodates the record type: 

## A

An A record stores an ipv4 address. This is the default record type 
should the record type not be specified. The record type has one field 
in it: the IP for the record. Examples:

```
a.example.net.              10.11.12.13 ~ 
b.example.net.        A     10.11.12.14 ~ 
c.example.net. +64000 A     10.11.12.15 ~ 
```

## PTR

A PTR record stores the name for a given ipv4 or ipv6 address, and is 
used for reverse DNS lookups. This record type has one field in it: The 
name for the record in question. Examples:

```
13.12.11.10.in-addr.arpa.        PTR    a.example.net. ~ 
14.12.11.10.in-addr.arpa.        PTR    b.example.net. ~ 
15.12.11.10.in-addr.arpa. +64000 PTR    c.example.net. ~ 
```

## MX

A MX record stores a mail exchange record, and is used for mail 
delivery. This record type has two fields in it: The priority (or 
"preference" in traditional DNS parlance) of the MX record (lower 
numbers get higher priority), and the name of the mail exchanger. 
Example of mail for example.net being mailed to mail.example.net, which 
has the IP "10.11.12.16":

```
example.net.      MX   10 mail.example.net. ~ 
mail.example.net.      10.11.12.16 ~ 
```

## AAAA

An AAAA record stores the ipv6 address for a given name. The IP is in 
standard ipv6 "colon delimited" format: eight 16-bit hexadecimal 
numbers are separated by colons. Two colons together indicate multiple 
streams of all-zero hex numbers. This record has only one field, the v6 
IP. Example:

```
a.example.net.   AAAA    2001:db8:dec:ade::f ~ 
```

## SRV

An SRV record stores a "service" definition. This record has four 
fields: Priority, weight, port, and target. For more information, 
please refer to RFC 2782. Example:

```
_http._tcp.% SRV 0 0 80 a.% ~ 
```

## NAPTR

A NAPTR record is described in RFC 2915. Example:

```
www.example.com. NAPTR 100 100 's';'http+I2R';'' _http._tcp.example.com. ~  
```

Note the semicolons. Because of a bug in MaraDNS 1.4.03 and 
earlier releases, NAPTR records will not parse unless a ~ is *not* used 
to separate records; a patch to fix this bug is available here. 

## NS

An NS record specifies the name servers for a given zone. If the name 
servers are not delegation name servers (in other words, if the name 
servers are the authoritative name servers for the zone), they need to 
be at the beginning of the zone, either as the first records in the 
zone, or right after the SOA record. The NS records are optional; if 
not present, MaraDNS will make an educated guess of that NS records 
should be there, based on the IPs the MaraDNS process is bound to. This 
record has one field: The name of the name server machine. Example:

```
example.net.    NS    ns1.example.net. ~ 
example.net.    NS    ns2.example.net. ~ 
```

## SOA

An SOA record stores the start of authority for a given zone file. This 
record is optional in a CSV2 zone file; should the record not be in the 
zone file, MaraDNS will synthesize an appropriate SOA record. This 
record can only exist once in a zone file: As the first record of the 
zone file. This record has seven fields: The name of the zone, the 
email address of the person responsible for the zone, and five numeric 
fields (serial, refresh, retry, expire, and minimum). Note that the SOA 
minimum does *not* affect other TTLs in MaraDNS. Example:

```
x.org. SOA x.org. email@x.org. 1 7200 3600 604800 1800 ~ 
```

If there is a '.' (dot) character in the part of the email 
address before the '@', it needs to be escaped thusly:

```
x.org. SOA x.org. john\.doe@x.org. 1 7200 3600 604800 1800 ~ 
```

Note that the csv2 parser will not allow more than one dot in a 
row; 'john\.\.doe@x.org' will cause a parse error. In addition, the dot 
character must be escaped with a backslash. 

The serial numeric field may be replaced by the string '/serial'; this 
string tells the CSV2 zone parser to synthesize a serial number for the 
zone based on the timestamp for the zone file. This allows one to have 
the serial number be automatically updated whenever the zone file is 
edited. Here is how this special field looks in a SOA record:

```
x.org. SOA x.org. email@x.org. /serial 7200 3600 604800 1800 ~ 
```

The '/serial' string is case-sensitive; only '/serial' in all 
lower case will parse. 

## TXT

A TXT record stores arbitrary text and/or binary data for a given host 
name. This record has one field: The text data for the record. 

A basic text record can be stored by placing ASCII data between two 
single quotes, as follows:

```
example.com. TXT 'This is an example text field' ~ 
```

Any binary data can be specified; see the **csv2_txt(5)** manual 
page for full details. 

If tildes are used to separate records, a TXT record can not contain a 
literal '|' (pipe) character, a '#' literal, a '~' literal, nor any 
ASCII control literal; these characters can be added to a TXT record 
via the use of escape sequences; read the csv2_txt man pagefor details. 

## SPF

A SPF record is, with the exception of the numeric rtype, identical to 
a TXT record. SPF records are designed to make it more difficult to 
forge email. 

Here is one example SPF record:

```
example.com. SPF 'v=spf1 +mx a:colo.example.com/28 -all' ~ 
```

Use '\x7e' to put a tilde ("~" character) in a SPF record:

```
example.com. SPF 'v=spf1 +mx a:colo.example.com/28 '\x7e'all' ~ 
```

More information about SPF records can be found in RFC4408, or by 
performing a web search for 'sender policy framework'. 

Note that SPF records never gained traction, and their role is handled 
by TXT records. 

## RAW

The RAW record is a special meta-record that allows any otherwise 
unsupported record type to be stored in a csv2 zone file. The syntax 
is:

```
RAW [numeric rtype] [data] ~ 
```

The numeric rtype is a decimal number. 

The data field can, among other thing, have backslashed hex sequences 
outside of quotes, concatenated by ASCII data inside quotes, such as 
the following example:

```
example.com. RAW 40 \x10\x01\x02'Kitchen sink'\x40' data' ~ 
```

The above example is a "Kitchen Sink" RR with a "meaning" of 16, 
a "coding" of 1, a "subcoding" of 2, and a data string of "Kitchen 
sink@ data" (since hex code 40 corresponds to a @ in ASCII). Note that 
unquoted hex sequences are concatenated with quoted ASCII data, and 
that spaces are *only* inside quoted data. 

The format for a data field in a RAW record is almost identical to the 
format for a TXT data field. Both formats are described in full in the 
**csv2_txt(5)** manual page. 

## FQDN4

The FQDN4 (short for "Fully Qualified Domain Name for IPv4") record is 
a special form of the "A" record (see above) that instructs MaraDNS to 
automatically create the corresponding PTR record. For example, the 
following is one way of setting up the reverse DNS lookup for 
x.example.net:

```
x.example.net. A 10.3.28.79 ~ 
79.28.3.10.in-addr.arpa. PTR x.example.net. ~ 
```

But the above two lines in a zone file can also be represented 
thusly:

```
x.example.net. FQDN4 10.3.28.79 ~ 
```

Note that the csv2 parser does not bother to check that any given 
IP only has a single FQDN4 record; it is up to the DNS administrator to 
ensure that a given IP has only one FQDN4 record. In the case of there 
being multiple FQDN4 records with the same IP, MaraDNS will have 
multiple entries in the corresponding PTR record, which is usually not 
the desired behavior. 

FQDN4 records are not permitted in a csv2_default_zonefile. If you do 
not know what a csv2_default_zonefile is, you do not have to worry 
about this limitation. 

## FQDN6

The FQDN6 (short for "Fully Qualified Domain Name for IPv6") record is 
the ipv6 form for the FQDN4 record. Like the FQDN4 record, this record 
creates both a "forward" and "reverse" DNS record for a given host 
name. For example, one may have:

```
x.example.net. AAAA 2001:db8:dec:ade::b:c:d ~ 
d.0.0.0.c.0.0.0.b.0.0.0.0.0.0.0.e.d.a.0.c.e.d.0.8.b.d.0.1.0.0.2 PTR  
x.example.net. ~ 
```

But the above two lines in a zone file can also be represented 
thusly:

```
x.example.net. FQDN6 2001:db8:dec:ade::b:c:d ~ 
```

Like FQDN4 records, it is the DNS administrator's duty to make 
sure only a single IP has a FQDN6 record. 

FQDN6 records are, like FQDN4 records, not permitted in a 
csv2_default_zonefile. If you do not know what a csv2_default_zonefile 
is, you do not have to worry about this limitation. 

FQDN6 records were implemented by Jean-Jacques Sarton. 

## CNAME

A CNAME record is a pointer to another host name. The CNAME record, in 
MaraDNS, affects any record type not already specified for a given host 
name. While MaraDNS allows CNAME and non-CNAME records to share the 
same host name, this is considered bad practice and is not compatible 
with some other DNS servers. 

CNAME records are not permitted in a csv2_default_zonefile. If you do 
not know what a csv2_default_zonefile is, this fact is of no relevance. 

# Historical and uncommon resource records

The following resource records are mainly of historical interest, or 
are not commonly used. 

## HINFO

*In light of RFC8482, using this record type is strongly discouraged.* 

An HINFO record is a description of the CPU (processor) and OS that a 
given host is using. The format for this record is identical to a TXT 
record, except that the field must have precisely two chunks. 

The first chunk of a HINFO record is the CPU the host is running; the 
second chunk is the OS the host is running. 

Example:

```
example.com. HINFO 'Intel Pentium III';'CentOS Linux 3.7' ~ 
```

This resource record is not actively used--the IANA has a list of 
CPUs and OSes that this record is supposed to have. However, this list 
has not been updated since 2002. 

Since MaraDNS has support for RFC8482, ANY queries sent to MaraDNS will 
return an HINFO record with a CPU of "RFC8482" and a blank OS name. 

## WKS

WKS records are historical records which have been superseded by SRV 
records. The format of the record is an IP, followed by a protocol 
number (6 means TCP), followed by a list of ports that a given server 
has available for services. 

For example, to advertise that example.net has the IP 10.1.2.3, and has 
a SSH, HTTP (web), and NNTP server:

```
example.net. WKS 10.1.2.3 6 22,80,119 ~ 
```

MaraDNS only allows up to 10 different port numbers in a WKS 
record, and requires that the listed port numbers are not be higher 
than 1023. 

## MD and MF

MD and MF records are RR types that existed before MX records, and were 
made obsolete by MX records. RFC1035 says that a DNS server can either 
reject these records or convert these records in to MX records. BIND 
rejects these records; MaraDNS converts them. 

Example:

```
example.net. MD a.example.net. ~ 
example.net. MF b.example.net. ~ 
```

Is equivalent to:

```
example.net. MX 0 a.example.net. ~ 
example.net. MX 10 b.example.net. ~ 
```

## MB, MG, MINFO, and MR

In the late 1980s, an alternative to MX records was proposed. This 
alternative utilized MB, MG, MINFO, and MR records. This alternative 
failed to gather popularity. However, these records were codified in 
RFC1035, and are supported by MaraDNS. Here is what the records look 
like:

```
example.net. MB mail.example.net. ~ 
example.net. MG mg@example.net. ~ 
example.net. MINFO rm@example.net. re@example.net. ~ 
example.net. MR mr@example.net. ~ 
```

More information about these records can be found in RFC1035. 

## AFSDB, RP, X25, ISDN, and RT

AFSDB, RP, X25, ISDN, and RT are resource records which were proposed 
in RFC1183. None of these resource records are widely used. 

With the exception of the ISDN record, the format of these records is 
identical to the examples in RFC1183. The format of the ISDN record is 
identical unless the record has a subaddress (SA). If an ISDN record 
has a subaddress, it is separated from the ISDN-address by a ';' 
instead of whitespace. 

If used, here is how the records would look in a csv2 zone file:

```
example.net. AFSDB 1 afsdb.example.net. ~ 
example.net. RP rp@example.net. rp.example.net. ~ 
example.net. RP rp2@example.net. . ~ 
example.net. X25 311061700956 ~ 
example.net. ISDN 150862028003217 ~ 
example.net. ISDN 150862028003217;004 ~ 
example.net. RT 10 relay.example.net. ~ 
```

## NSAP and NSAP-PTR

NSAP and NSAP-PTR records were proposed in RFC1706. A NSAP record is a 
hexadecimal number preceded by the string "0x" and with optional dots 
between bytes. This hexadecimal number is converted in to a binary 
number by MaraDNS. A NSAP-PTR record is identical to a PTR record, but 
has a different RTYPE. 

More information about these records can be obtained from RFC1706. 

If used, here is how the records would look in a csv2 zone file:

```
example.net. NSAP 0x47.0005.80.005a00.0000.0001.e133.ffffff000162.00 ~ 
example.net. NSAP-PTR nsap.example.net. ~ 
```

## PX

The PX RR is an obscure RR described in RFC2163. A PX record looks like 
this in a CSV2 zone file:

```
example.net. PX 15 px1.example.net. px2.example.net. ~ 
```

## GPOS

An GPOS record is a description of the location of a given server. The 
format for this record is identical to a TXT record, except that the 
field must have precisely three chunks. 

The first chunk of a GPOS record is the longitude; the second chunk is 
the latitude; the third chunk is the altitude (in meters). 

Example:

```
example.net. GPOS '-98.6502';'19.283';'2134' ~ 
```

More information about this record can be found in RFC1712. 

This resource record is not actively used; for the relatively few 
people who encode their position in DNS, the LOC record is far more 
common. 

## LOC

The LOC resource record is an uncommonly used resource record that 
describes the position of a given server. LOC records are described in 
RFC1876. 

Note that MaraDNS' LOC parser assumes that the altitude, size, 
horizontal, and vertical precision numbers are always expressed in 
meters. Also note that that sub-meter values for size, horizontal, and 
vertical precision are not allowed. Additionally, the altitude can not 
be greater than 21374836.47 meters. 

Example:

```
example.net. LOC 19 31 2.123 N 98 3 4 W 2000m 2m 4m 567m ~ 
```

## CAA

MaraDNS does not have direct support for CAA records. However, the RAW 
record type can generate CAA records. For example, to have 
"example.com" have a CAA record with the value of "issue 
letsencrypt.org":

```
example.com. RAW 257 \x00\x05'issueletsencrypt.org' ~ 
```

# STAR RECORDS

MaraDNS has support for star records in zone files:

```
*.example.net.  A		10.11.12.13 ~ 
```

In this example, anything.example.net will have the IP 
10.11.12.13. Note that this does not set the ip for "example.net", 
which needs a separate record:

```
example.net.  A                 10.11.12.13 ~ 
```

Note also that stars must be at the beginining of a name; to have 
stars at the end of a name, use the csv2_default_zonefile feature as 
described in the mararc man page. 

# PERCENT SYMBOL

Placing the percent symbol at the end of a record indicates that the 
percent should be replaced with the domain name for the zone. 

For example, in the zone for example.net. (e.g. one's mararc file has 
csv2["example.net."] = "db.example.net", and we are editing the 
"db.example.net" file):

```
www.%	A	10.10.10.10 ~ 
```

This will cause "www.example.net" to have the ip 10.10.10.10. 

# SLASH COMMANDS

In addition to being able to have resource records and comments, csv2 
zone files can also have special slash commands. These slash commands, 
with the exception of the '/serial' slash command (see "SOA" above), 
can only be placed where the name for a record would be placed. Like 
resource records, a tilde is to be placed after the slash command. Note 
also that slash commands are case-sensitive, and the command in 
question must be in all-lower-case. 

These commands are as follows: 

## Default TTL

The default TTL is the TTL for a resource record without a TTL 
specified. This can be changed with the '/ttl' slash command. This 
command takes only a single argument: The time, in seconds, for the new 
default TTL. The '/ttl' slash command only affects the TTL of records 
that follow the command. A zone file can have multiple '/ttl' slash 
commands. 

The default TTL is 86400 seconds (one day) until changed by the '/ttl' 
slash command. 

In the following example, a.ttl.example.com will have a TTL of 86400 
seconds (as long as the zone file with this record has not previously 
used the '/ttl' slash command), b.ttl.example.com and d.ttl.example.com 
will have a TTL of 3600 seconds, c.ttl.example.com will have a TTL of 
9600 seconds, and e.ttl.example.com will have a TTL of 7200 seconds:

```
a.ttl.example.com.       10.0.0.1 ~ 
/ttl 3600 ~ 
b.ttl.example.com.       10.0.0.2 ~ 
c.ttl.example.com. +9600 10.0.0.3 ~ 
d.ttl.example.com.       10.0.0.4 ~ 
/ttl 7200 ~ 
e.ttl.example.com.       10.0.0.5 ~ 
```

## Origin

It is possible to change the host name suffix that is used to 
substitute the percent in a csv2 zone file. This suffix is called, for 
historical and compatibility reasons, "origin". This is done as the 
slash command '/origin', taking the new origin as the one argument to 
this function. Note that changing the origin does *not* change the 
domain suffix used to determine whether a given domain name is 
authoritative. 

Here is one example usage of the '/origin' slash command:

```
/origin example.com. ~ 
www.% 10.1.0.1 ~ 
% MX 10 mail.% ~ 
mail.% 10.1.0.2 ~ 
/origin example.org. ~ 
www.% 10.2.0.1 ~ 
% MX 10 mail.% ~ 
mail.% 10.2.0.2 ~ 
```

Which is equivalent to:

```
www.example.com. 10.1.0.1 ~ 
example.com. MX 10 mail.example.com. ~ 
mail.example.com. 10.1.0.2 ~ 
www.example.org. 10.2.0.1 ~ 
example.org. MX 10 mail.example.org. ~ 
mail.example.org. 10.2.0.2 ~ 
```

It is also possible to make the current origin be part of the new 
origin:

```
/origin example.com. ~ 
% 10.3.2.1 ~ # example.com now has IP 10.3.2.1 
/origin mail.% ~ 
% 10.3.2.2 ~ # mail.example.com now has IP 10.3.2.2 
```

## Opush and Opop

The '/opush' and '/opop' slash commands use a stack to remember and 
later recall values for the origin (see origin above). The '/opush' 
command is used just like the '/origin' command; however, the current 
origin is placed on a stack instead of discarded. The '/opop' command 
removes ("pops") the top element from this stack and makes the element 
the origin. 

For example:

```
/origin example.com. ~ 
/opush mail.% ~ # origin is now mail.example.com; example.com is on stack 
a.% 10.4.0.1 ~ # a.mail.example.com has IP 10.4.0.1 
/opush web.example.com. ~ # mail.example.com and example.com are on stack 
a.% 10.5.0.1 ~ # a.web.example.com has IP 10.5.0.1 
b.% 10.5.0.2 ~ # b.web.example.com has IP 10.5.0.2 
/opop ~ # origin is now mail.example.com again 
b.% 10.4.0.2 ~ # b.mail.example.com has IP 10.4.0.2 
/opop ~ # origin is now example.com 
% MX 10 a.mail.% ~ # example.com. MX 10 a.mail.example.com. 
% MX 20 b.mail.% ~ # example.com. MX 20 b.mail.example.com. 
```

The opush/opop stack can have up to seven elements on it. 

## Read

The '/read' slash commands allows one to have the contents of another 
file in a zone. The '/read' command takes a single argument: A filename 
that one wishes to read. The filename is only allowed to have letters, 
numbers, the '-' character, the '_' character, and the '.' character in 
it. 

The file needs to be in the same directory as the zone file. The file 
will be read with the same privileges as the zone file; content in the 
file should come from a trusted source or be controlled by the system 
administrator. 

Let us suppose that we have the following in a zone file:

```
mail.foo.example.com. 10.3.2.1 ~ 
/read foo ~ 
foo.example.com. MX 10 mail.foo.example.com. ~ 
```

And a file foo with the following contents:

```
foo.example.com. 10.1.2.3 ~ 
foo.example.com. TXT 'Foomatic!' ~ 
```

Then foo.example.com will have an A record with the value 
10.1.2.3, a TXT value of 'Foomatic!', and a MX record with priority 10 
pointing to mail.foo.example.com. mail.foo.example.com will have the IP 
10.3.2.1. 

Note that no pre-processing nor post-processing of the origin is done 
by the '/read' command; should the file read change the origin, this 
changed value will affect any records after the '/read' command. For 
example, let us suppose db.example.com looks like this:

```
/origin foo.example.com. ~ 
% TXT 'Foomatic!' ~ 
/read foo ~ 
% MX 10 mail.foo.example.com. ~ 
```

And the file foo looks like this:

```
% 10.1.2.3 ~ 
/origin mail.% ~ 
% 10.3.2.1 ~ 
```

Then the following records will be created:

```
foo.example.com.      TXT   'Foomatic!' ~ 
foo.example.com.      A     10.1.2.3 ~ 
mail.foo.example.com. A     10.3.2.1 ~ 
mail.foo.example.com. MX 10 mail.foo.example.com. ~ 
```

To have something that works like '$INCLUDE filename' in a 
RFC1035 master file, do the following:

```
/opush % ~ 
/read filename ~ 
/opop ~ 
```

Or, for that matter, the equivalent of '$INCLUDE filename 
neworigin':

```
/opush neworigin. ~ 
/read filename ~ 
/opop ~ 
```

## EXAMPLE ZONE FILE

```
 
## This is an example csv2 zone file 
 
## First of all, csv2 zone files do not need an SOA record; however, if 
## one is provided, we will make it the SOA record for our zone 
## The SOA record needs to be the first record in the zone if provided 
## This is a commented out record and disabled. 
 
#% 	SOA	% email@% 1 7200 3600 604800 1800 ~ 
 
## Second of all, csv2 zone files do not need authoritative NS records. 
## If they aren't there, MaraDNS will synthesize them, based on the IP 
## addresses MaraDNS is bound to.  (She's pretty smart about this; if 
## Mara is bound to both public and private IPs, only the public IPs will 
## be synthesized as NS records)

#% 	NS 	a.% ~ 
#%	NS	b.% ~ 
 
## Here are some A (ipv4 address) records; since this is the most 
## common field, the zone file format allows a compact representation 
## of it. 
a.example.net. 	10.10.10.10 ~ 
## Here, you can see that a single name, "b.example.net." has multiple IPs 
## This can be used as a primitive form of load balancing; MaraDNS will 
## rotate the IPs so that first IP seen by a DNS client changes every time 
## a query for "b.example.net." is made 
b.example.net.  10.10.10.11 ~ 
b.example.net.  10.10.10.12 ~ 
 
## We can have the label in either case; it makes no difference 
Z.EXAMPLE.NET. 	10.2.3.4 ~ 
Y.EXAMPLE.net.  10.3.4.5 ~ 
 
## We can use the percent shortcut.  When the percent shortcut is present, 
## it indicates that the name in question should terminate with the name 
## of the zone we are processing. 
percent.%	a 		10.9.8.7 ~ 
 
## And we can have star records 
#*.example.net.  A		10.11.12.13 ~ 
 
## We can have a ttl in a record; however the ttl needs a '+' before it: 
## Note that the ttl has to be in seconds, and is before the RTYPE 
d.example.net. +86400 A 10.11.12.13 ~ 
 
f.example.net. # As you can see, records can span multiple lines 
        	A 	10.2.19.83 ~ 
 
## This allows well-commented records, like this: 
c.example.net. 		# Our C class machine 
        +86400  	# This record is stored for one day 
        A       	# A record 
        10.1.1.1 	# Where we are  
        ~               # End of record 
 
## We can even have something similar to csv1 if we want... 
e.example.net.|+86400|a|10.2.3.4|~ 
h.example.net.|a|10.9.8.7|~ 
## Here, we see we can specify the ttl but not the rtype if desired 
g.example.net.|+86400|10.11.9.8|~ 
 
## Here is a MX record 
## Note that "IN" is a pseudo-RR which means to ignore the RR type and 
## look at the next RR type in the zone file; this allows MaraDNS zone 
## files to look more like BIND zone files. 
% mx 10 mail.% ~ 
mail.% +86400 IN A 10.22.23.24 ~ 
 
## We even have a bit of ipv6 support 
a.example.net. 		aaaa 	2001:db8:1:2::3:f ~ 
 
## Not to mention support for SRV records 
_http._tcp.%    srv   0 0 80 a.% ~ 
 
## TXT records, naturally 
example.net.    txt 'This is some text' ~ 
 
## Starting with MaraDNS 1.2.08, there is also support for SPF records, 
## which are identical to TXT records.  See RFC4408 for more details. 
example.net.    spf 'v=spf1 +mx a:colo.example.com/28 -all' ~

```

## LEGAL DISCLAIMER

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

## AUTHOR

Sam Trenholme http://www.samiam.org/ 

# csv2_txt man page

# NAME

csv2_txt - Description of txt and raw resource records in the csv2 zone 
file 

# DESCRIPTION

Due to the complexity of TXT and RAW records, this man page is 
dedicated to describing the csv2 format of this RR. 

TXT and RAW rrs in MaraDNS' csv2 zone files can store any arbitrary 
binary data. Additionally, it is possible to arbitrarily divide up TXT 
records in to chunks (chunks, which RFC1035 call "character-string"s, 
are described below). 

## ASCII AND UTF-8 DATA

If a given TXT field or RAW record contains only ASCII data, creating a 
record is easy: Place the full data between single quotes, like this:

```
a.example.com. TXT 'This is some text' ~ 
```

It is also possible, to place almost any printable ASCII 
characters between quotes. The '~' (tilde) character is not allowed 
unless csv2_tilde_handling has a value of 0; the '|' (pipe), '#' (hash) 
and non-printable ASCII control characters are not allowed in TXT data 
if the ~ is used to separate records. If there are any bytes with a 
value of 0x80 or more, the data must be UTF-8 encoded Unicode.  
For example:

```
b.example.com. TXT 'This is an example UTF-8 character: I ♥ MaraDNS' 
```

(If your font does not have this Unicode symbol, it is a heart)

The printable ASCII characters not allowed in quotes are the ' 
character, the '|' character, the '~' (tilde) character, and the '#' 
character. See BACKSLASH ESCAPE SEQUENCES below for information on 
adding these characters to TXT or RAW fields. 

## UNQUOTED DATA

Note that the record does not have to be quoted. As long as the record 
only contains ASCII alphanumeric data, and/or the characters '-', '_', 
'+', '%', '!', '^', and '=', the data can be unquoted as follows:

```
c.example.com. TXT This_is_100%_unquoted_text_+symbols! 
```

It is also possible to mix quoted and unquoted text, such as 
this:

```
d.example.com. TXT This' is a mix 'of_unquoted' and quoted 'text! 
```

Which will have its data look like this:

```
This is a mix of_unquoted and quoted text! 
```

When mixing quoted and unquoted data, it is important to have all 
whitespace *inside* quotes. 

## BACKSLASH ESCAPE SEQUENCES

In order to accommodate storing non-UTF-8 high bit characters, the 
single quote character, non-printable ASCII control codes, the '|', 
'~', and '#' characters, and to permit multi-line TXT/RAW records (with 
comments allowed mid-record), the TXT/RAW RR allows backslashes. These 
backslashes only have significance *outside* of quoted text; if they 
are placed inside single quotes, they are not interpreted and result in 
a literal backslash being added to the resource record data. 

The following characters can be backslashed:  

`'` When backslashed, the adds a literal quote to the resource record. 

`whitespace` When any whitespace is backslashed (space, newline, cr, 
and tab), this indicates that the record has not ended, and that more 
data for this resource will follow. This also allows comments to be 
placed in TXT and RAW resource records. What happens is that the 
backslash indicates that any whitespace characters (space, tab, 
carriage return, and line feed) are to be ignored until the next 
non-whitespace character that is not a # (hash). If a # is seen, this 
indicates that we ignore any and all characters until the next carriage 
return or line feed, and continue to ignore everything until the next 
non-whitespace character. See the section on multi-line and commented 
records for examples. 

`0123` When a number between 0 and 3 is backslashed, this indicates the 
beginning of a three-digit octal number. 

`x` When an x is backslashed, this indicates the beginning of a 
two-digit hexadecimal number.  Note that, with the exception of 
the single quote, the backslash character is *not* used to remove the 
meta-significance of a given character. In particular, unlike other 
environments, it is not possible to backslash spaces. Spaces can be 
represented either as ' ' in quotes, \x20, or as \040. 

Here are some examples of backslashed data. In this example, we see 
backslash sequences being used to store non-UTF-8 hi-bit data:

```
e.example.com. TXT \x80\x81\x82\x83 ~ 
```

This same data can also be created as follows:

```
f.example.com. TXT \200\201\202\203 ~ 
```

Octal and hex information can be mixed:

```
g.example.com. TXT \200\x81\202\x83 ~ 
```

Literal single quotes can be placed in resource records:

```
h.example.com. TXT 'perl -e '\''print "A Perl of a TXT record!\n"'\' ~ 
```

The above example produces this record:

```
perl -e 'print "A Perl of a TXT record!\n"' ~ 
```

To render the '~' character, use the escape sequence \x7e 
(outside of quotes). For example:

```
h1.example.com. TXT 'http://ocf.berkeley.edu/'\x7e'set' ~ 
```

Produces this record:

```
http://ocf.berkeley.edu/~set 
```

To render the '|' character, use the escape sequence \x7c:

```
h2.example.com. TXT 'ls '\x7c' more' ~ 
```

Produces this record:

```
ls | more 
```

To render the '#' character, use the escape sequence \x23:

```
h3.example.com. TXT 'Press '\x23' for customer service' ~ 
```

Produces this record:

```
Press # for customer service 
```

## MULTI-LINE AND COMMENTED RECORDS

By utilizing backslashes followed by comments, it is possible to have 
multi-line and commented TXT and RAW records. The following resource 
record will span more than one line on an 80-column display:

```
i.example.com. TXT 'Not only did the quick brown fox jump over the lazy dog, but the lazy dog jumped over the cat.' ~ 
```

Without affecting this resource record, the same data can be 
split over multiple lines:

```
j.example.com. TXT 'Not only did the quick brown fox jump '\ 
                   'over the lazy dog, but the lazy dog'\ 
                   ' jumped over the cat.' ~ 
```

Some points: 

* The backslash must be outsize of the quotes (or a literal backslash 
  will be added to the record)

* The backslash must be present *before* any unquoted white space. 
  Usually, the backslash is placed immediately after the quote 
  character.

* Unlike other environments, it does not matter whether or not there 
  is invisible whitespace after the backslash.

It is also possible to add comments after such a backslash as follows:

```
k.example.com. TXT 'Not only did the quick brown fox jump '\ # The fox 
                   'over the lazy dog, but the lazy dog'\    # The dog 
                   ' jumped over the cat.' ~                 # The cat 
```

Note that, since the third comment is not preceded by a 
backslash, this indicates the end of the resource record. 

There can also be multiple lines dedicated to comments (and, 
optionally, even blank lines) in the middle of TXT and RAW record data:

```
k2.example.com. TXT 'This is some data '\ 
# Here we have some comments followed by a blank line 
 
# Now we have some more comments,  
# followed by the rest of the data 
    'and this is the rest of the data' ~ 
```

## MULTIPLE TXT CHUNKS

TXT RRs may be divided up in to multiple "chunks" (RFC1035 calls these 
"character-string"s). A single chunk can be anywhere from zero to 255 
bytes long. The default is to have one chunk, as follows:

```
o.example.com. TXT 'TXT record with only one chunk' ~ 
```

It is also possible to have a record with multiple chunks. Chunks 
are delimited by an unquoted ';' character:

```
p.example.com. TXT 'This is chunk one';'This is chunk two' ~ 
```

Or:

```
q.example.com. TXT 'This is chunk one';\   # Our first chunk 
                    This_is_chunk_two;\    # Our second chunk 
                   'This is chunk three' ~ # Our final chunk 
```

Quoted ; characters simply add a ; to the record data. 

If a single TXT chunk is longer than 255 bytes long, the csv2 parser 
will report an error in the zone file: Single TXT chunk too long 

In order to resolve this, place unquoted ; characters in the record 
data so that each chunk is under 255 octets (bytes or characters) in 
length. 

It is possible to have zero length chunks:

```
r.example.com. TXT 'chunk one';;'chunk three' ~ # Chunk two zero-length 
```

In particular, is is possible to have zero length chunks at the 
beginning and end of a TXT record:

```
s.example.com. TXT ;'chunk two'; ~ # Chunks one and three zero-length 
```

Do not place semicolons at the beginning nor end of TXT records 
unless you wish to have these zero-length chunks. 

Chunk support only exists for TXT records. An unquoted ; character will 
cause a syntax error in a RAW record. 

## RAW RECORDS

With the exception of no support for chunk delimiters, and the addition 
of a numeric record type before the record data, the format for RAW 
records is identical to text records. For example, if we wish to have a 
"Kitchen Sink" RR record, which has the 8-bit binary numbers "16", "1", 
and "2", followed by the ASCII string "Kitchen sink+ data", we can 
specify this in any of the following manners:

```
t1.example.com. RAW 40 \x10\x01\x02'Kitchen sink'\x2b' data' ~ 
```

```
t.example.com. RAW 40 \020\001\002Kitchen' sink+ data' ~ 
```

```
u.example.com. RAW 40 \x10\x01\x02Kitchen\x20sink+\x20data ~ 
```

```
v.example.com. RAW 40 \x10\001\x02\ 
                      'Kitchen sink+ data' ~ 
```

```
w.example.com. RAW 40 \x10\ # Meaning: 16 
                      \x01\ # Coding: 1 
                      \x02\ # Sub-coding: 2 
                      'Kitchen sink+ data' ~ # Data: 'Kitchen sink+ data' 
```

## DKIM RECORDS

DKIM is a format used to store e-mail authentication data via DNS. 

MaraDNS can store a 2048-bit RSA DKIM key. Longer keys are not 
supported because of the 512-byte limit for traditional DNS packets. 

A DKIM record is a long “multi chunk” TXT record; DKIM records are 
stored in a special `_domainkey.example.com` record. As per RFC6376 
section 3.6.2.2, “Strings in a TXT RR MUST be concatenated together 
before use with no intervening whitespace”; a single TXT “chunk” can 
only be up to 255 bytes in length, but we need more than 255 bytes to 
store a 2048 bit RSA key (6 bits per character, so we need 342 
characters to store just the key) and a little more overhead to store 
the other bits in our DKIM record. But, it doesn’t matter where we 
split the chunks as long as each individual chunk is under 256 bytes in 
size. 

Here is a real-world DKIM key stored in a MaraDNS zone file:

```
x._domainkey.% +600 TXT 'v=DKIM1; k=rsa; '\   
'p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg'\   
'KCAQEAuhKjx2Aepa3rllxUEZLgF3x'\   
'68SWvZ8pEgnjZvxtqp94Vkra3AUC4C8dRLKf5SvT'\   
'xFtIl6pF27jn+M/w2MzYwPFjBgqVf'\   
'p2lf7xuKsrus63m0T9Sq958nIt1yuUlLDr71bFs7'\   
'ZuZyQid0ciCc2JF5lwHno10cAvuNJ';'y1Q'\   
'tFJa+lRJI6/kzY20Hi/ZTzFzctqgqaRZnSoJlTZHf'\    
'Oy0uwfmF5ejkJ8xvHbEJp6TEc'\   
'30DwsqrjVWSFLnUWYBv7lrAPB9sAHN7fCayhEuORn'\   
'Ap+YUhjjMPWyPla1pvTS9h/LTE7g'\   
'2d+jR/zOkRpV2Ak/4KpeP9dpsRJEOsPEaWGG1pQXgPw'\  
'IDAQAB'  
```

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

# AUTHOR

Sam Trenholme http://www.samiam.org/ 

# duende man page

# NAME

duende - run a child process as a daemon 

# DESCRIPTION

**duende** is a tool for users of init systems which require programs 
to provide their own daemonization. **duende** is not needed with 
systemd and other init systems which can provide daemonization for 
network services. **duende** makes a given child process a daemon. The 
standard output and standard error of the child process is logged via 
syslog() with a priority of LOG_INFO. 

# SYSTEMD

**duende** should not be used if one uses systemd` as the init 
process. Instead, files like this should be added to 
`/etc/systemd/system`

```
# Place this file here: 
# /etc/systemd/system/maradns.service 
# Then 
# systemctl enable maradns 
# systemctl start maradns 
# To view log 
# journalctl -u maradns 
[Unit] 
 After=network-online.target 
 ConditionPathExists=/usr/local/bin/maradns 
 Description=MaraDNS 
 Wants=network-online.target 
 
[Service] 
 ExecStart=/usr/local/bin/maradns 
 StandardOutput=journal 
 TimeoutSec=0 
 Type=exec 
 
[Install] 
 WantedBy=multi-user.target 
```

When installed with `make install`, MaraDNS will look for systemd 
files, and install MaraDNS and Deadwood startup files. 

# USAGE

**duende** (--pid=/path/to/file) child_process [ all subsequent 
arguments passed on to child ] 

# DETAILS

When **duende** is invoked, it spawns two processes. In addition to 
spawning the daemonized child process, **duende** also spawns a process 
which reads and logs the standard output of the daemonized process. The 
parent process stays alive so as to monitor the daemonized process. If 
the optional `--pid` argument is supplied, **duende** will write its 
PID to the file specified by the argument. It is an error to supply the 
`--pid` argument without an equal sign and file name. 

**duende** requires a blank directory named `/etc/maradns/logger` to 
run. 

Should the parent duende process a HUP signal, **duende** will restart 
the child process. Should the daemonized or logging process received an 
untrapped HUP signal or exit with an exit code of 8, **duende** will 
restart the process. Should the daemonized or logging process exit for 
any other reason, **duende** will send the logger process a TERM signal 
and exit. Should the duende parent process receive a TERM or INT 
signal, **duende** sends all of its children TERM signals, then exits. 

The duende process must be started as the superuser; this is because 
Duende's intended child processes (maradns and zoneserver) need to bind 
to privileged ports, and because duende uses a setuid() call to change 
the user ID of the logging process to the user with ID 707. 

# LOGGING

**duende** uses the syslog() facility to log the standard output of the 
program that it invokes. The name of the program (in other words, the 
"ident" given to openlog()) is the full path of the first argument 
given to **duende**. All messages created by the child process are sent 
to syslog() with a priority of LOG_INFO and a "facility" of LOG_DAEMON 
(daemon.info in /etc/syslog.conf); since daemon.info messages are not 
logged by default in FreeBSD, on FreeBSD systems messages generated by 
the child process are logged with a priority of LOG_ALERT and a 
"facility" of LOG_DAEMON (daemon.alert in /etc/syslog.conf). Should 
duende itself encounter an error, it will send messages to syslog() 
with a priority of LOG_ALERT. 

For example, suppose one invokes duende thusly:

```
	duende /usr/local/sbin/maradns 
```

If invoked thusly, duende will log all messages with the "ident" 
(program name) of "/usr/local/sbin/maradns". If this is not desired, 
invoke duende with something like:

```
	export PATH=$PATH:/usr/local/sbin 
	duende maradns 
```

This will log messages with a (more sensible) "ident" of maradns. 

Note: If a non-POSIX Bourne shell (such as csh, es, rc, or fish) is 
used to invoke MaraDNS, the above syntax needs to be changed. 

Also, the directory /etc/maradns/logger, while used by duende, is not 
used to store any log messages. That is unless, for some reason, one 
configures syslog to store messages there. 

# EXAMPLES

Using duende to start maradns, where the mararc file is /etc/mararc.2

```
	duende maradns -f /etc/mararc.2 
```

Using duende to start zoneserver, where the mararc file is 
/etc/mararc.4

```
	duende zoneserver -f /etc/mararc.4 
```

# BUGS

**Duende** assumes that all of its children are well-behaved, eating 
their vegetables, going to bed when told, and terminating when 
receiving a TERM signal. 

# SEE ALSO

**maradns(8)**, **syslog(3)** 
 http://www.maradns.org

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

# AUTHOR

Duende and this man page are written by Sam Trenholme. D Richard Felker 
III provided some invaluable assistance with the piping code which 
**duende** uses.  

# fetchzone man page

# NAME

fetchzone - get dns zone from server 

# DESCRIPTION

**fetchzone** transfers a user-specified dns zone from a zone server 
and displays it in csv2 format on the standard output. 

# USAGE

**fetchzone** zone_name zone_server_IP [query_class] 

# OPTIONS

**zone_name** 

Name of the dns zone to be transferred. 

**zone_server_IP** 

IP address of dns server 

**query_class** 

Optional argument which can change the query class from 1 (the default) 
to 255. This may be needed for some versions of Bind. 

# EXAMPLES

To obtain the zone example.com from the server 192.168.9.8:

```
fetchzone example.com 192.168.9.8  
```

To obtain the zone example.org from the server 10.9.8.78 using a query 
class of 255:

```
fetchzone example.com 10.9.8.78 255 
```

# BUGS

Fetchzone will not correctly output host names with utf-8 characters in 
them. 

# SEE ALSO

The man pages **maradns(8)** and **csv2(5)** 

http://www.maradns.org

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

# AUTHOR

Sam Trenholme  

# getzone man page

# NAME

getzone - get dns zone from server 

# DESCRIPTION

**getzone** transfers a user-specified dns zone from a zone server and 
displays it in csv1 format on the standard output. This program is here 
for compatibility with older setups that use getzone to get zone files; 
newer setups may wish to consider using the fetchzone tool to obtain 
csv2-compatible zone files. 

# USAGE

**getzone** zone_name zone_server_IP [query_class] 

# OPTIONS

**zone_name** 

Name of the dns zone to be transferred. 

**zone_server_IP** 

IP address of dns server 

**query_class** 

Optional argument which can change the query class from 1 (the default) 
to 255. This may be needed for some versions of Bind. 

# EXAMPLES

To obtain the zone example.com from the server 192.168.9.8:

```
getzone example.com 192.168.9.8  
```

To obtain the zone example.org from the server 10.9.8.78 using a query 
class of 255:

```
getzone example.com 10.9.8.78 255 
```

# SEE ALSO

The man pages **maradns(8)** and **csv1(5)** 

http://www.maradns.org

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

# AUTHOR

MaraDNS is written by Sam Trenholme. Jaakko Niemi used 5 minutes to put 
this manpage together. Sam has subsequently made revisions to this 
manpage.  

# maradns man page

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

# mararc man page

# NAME

mararc - Format of the mararc zone file that MaraDNS uses 

# MARARC FILE FORMAT

Mararc files use a syntax that is a subset of Python 2.2.3 syntax. In 
particular, Python 2.2.3 (and possibly other versions of Python) can 
read a properly formatted mararc file without error. 

Unlike Python, however, a mararc file can only use certain variable 
names, and the variables can only be declared as described below.

# COMMENTS

Comments (lines ignored by the MaraDNS parser) start with the '#' 
character, like this:

```
# This is a comment 
```

The MaraDNS parser also ignores lines which contain only white 
space. 

# OPERATORS

The MaraRC file supports two operators: = and += 

The = operator can be used to assign both numeric and string values 

The += operator can only be used on string values, and concatenates the 
value to the right of the += operator to the string specified to the 
left of the += operator. 

Examples:

```
ipv4_bind_addresses = "10.2.19.83" 
ipv4_bind_addresses += ",10.2.66.74" 
ipv4_bind_addresses += ",10.3.87.13" 
```

ipv4_bind_addresses now has the value 
"10.2.19.83,10.2.66.74,10.3.87.13"

```
ipv4_alias["icann"] = "198.41.0.4" 
ipv4_alias["icann"] += ",192.228.79.201" 
ipv4_alias["icann"] += ",192.33.4.12,128.8.10.90" 
```

# MARARC VARIABLES

Follows is a listing of variables that can be declared in the mararc 
file. 

# DICTIONARY VARIABLE FORMAT

A **dictionary variable** is an array that can have multiple elements. 
Unlike a traditional array, these arrays are indexed by strings instead 
of numbers. These are analogous to associative arrays, or what Perl 
somewhat inaccurately calls hashes. 

The syntax of a dictionary variable is in the following form:

```
name["index"] = "value" 
```

Where **name** is the name of the dictionary variable, **index** 
is the index of the array, and **value** is the value stored at that 
index. 

Every time we have a dictionary-type variable (such as csv2), we must 
first initialize it using a line in the following form:

```
csv2 = {} 
```

Here, csv2 is the name of the "dictionary" variable that we are 
initializing. 

# DICTIONARY VARIABLES

Here is a listing of all "dictionary"-style variables that MaraDNS 
uses: 

## csv2

The csv2 dictionary variable stores all of the zone names and file 
names for the zone files that MaraDNS uses. Note that csv2 files are 
read after MaraDNS is chrooted. Hence the filename is relative to the 
chroot_dir. Example:

```
csv2["example.net."] = "db.example.net" 
```

See **csv2(5)** for a description of this file's format. 

The dictionary index (zone name) can not have a * in it. If it does, 
MaraDNS will terminate with an "Illegal zone name" error. 

Please note that, in order to reload a zone file, it is necessary to 
restart MaraDNS and reload all zone files. MaraDNS uses a hash data 
format which loads records very quickly from memory, but requires a 
restart to update. 

## csv1

csv1: Used to indicate the filename to use for a given zone stored in 
the legacy csv1 zone file format. This is primarily for compatibility 
with people who have maradns-1.0 zone files.

```
csv1["zone"] = "filename" 
```

**csv1**: A pipe-separated-file. See **csv1(5)**. 

**zone**: the zone that file in question is authoritative for 

**filename**: the file with the CSV1 zone data 

Note that csv1 files are read after MaraDNS is chrooted, and, hence the 
filename is relative to the chroot_dir. 

See the **csv1(5)** man page for more information on this file format. 

## ipv4_alias

ipv4_alias: Used to give nicknames or aliases for ip/netmask pairs for 
ipv4 (standard 32-bit) IP addresses.

```
ipv4_alias["name"] = "ip1/netmask,ip2/netmask,etc" 
```

**name**: The name of the alias in question 

**ip**: The ip portion of an ip/netmask pair 

**netmask**: the mask portion of an ip/netmask pair 

**,**: Used to separate ip/netmask pairs. Spaces may be placed before 
or after this comma. 

An ip is in dotted-decimal format, e.g. "10.1.2.3". 

The netmask can be in one of two formats: A single number between 1 and 
32, which indicates the number of leading "1" bits in the netmask, or a 
4-digit dotted-decimal netmask. 

The netmask is used to specify a range of IPs.

## ipv4_alias examples

**10.1.1.1/24** indicates that any ip from 10.1.1.0 to 10.1.1.255 will 
match. 

**10.1.1.1/255.255.255.0** is identical to 10.1.1.1/24 

**10.2.3.4/16** indicates that any ip from 10.2.0.0 to 10.2.255.255 
will match. 

**10.2.3.4/255.255.0.0** is identical to 10.2.3.4/16 

**127.0.0.0/8** indicates that any ip with "127" as the first octet 
(number) will match. 

**127.0.0.0/255.0.0.0** is identical to 127.0.0.0/8 

The netmask is optional, and, if not present, indicates that only a 
single IP will "match". e.g: 

**10.9.9.9/32**, **10.9.9.9/255.255.255.255**, and **10.9.9.9** are all 
functionally identical, and indicate that only the ip 10.9.9.9 will 
match. 

The significance of "match" depends on what we use the ipv4 alias for. 

ipv4 aliases can nest. E.g:

```
ipv4_alias["susan"] = "10.6.7.8/24"  
ipv4_alias["office"] = "susan,10.9.9.9" 
```

Where "susan" in the "office" alias matches the value of the 
ipv4_alias susan. 

Multiple levels of nesting are allowed. Self-referring nests will 
result in an error.

# NORMAL VARIABLE FORMAT

Normal variables. These are variables that can only take a single 
value. 

The syntax of a normal variable is in the form

```
name = "value" 
```

Where **name** is the name of the normal variable, and **value** 
is the value of the variable in question. 

# NORMAL VARIABLES

Here is a listing of normal variables that MaraDNS uses: 

## ipv4_bind_addresses

ipv4_bind_addresses: The IP addresses to give the MaraDNS server. 

This accepts one or more ipv4 IPs in dotted-decimal (e.g. "127.0.0.1") 
notation, and specifies what IP addresses the MaraDNS server will 
listen on. Multiple bind addresses are separated with a comma, like 
this: "10.1.2.3, 10.1.2.4, 127.0.0.1"

## admin_acl

This is a list of ip/netmask pairs that are allowed to get certain 
administrative information about MaraDNS, including: 

* The version number of MaraDNS running

* The number of threads MaraDNS has

* MaraDNS' internal timestamp value

Note that this information is not available unless the mararc variable 
debug_msg_level is sufficiently high. See the information on 
debug_msg_level below for details on this and on the TXT queries sent 
to get the above information. 

## bind_address

bind_address: The IP address to give the MaraDNS server. 

This accepts a single IP in dotted-decimal (e.g. "127.0.0.1") notation, 
and specifies what IP address the MaraDNS server will listen on. Note 
that ipv4_bind_addresses has the same functionality. This name is 
included so that old MaraDNS configuration files will continue to work 
with new MaraDNS releases.

## bind_star_handling

In the case where there is both a star record for a given name and 
recordtype, a non-star record with the same name but a different 
recordtype, and no record for the given name and recordtype, MaraDNS 
will usually return the star record. BIND, on the other hand, will 
return a "not there" reply. In other words: 

* If a non-A record for `foo.example.com` exists

* An A record for `*.example.com` exists

* No A record for `foo.example.com` exists

* And the user asks for the A record for `foo.example.com`

* MaraDNS will usually return the A record attached to `*.example.com`

* BIND, on the other hand, returns a "not there" for `foo.example.com`

If the BIND behavior is desired, set `bind_star_handling` to 1. 
Otherwise, set this to 0. In MaraDNS 1.3, this has a default value of 
1. 

In addition, if there is a star record that could match any given 
record type, when bind_star_handling is 1, it makes sure that MaraDNS 
does not incorrectly return a NXDOMAIN (RFC 4074 section 4.2). 

Also, if bind_star_handling has a value of 2, MaraDNS will handle the 
following case exactly as per section 4.3.3 of RFC1034: 

* If a record for `foo.example.com` exists

* An A record for `*.example.com` exists

* And the user asks for the A record for `bar.foo.example.com`

* MaraDNS will usually return the A record attached to `*.example.com`

* RFC1034 section 4.3.3 says one should return a NXDOMAIN.

MaraDNS will exit with a fatal error if `bind_star_handling` has any 
value besides 0, 1, or 2. 

## chroot_dir

chroot_dir: The directory MaraDNS chroots to 

This accepts a single value: The full path to the directory to use as a 
chroot jail. 

Note that csv1 zone files are read after the chroot operation. Hence, 
the chroot jail needs to have any and all zone files that MaraDNS will 
load. 

## csv2_default_zonefile

This is a special zone file that allows there to be stars at the *end* 
of hostnames. This file is similar to a normal csv2 zone file, but has 
the following features and limitations: 

* Stars are allowed at the end of hostnames

* A SOA record is mandatory

* NS records are mandatory

* Neither CNAME, FQDN4, nor FQDN6 records are permitted in the zone 
  file

* Delegation NS records are not permitted in the zone file

* Default zonefiles may not be transferred via zone transfer

* Both recursion and default zonefiles may not be enabled at the same 
  time

## csv2_synthip_list

Sometimes the IP list of nameservers will be different than the 
nameservers one is bound to. This allows the synthetic nameserver list 
to have different IPs. 

Note that this may act in an unexpected manner if routable and 
non-routable (localhost and RFC1918) addresses are combined; in 
particular, a list with both routable and non-routable addresses will 
discard the non-routable IP addresses, and a list with rfc1918 and 
localhost addresses will discard the localhost addresses. 

## csv2_tilde_handling

How the csv2 zone file parser handles tildes (the ~ character) in csv2 
zone files. This is a numeric record, with a possible value between 0 
and 3 (four possible values). The way the csv2 parser acts at different 
csv2_tilde_handling levels: 

* 0) The csv2 parser behaves the same as it does in old MaraDNS 
  releases: The tilde has no special significance to the parser.

* 1) A tilde is not allowed anywhere in a csv2 zone file.

* 2) A tilde is only allowed between records in a csv2 zone file. If a 
  tilde is between the first record and the second record, a tilde 
  is required to be between all records. Otherwise, a tilde is not 
  allowed anywhere in a csv2 zone file. The first record can not be 
  a TXT, WKS, or LOC record.

* 3) A tilde is required to be between all records in a csv2 zone 
  file.

The default value for csv2_tilde_handling is 2; this allows 
compatibility with older zone files without tildes while allowing zone 
files to be updated to use the tilde to separate resource records. 

## debug_msg_level

This is a number indicating what level of information about a running 
MaraDNS process should be made public. When set to 0, no information 
will be made public. 

When set to one (the default), or higher, a Tversion.maradns. (TXT 
query for "version.maradns.") query will return the version number of 
MaraDNS. 

When set to two or higher, a Tnumthreads.maradns. (TXT query for 
"numthreads.maradns.") query will return the number of threads that 
MaraDNS is currently running, and a Tcache-elements.maradns. query will 
return the number of elements in MaraDNS' cache. 

If MaraDNS is compiled with debugging information on, a 
Tmemusage.maradns. query will return the amount of memory MaraDNS has 
allocated. Note that the overhead for tracking memory usage is 
considerable and that compiling MaraDNS with "make debug" will greatly 
slow down MaraDNS. A debug build of MaraDNS is **not** recommended for 
production use. 

When set to three or higher, a Ttimestamp.maradns. query will return, 
in seconds since the UNIX epoch, the timestamp for the system MaraDNS 
is running on.

## default_rrany_set

This variable used to determine what kind of resource records were 
returned when an ANY query was sent. In MaraDNS, the data structures 
have since been revised to return any resource record type when an ANY 
query is sent; this variable does nothing, and is only here so that old 
MaraDNS mararc files will continue to work. The only accepted values 
for this variable were 3 and 15. 

## dns_port

This is the port that MaraDNS listens on. This is usually 53 (the 
default value), but certain unusual MaraDNS setups (such as when 
resolving dangling CNAME records on but a single IP) may need to have a 
different value for this. 

## dos_protection_level

If this is set to a non-zero value, certain features of MaraDNS will be 
disabled in order to speed up MaraDNS' response time. This is designed 
for situations when a MaraDNS server is receiving a large number of 
queries, such as during a denial of service attack. 

This is a numeric variable; its default value is zero, indicating that 
all of MaraDNS' normal features are enabled. Higher numeric values 
disable more features: 

* A dos_protection_level between 1 and 78 (inclusive) disables getting 
  MaraDNS status information remotely.

* A dos_protection_level of 8 or above disables CNAME lookups.

* A dos_protection_level or 12 or above disables delegation NS 
  records.

* A dos_protection_level of 14 or above disables ANY record 
  processing.

* A dos_protection_level of 18 or above disables star record 
  processing at the beginning of hostnames (default zonefiles still 
  work, however).

* A dos_protection_level of 78 disables all authoritative processing, 
  including default zonefiles.

The default level of dos_protection_level is 0 when there are one or 
more zonefiles; 78 when there are no zone files. 

## ipv6_bind_address

If MaraDNS is compiled with as an authoritative server, then this 
variable will tell MaraDNS which ipv6 address for the UDP server to; 
for this variable to be set, MaraDNS must be bound to at least one ipv4 
address. 

## hide_disclaimer

If this is set to "YES", MaraDNS will not display the legal disclaimer 
when starting up. 

## long_packet_ipv4

This is a list of IPs which we will send UDP packets longer than the 
512 bytes RFC1035 permits if necessary. This is designed to allow 
`zoneserver`, when used send regular DNS packets over TCP, to receive 
packets with more data than can fit in a 512-byte DNS packet. 

This variable only functions if MaraDNS is compiled as an authoritative 
only server. 

## maradns_uid

maradns_uid: The numeric UID that MaraDNS will run as 

This accepts a single numerical value: The UID to run MaraDNS as. 

MaraDNS, as soon as possible drops root privileges, minimizing the 
damage a potential attacker can cause should there be a security 
problem with MaraDNS. This is the UID maradns becomes. 

The default UID is 707. 

## maradns_gid

maradns_gid: The numeric GID that MaraDNS will run as. 

This accepts a single numerical value: The GID to run MaraDNS as. 

The default GID is 707. 

## max_ar_chain

max_ar_chain: The maximum number of records to display if a record in 
the additional section (e.g., the IP of a NS server or the ip of a MX 
exchange) has more than one value. 

This is similar to max_chain, but applies to records in the 
"additional" (or AR) section. 

Due to limitations in the internal data structures that MaraDNS uses to 
store RRs, if this has a value besides one, round robin rotates of 
records are disabled. 

The default value for this variable is 1. 

## max_chain

max_chain: The maximum number of records to display in a chain of 
records. 

With DNS, it is possible to have more than one RR for a given domain 
label. For example, "example.com" can have, as the A record, a list of 
multiple ip addresses. 

This sets the maximum number of records MaraDNS will show for a single 
RR. 

MaraDNS normally round-robin rotates records. Hence, all records for a 
given DNS label (e.g. "example.com.") will be visible, although not at 
the same time if there are more records than the value allowed with 
max_chain 

The default value for this variable is 8. 

## max_tcp_procs

max_tcp_procs: The (optional) maximum number of processes the zone 
server is allowed to run. 

Sometimes, it is desirable to have a different number of maximum 
allowed tcp processes than maximum allowed threads. If this variable is 
not set, the maximum number of allowed tcp processes is "maxprocs". 

## max_total

max_total: The maximum number of records to show total for a given DNS 
request. 

This is the maximum total number of records that MaraDNS will make 
available in a DNS reply. 

The default value for this variable is 20. 

## max_mem

max_mem is the maximum amount of memory we allow MaraDNS to allocate, 
in bytes.

The default value of this is to allocate 2 megabytes for MaraDNS' 
general use, and in addition, to allocate 3072 bytes for each element 
we can have in the cache or DNS record that we are authoritatively 
serving. 

## min_visible_ttl

min_visible_ttl: The minimum value that we will will show as the TTL 
(time to live) value for a resource record to other DNS servers and 
stub resolvers. In other words, this is the minimum value we will ask 
other DNS server to cache (keep in their memory) a DNS resource record. 

The value is in seconds. The default value for this is 30; the minimum 
value this can have is 5. 

As an aside, RFC1123 section 6.1.2.1 implies that zero-length TTL 
records should be passed on with a TTL of zero. This, unfortunately, 
breaks some stub resolvers (such as Mozilla's stub resolver). 

## remote_admin

remote_admin: Whether we allow `verbose_level` to be changed after 
MaraDNS is started. 

If `remote_admin` is set to 1, and `admin_acl` is set, any and all IPs 
listed in `admin_acl` will be able to reset the value of 
`verbose_level` from any value between 0 and 9 via a TXT query in the 
form of `5.verbose_level.maradns.` What this will do is set 
`verbose_query` to the value in the first digit of the query. 

This is useful when wishing to temporarily increase the `verbose_level` 
to find out why a given host name is not resolving, then decreasing 
`verbose_level` so as to minimize the size of MaraDNS' log. 

## rfc8482

If this is set to 1, MaraDNS will not allow ANY queries, sending a 
RFC8482 response if one is given to MaraDNS. If this is 0, ANY queries 
are allowed. Default value: 1 

## synth_soa_origin

When a CSV2 zone file doesn't have a SOA record in it, MaraDNS 
generates a SOA record on the fly. This variable determines the host 
name for the "SOA origin" (which is called the MNAME in RFC1035); this 
is the host name of the DNS server which has the "master copy" of a 
given DNS zone's file. 

This host name is in human-readable format without a trailing dot, 
e.g.:

```
synth_soa_origin = "ns1.example.com" 
```

If this is not set, a synthetic SOA record will use the name of 
the zone for the SOA origin (MNAME) field.

## synth_soa_serial

This determines whether we strictly follow RFC1912 section 2.2 with SOA 
serial numbers. If this is set to 1 (the default value), we do not 
strictly follow RFC1912 section 2.2 (the serial is a number, based on 
the timestamp of the zone file, that is updated every six seconds), but 
this makes it so that a serial number is guaranteed to be automatically 
updated every time one edits a zone file. 

If this is set to 2, the SOA serial number will be in YYYYMMDDHH 
format, where YYYY is the 4-digit year, MM is the 2-digit month, DD is 
the 2-digit day, and HH is the 2-digit hour of the time the zone file 
was last updated (GMT; localtime doesn't work in a chroot() 
environment). While this format is strictly RFC1912 compliant, the 
disadvantage is that more than one edit to a zone file in an hour will 
not update the serial number. 

I strongly recommend, unless it is extremely important to have a DNS 
zone that generates no warnings when tested at dnsreport.com, to have 
this set to 1 (the default value). Having this set to 2 can result in 
updated zone files not being seen by slave DNS servers. 

Note that synth_soa_serial can only have a value of 1 on the native 
Windows port. 

On systems where time_t is 32-bit, MaraDNS will always act as if 
`synth_soa_serial` has a value of 1. This is to avoid having MaraDNS 
use invalid time and date values starting in late January of 2038; 
systems with a 32-bit time_t can very well have their underlying system 
libraries with regards to dates and times no longer correctly function 
come 2038. 

## tcp_convert_acl

This only applies to the zoneserver (general DNS-over-TCP) program. 

This is a list of IPs which are allowed to connect to the zoneserver 
and send normal TCP DNS requests. The zoneserver will convert TCP DNS 
requests in to UDP DNS requests, and send the UDP request in question 
to the server specified in **tcp_convert_server**. Once it gets a reply 
from the UDP DNS server, it will convert the reply in to a TCP request 
and send the reply back to the original TCP client. 

Whether the RD (recursion desired) flag is set or not when converting a 
TCP DNS request in to a UDP DNS request is determined by whether the 
TCP client is on the **recursive_acl** list. Since MaraDNS 2.0 does not 
have recursion, the maradns daemon ignores the RD bit (Deadwood will 
not process any queries without the RD bit set). 

## tcp_convert_server

This only applies to the zoneserver (general DNS-over-TCP) program. 

This is the UDP server which we send a query to when converting DNS TCP 
queries in to DNS UDP servers. Note that, while this value allows 
multiple IPs, all values except the first one are presently ignored. 

## timestamp_type

timestamp_type: The type of timestamp to display. The main purpose of 
this option is to suppress the output of timestamps. Since duende uses 
syslog() to output data, and since syslog() adds its own timestamp, 
this option should be set to 5 when maradns is invoked with the duende 
tool. 

This option also allows people who do not use the duende tool to view 
human-readable timestamps. This option only allows timestamps in GMT, 
due to issues with showing local times in a chroot() environment. 

This can have the following values:  

`0` The string "Timestamp" followed by a UNIX timestamp 

`1` Just the bare UNIX timestamp 

`2` A GMT timestamp in the Spanish language 

`3` A (hopefully) local timestamp in the Spanish language 

`4` A timestamp using asctime(gmtime()); usually in the English 
language 

`5` No timestamp whatsoever is shown (this is the best option when 
maradns is invoked with the `duende` tool). 

`6` ISO GMT timestamp is shown 

`7` ISO local timestamp is shown  

On systems where time_t is 32-bit, MaraDNS will always act as if 
`timestamp_type` has a value of 5, never showing a timestamp. This is 
to avoid having MaraDNS show an invalid timestamp starting in late 
January of 2038; systems with a 32-bit time_t can very well have their 
underlying system libraries with regards to dates and times no longer 
correctly function come 2038. 

The default value for this variable is 5. 

## verbose_level

verbose_level: The number of messages we log to stdout 

This can have five values:  

`0` No messages except for the legal disclaimer and fatal parsing 
errors 

`1` Only startup messages logged (Default level) 

`2` Error queries logged 

`3` All queries logged 

`4` All actions adding and removing records from the cache logged  

The default value for this variable is 1. 

## zone_transfer_acl

zone_transfer_acl: List of ips allowed to perform zone transfers with 
the zone server 

The format of this string is identical to the format of an ipv4_alias 
entry. 

# EXAMPLE MARARC FILE

```
 
# Example mararc file (unabridged version) 
 
# The various zones we support 
 
# We must initialize the csv2 hash, or MaraDNS will be unable to 
# load any csv2 zone files 
csv2 = {} 
 
# This is just to show the format of the file 
#csv2["example.com."] = "db.example.com" 
 
# The address this DNS server runs on.  If you want to bind  
# to multiple addresses, separate them with a comma like this: 
# "10.1.2.3,10.1.2.4,127.0.0.1" 
ipv4_bind_addresses = "127.0.0.1" 
# The directory with all of the zone files 
chroot_dir = "/etc/maradns" 
# The numeric UID MaraDNS will run as 
maradns_uid = 99 
# The (optional) numeric GID MaraDNS will run as 
# maradns_gid = 99 
 
# Normally, MaraDNS has some MaraDNS-specific features, such as DDIP 
# synthesizing, a special DNS query ("erre-con-erre-cigarro.maradns.org."  
# with a TXT query returns the version of MaraDNS that a server is  
# running), unique handling of multiple QDCOUNTs, etc.  Some people  
# might not like these features, so I have added a switch that lets  
# a sys admin disable all these features.  Just give "no_fingerprint"  
# a value of one here, and MaraDNS should be more or less  
# indistinguishable from a tinydns server. 
no_fingerprint = 0 
 
# These constants limit the number of records we will display, in order 
# to help keep packets 512 bytes or smaller.  This, combined with round_robin 
# record rotation, help to use DNS as a crude load-balancer. 
 
# The maximum number of records to display in a chain of records (list 
# of records) for a given host name 
max_chain = 8 
# The maximum number of records to display in a list of records in the 
# additional section of a query.  If this is any value besides one, 
# round robin rotation is disabled (due to limitations in the current 
# data structure MaraDNS uses) 
max_ar_chain = 1 
# The maximum number of records to show total for a given question 
max_total = 20 
 
# The number of messages we log to stdout 
# 0: No messages except for fatal parsing errors and the legal disclaimer 
# 1: Only startup messages logged (default) 
# 2: Error queries logged 
# 3: All queries logged (but not very verbosely right now) 
verbose_level = 1 
 
# Here is a ACL which restricts who is allowed to perform zone transfer from  
# the zoneserver program 
 
# Simplest form: 10.1.1.1/24 (IP: 10.1.1.1, 24 left bits in IP need to match) 
# and 10.100.100.100/255.255.255.224 (IP: 10.100.100.100, netmask 
# 255.255.255.224) are allowed to connect to the zone server  
# NOTE: The "maradns" program does not serve zones.  Zones are served 
# by the "zoneserver" program. 
#zone_transfer_acl = "10.1.1.1/24, 10.100.100.100/255.255.255.224" 
 
```

# BUGS

If one should declare the same the same index twice with a dictionary 
variable, MaraDNS will exit with a fatal error. This is because earlier 
versions of MaraDNS acted in a different manner than Python 2.3.3. With 
Python 2.3.3, the last declaration is used, while MaraDNS used to use 
the first declaration. 

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

# zoneserver man page

# NAME

zoneserver - handle zone transfers and other TCP functions for MaraDNS 

# DESCRIPTION

**zoneserver** listens on port 53/tcp and handles DNS zone transfers 
and any DNS query done over TCP instead of UDP. **zoneserver** uses a 
configuration file, **/etc/mararc** by default, to determine its 
parameters. 

# USAGE

**zoneserver -f** pointer_to_mararc_file 

# OPTIONS

`-f` Specifies the location of the configuration file. MaraDNS uses the 
same configuration file for both the main dns server and the 
zoneserver.  

# CONFIGURATION FILE FORMAT

The file format for the mararc file can be found in the **mararc(5)** 
manual page. In particular, the zoneserver uses the zone_transfer_acl, 
tcp_convert_acl, tcp_convert_server, and bind_address mararc 
parameters. 

# EXAMPLE MARARC FILE

In this example mararc file, which is used both by maradns and 
zoneserver, we allow 10.1.2.3, 10.1.14.7, and 192.168.116.{any} to 
transfer zones, and we allow anyone on the internet to perform TCP 
queries. The only zone served in this example is example.com:

```
ipv4_bind_addresses = "10.1.1.1" # Our IP 
tcp_convert_server = "10.1.1.1" # IP of UDP DNS server 
tcp_convert_acl = "0.0.0.0/0" # Anyone may do DNS-over-TCP 
chroot_dir = "/etc/maradns" # Where zone files are 
csv2 = {} # Initialize list of zone files 
csv2["example.com."] = "db.example.com" # example.com zone file 
# The next line is a list of who can transfer zones from us 
zone_transfer_acl = "10.1.2.3, 10.1.14.7, 192,168.116.0/24" 
```

# SEE ALSO

The man pages **maradns(8)** and **mararc(5)** 

http://www.maradns.org

# BUGS

**zoneserver** assumes that the authoritative NS records are 
immediately after the SOA record, and that there is at least one non-NS 
between that last authority NS record for the zone and the first 
delegation NS record. 

IXFR requests are incremental zone transfers, meaning that the DNS 
server should only display records changed since the last IXFR request. 
**zoneserver**, however, treats an IXFR as if it were an AXFR request, 
outputting all of the records for the zone in question. 

**zoneserver** closes the TCP connection after transferring the 
requested zone. 

If an unauthorized client attempts to connect to the zoneserver, 
**zoneserver** immediately disconnects the unauthorized client. 

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

# AUTHOR

MaraDNS is written by Sam Trenholme. Jaakko Niemi used 5 minutes to put 
the original version this manpage together. Sam has subsequently 
revised this manual page.  

