# coLunacyDNS 

coLunacyDNS is a simply IPv4 and IPv6 forwarding DNS server (with
support only for IPv4 and IPv6 IP records) controlled by a Lua script.
It allows a lot of flexibility because it uses a combination of C for
high performance and Lua for maximum control.

The current version of coLunacyDNS is version 1.0.010, made in December
of 2020.

All example configuration files here are public domain.

# Getting started

On a CentOS 8 Linux system, this gets us started:

```bash
make
su
./coLunacyDNS -d
```

If one has `clang` instead of GCC:

```
make CC="clang"
```

Here, we use `coLunacyDNS.lua` as the configuration file.

Since coLunacyDNS runs on port 53, we need to start it as root.
As soon as coLunacyDNS binds to port 53 and seeds its internal 
secure pseudo random number generator, it calls `chroot` and drops
root privileges.  It runs as the user and group with the user ID of
707; this value can be changed by altering `UID` and `GID` in the
source code.

Cygwin users may use `make -f Makefile.cygwin` (or, if one prefers,
`make CFLAGS="-O3 -DCYGWIN"` also works) to compile coLunacyDNS, 
since Cygwin does not have the same sandboxing Linux has.  The
Windows binary does not have sandboxing, but other measures are
taken to minimize security risks.

# Configration file examples

In this example, we listen on 127.0.0.1, and, for any IPv4 query,
we return the IP of that query as reported by 9.9.9.9.

```lua
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
function processQuery(Q) -- Called for every DNS query received
   -- Connect to 9.9.9.9 for the query given to this routine
   local t = coDNS.solve({name=Q.coQuery, type="A", upstreamIp4="9.9.9.9"})
   -- Return a "server fail" if we did not get an answer
   if(t.error or t.status ~= 1) then return {co1Type = "serverFail"} end
   -- Otherwise, return the answer
   return {co1Type = "A", co1Data = t.answer}
end
```

As an even simpler example, we always return "10.1.1.1" for any DNS
query given to us:

```lua
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
function processQuery(Q) -- Called for every DNS query received
  return {co1Type = "A", co1Data = "10.1.1.1"}
end
```

We can also set the `AA` (authoritative answer) flag, the `RA` 
(recursion available) flag, and the TTL (time to live) for our 
answer.  In this example, both the `AA` and `RA` flags are set, and
the answer is given a time to live of one hour (3600 seconds).

```lua
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
function processQuery(Q) -- Called for every DNS query received
  return {co1Type = "A", co1Data = "10.1.1.1", 
          co1AA = 1, co1RA = 1, co1TTL = 3600}
end
```

In this example, where we bind to both IPv4 and IPv6 localhost, we return
`10.1.1.1` for all IPv4 `A` queries, `2001:db8:4d61:7261:444e:5300::1234`
for all IPv6 `AAAA` queries, and "not there" for all other query types:

```lua
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
bindIp6 = "::1" -- Localhost for IPv6
function processQuery(Q) -- Called for every DNS query received
  if Q.coQtype == 28 then
    return {co1Type = "ip6",co1Data="2001-0db8-4d61-7261 444e-5300-0000-1234"}
  elseif Q.coQtype == 1 then
    return {co1Type = "A", co1Data = "10.1.1.1"}
  else
    return {co1Type = "notThere"}
  end
end
```

Note that coLunacyDNS *always* binds to an IPv4 address; if `bindIp` is
not set, coLunacyDNS will bind to `0.0.0.0` (all available IPv4 addresses).

In this example, we contact the DNS server 9.9.9.9 for 
IPv4 queries, and 149.112.112.112 for IPv6 queries:

```lua
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
bindIp6 = "::1" -- Localhost for IPv6
function processQuery(Q) -- Called for every DNS query received
  local t
  if Q.coQtype == 28 then -- Request for IPv6 IP
    t = coDNS.solve({name=Q.coQuery,type="ip6", upstreamIp4="149.112.112.112"})
  elseif Q.coQtype == 1 then -- Request for IPv4 IP
    t = coDNS.solve({name=Q.coQuery, type="A", upstreamIp4="9.9.9.9"})
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

```lua
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
list; see the file `make.blocklist.sh` in the upper level directory
for the tool used to make the file we read to find domains to 
block.

```lua
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

  if Q.coQtype ~= 1 and Q.coQtype ~= 28 then -- If not IPv4 or IPv6 IP query
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

```lua
-- coLunacyDNS configuration
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1

-- Examples of three API calls we have: timestamp, rand32, and rand16
coDNS.log(string.format("Timestamp: %.1f",coDNS.timestamp())) -- timestamp
coDNS.log(string.format("Random32: %08x",coDNS.rand32())) -- random 32-bit num
coDNS.log(string.format("Random16: %04x",coDNS.rand16())) -- random 16-bit num
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

  -- We will use 8.8.8.8 as the upstream server if the query ends in ".tj"
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
  local t = coDNS.solve({name=Q.coQuery, type="A", upstreamIp4=upstream})

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
    return {co1Type = "A", co1Data = "10.1.1.1"} -- Answer for anything.invalid
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

* Only the `math`, `string`, and `bit32` libraries are loaded from
  Lua's standard libs.  (bit32 actually is another Bit library, but with a
  `bit32` interface.)
* A special `coDNS` library is also loaded.
* The program is designed to give Lua very limted access to the 
  filesystem nor be able to do anything malicious.
* `coDNS.open1()` can only open a file in the directory coLunacyDNS is
  called from; it can not open files in other directories.
* All DNS `ANY` and `HINFO` queries are given a RFC8482 response.

# Limitations

coLunacyDNS only processes requests for DNS `A` queries and DNS `AAAA`
queries — queries for IPv4 and IPv6 IP addresses.  Information about
other query types is not available to coLunacyDNS, and it can only return
`A` queries, `AAAA` queries, “server fail”, or “this name is not
here” in its replies.

coLunacyDNS, likewise, can only send `A` (IPv4 IP) and `AAAA` (IPv6 IP)
requests to upstream servers.  While coLunacyDNS can process and forward
IPv6 DNS records, and while coLunacyDNS can bind to IPv4 and IPv6 IPs, it
can not send queries to upstream DNS servers via IPv6, and `coLunacyDNS`
must always have an IPv4 address to bind to.

# The API available to the Lua script

coLunacyDNS, when running Lua code, has access to the Lua 5.1 versions
of the `math` and `string` libraries.  The math library has the
functions `math.abs`, `math.acos`, `math.asin`, `math.atan`, `math.atan2`,
`math.ceil`, `math.cos`, `math.cosh`, `math.deg`, `math.exp`,
`math.floor`, `math.fmod`, `math.frexp`, `math.huge`, `math.ldexp`,
`math.log`, `math.log10`, `math.max`, `math.min`, `math.modf`, `math.pi`,
`math.pow`, `math.rad`, `math.random`, `math.randomseed`, `math.sin`,
`math.sinh`, `math.sqrt`, `math.tan`, and `math.tanh`.  Almost all of
them are the same as they are in Lua 5.1; the only one which is different
is `math.random`, which uses RadioGatun[32] instead of `rand` to generate
random numbers, `math.randomseed`, which takes a string as the random seed
(if a number is given, Lua uses coercion to convert the number in to a 
string), and `math.rand16()` (not available in stock Lua) which returns
a 16-bit random integer between 0 and 65535.

coLunacyDNS also has access to the string library: `string.byte`,
`string.char`, `string.dump`, `string.find`, `string.format`,
`string.gmatch`, `string.gsub`, `string.len`, `string.lower`,
`string.match`, `string.rep`, `string.reverse`, `string.sub`, and
`string.upper`.  All of these are as per Lua 5.1.  

`string.match(str, pattern)`, for example, looks for the regular 
expression `pattern` in the string `str`; regular expression are
non-Perl compatible Lua regular expressions.  There are number of
changes; one being that, instead of using `\` to escape characters, 
Lua regular expressions use `%` (so `%.` matches against a literal
dot, while `.` matches against any character).

While Lua 5.1 does not include the `bit32` library, coLunacyDNS uses a
bit manipulation library with an interface like `bit32`: The numbers are
32-bit numbers, and the function calls are `bit32.arshift`, `bit32.band`,
`bit32.bnot`, `bit32.bor`, `bit32.bxor`, `bit32.lshift`, `bit32.rshift`,
and `bit32.rrotate`.  

coLunacyDNS also includes a few functions in its own `coDNS` space:

* `coDNS.log`  This takes a single string as its input, and logs the
  string in question.  The logging method depends on the OS being 
  used: In Windows it writes to a log file; in *NIX it currently
  outputs the message on standard output.  If `logLevel` is 0,
  its output on *NIX is buffered; if `logLevel` is 1 or higher,
  its output is flushed after every call to coDNS.log.
* `coDNS.timestamp` This returns coLunacyDNS's internal time 
  representation.  This is not a standard *NIX timestamp; instead it's 
  a special timestamp generated by coLunacyDNS in a Y2038-compliant 
  manner (in places where `time_t` is 32-bit and we do not have an 
  alternate API to get numbers, we assume negative timestamps are in
  the future; on Windows 32-bit, we use the Y2038 compatible 64-bit
  Windows NT `fileTime` timestamps; and on places with a 64-bit `time_t`,
  we consider the timestamp accurate and merely convert it).  Each second
  has 256 ticks.
* `coDNS.rand32` This returns a random integer between 0 and 4294967295.
* `coDNS.rand16` This returns a random integer between 0 and 65535.
* `coDNS.solve` This function, which can only be called inside of
  `processQuery`, requests a DNS record from another DNS server, and
  returns once the data is available (or if the DNS server does not 
  respond, or if it gives us a reply that we did not get a record).
  This function is described in more detail in the following section.
* `coDNS.open1`, `coDNS.read1`, and `coDNS.close1` can be used to
  read a text file in the same directory that coLunacyDNS is being 
  run from.  Details are below, after the `coDNS.solve` section.

# coDNS.solve

This function is given a table with three members: 

* `name`, which is the DNS name in human format like `example.com.` 
  The final dot is mandatory
* `type`, which can be `A` (IPv4) or `ip6` (IPv6)
* `upstreamIp4`, which is the IP connect to; this is a string in IPv4
  dotted decimal format, like `10.1.2.3` or `9.9.9.9`.  If `upstreamIp4`
  is not present, coLunacyDNS looks for a global variable called
  `upstreamIp4` to see if a default value is available.  

It outputs a table with a number of possible elements:

* `error`: If this is in the return table, an error happened which makes 
  it not possible to have `coDNS.solve` run.  Errors include giving
  `coDNS.solve` a bad query for its DNS name; not giving `coDNS.solve`
  a table when calling it; not having the element `type` in the table
  given to `coDNS.solve`; etc.  Once an error is returned, it is not
  possible to run `coDNS.solve` again in the current thread; if one
  calls `coDNS.solve` a second time after getting an error, the thread
  will be terminated and the client will not receive a DNS reply.
* `status`: If we got an IPv4 address from the upstream server, this
  returns the number 1.  If we got an IPv6 address from the upstream
  server, this returns the number 28 (the DNS number for an IPv6 reply).
  Otherwise, this returns the number 0.
* `answer`: This is the answer we got from the upstream DNS server.
  If the answer is an IPv4 IP, the answer is a string with a standard
  dotted decimal IP in it, such as `10.4.5.6`.  If the answer is an
  IPv6 IP, the answer is a string with the IPv6 IP in it, in the form
  `XXXX-XXXX-XXXX-XXXX XXXX-XXXX-XXXX-XXXX`, where each X is a 
  hexadecimal digit, such as `2001-0db8-4d61-7261 444e-5300-0000-0001`
  All 32 hexadecimal digits that comprise an IPv6 address will be 
  present in the reply string.  Should there be a timeout or error 
  getting an answer from the upstream DNS server, this string will have
  the value `DNS connect error`.  Should we get a reply from the
  upstream DNS server, but an answer was not seen (usually, because
  we asked for a DNS record which does not exist), the `answer` field
  will have the string `DNS answer not seen`.
* `rawpacket`: If the global variable `logLevel` has a value of 0,
  this will always be `nil`.  If `logLevel` is 1, this will be `nil`
  if we were able to extract an answer from the upstream DNS server;
  otherwise, this will be an escaped form of the raw packet sent to
  us from upstream.  If `logLevel` is 2 or higher, this will always
  be an escaped raw packet from upstream.  In an escaped packet, 
  characters which are between ASCII `0` and `z` will be shown as
  is; otherwise, they will be in the form `{1f}`, where the hex
  value of the byte is shown between the brackets (`{` and
  `}` have an ASCII value above `z`).

Since this function allows other Lua threads to run while it awaits a
DNS reply, global variables may change in value while the DNS record is
being fetched.

# Reading files

We have an API which can be used to read files.  For example:

```lua
if not coDNS.open1("filename.txt") then
  return {co1Type = "serverFail"}
end
local line = ""
while line do
  if line then coDNS.log("Line: " .. line) end
  line = coDNS.read1()
end
```
    
The calls are: `coDNS.open1(filename)`, `coDNS.read1()`, and 
`coDNS.close1()`.
    
Only a single file can be open at a time.  If `coDNS.open1()` is called
when a file is open, the currently open file is closed before we attempt
to open the new file.  If `coDNS.solve()` is called while a file is open,
the file is closed before we attempt to solve the DNS query.  If we exit
`processQuery()` while a file is open, the file is closed as we exit the
function.  Files are also closed when we finish parsing the Lua
configuration file used by coLunacyDNS, before listening to DNS queries.
    
The filename must start with an ASCII letter, number, or the `_`
(underscore) character.  The filename may contain only ASCII letters,
numbers, instances of `.` (the dot character), or the `_` character.
In particular, the filename may not contain `/`, `\`, or any other
commonly used directory separator.

If the file is not present, or the filename contains an illegal
character, or the file can not be opened, `coDNS.open1` will return
a `false` boolean value.  Otherwise, `open1` returns the `true` 
boolean.
    
The file has to be in the same directory that coLunacyDNS is run
from.  The file may only be read; writing to the file is not possible.
    
`coDNS.read1()` reads a single line from the file.  Any newline is
stripped from the end (unlike Perl, coLunacyDNS does not require a `chop`);
NUL characters in the line also truncate the string read.  If a line
is read from the file, `coDNS.read1()` returns the line which was read.
Otherwise, `coDNS.read1()` returns the `false` Lua boolean value.

`coDNS.read1()` assumes that a single line will be under 500 bytes 
in size.  Behavior is undefined when trying to read a longer line.
    
`coDNS.close1()` closes an open file; a file is also closed when
opening another file, ending `processQuery()`, or calling `coDNS.solve()`.
It is mainly here to give programmers trained to close open files
a function which does so.

# processQuery

Every time coLunacyDNS gets a query, it runs the lua function
processQuery, which takes as its input a table with the following members:

* `coQuery`: This is the DNS name requested, in the form of a string
  like `caulixtla.com.` or `samiam.org.` (observe the dot at the end of
  the mmQuery string).  If the string has anything besides an ASCII
  letter, an ASCII number, the `-` character (dash), or the `_`
  character (underline), the character will be a two-digit hexadecimal
  number in brackets.  If we get the raw UTF-8 query `ñ.samiam.org`
  (where the first character is a n with a tilde), coQuery will look
  like `{c3}{b1}.samiam.org.`.
* `coQtype`: The is the numeric DNS query type requested.  This is a number
  between 0 and 65535, and corresponds to the DNS query type made.  A
  list of DNS query type numbers is available at
  https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
  1 is "A", i.e. a request for an IPv4 IP address.
* `coFromIP`: This is a string containing, in human-readable format, the
  IP the query came from.  The string will look like `10.9.8.7`.
* `coFromIPtype`: This is the string `IPv4`

The processQuery function returns as its output a table with the following
parameters:

* `co1Type`: This is a string which can have the following values: 
  `ignoreMe` (no DNS reply will be sent back to the client), `notThere`
  (tell the client that this DNS name does not exist for the query
  type requested), `serverFail` (send a "server fail" to the client),
  "A" (send an IPv4 IP answer back to the client), or "ip6" (send an
  IPv6 IP answer back to the client).  Please note that `ignoreMe` 
  does not guarantee that coLunacyDNS ignores all DNS queries;  
  coLunacyDNS will always respond to ANY or HINFO queries in a
  RFC8482 manner; if one wishes to drop all DNS packets, this can
  be done at the firewall level.  This field is mandatory.
* `co1Data`: This is to be a string.  When `co1Type` is `A`, this is an 
  IPv4 IP in dotted decimal format, e.g. `10.1.2.3`.  When `co1type` is 
  `ip6`, and `co1data` is either a standard IPv6 string, such as 
  `2001:db8:1234::5678`, or a string with 32 hexadecimal digits, the IPv6 
  IP in the string is returned to the client.  If the character `_` is in 
  the ip6 string and the character `:` is *not* present in the string, 
  this is treated as if it were the number `0`; the characters ` ` (space) 
  and `-` (dash) are ignored.  For example, both `2001:db8::8` and
  `2001-0db8-4d61-7261 444e-5300-0000-__01` (without linefeed) are
  allowed values for `co1data` when `co1type` is `ip6`.  This field
  is mandatory when `co1type` is `A` or `ip6`.
* `co1AA`: This field, when set with the numeric value of 1,
  gives the `AA` flag in the DNS reply a value of true; in other
  words, the DNS answer is marked as “authoritative”.  This field
  is optional; if not set, the reply is *not* marked authoritative.
* `co1RA`: This field, when set with the numeric value of 1,
  gives the `RA` flag in the DNS reply a value of true, indicating
  that the coLunacyDNS server can process recursive queries.  This
  field is optional; if not set, the reply is *not* marked as having
  recursion available.
* `co1TTL`: This numeric field, if set, determines the DNS TTL (suggested 
  time to live for the record) of the reply.  This is the TTL in raw seconds,
  and can have a value between 0 (do not cache) and 7777777 (cache for
  just over 90 days).  This field is optional; if not set, the TTL 
  returned will be 0 (do not cache).

# Global settings 

coLunacyDNS Lua scripts have three special global variables which are
read to adjust settings in coLunacyDNS:

* `bindIp`: This is the IPv4 IP that coLunacyDNS will use as a DNS server.
  If this is not set, then coLunacyDNS will bind to the IP `0.0.0.0`
  (all IP addresses the machine running coLunacyDNS has)
* `bindIp6`: This is the IPv6 IP that coLunacyDNS will bind to.  If this
  is not set, coLunacyDNS will only bind to IPv4.  The IP address
  is in standard IPv6 format, e.g. `2001:0db8:f00:ba4::2020` or in
  MaraDNS-specific format, e.g. `2001-0db8-0f00-0ba4 00__00__00__2020`
* `logLevel`: If this is set, more information will be logged and passed
  to Lua scripts which can be used for debugging purposes.  This can have
  a value between 0 and 10; higher values result in more logging.  If
  `logLevel` has a value of 0, log messages generated with `coDNS.log` are
  buffered and will not immediately be visible; if `logLevel` has a value
  more than 0, `coDNS.log` messages are immediately flushed (unbuffered).

# Test coverage

`coLunacyDNS` is feature complete and being made stable.

I am currently in the process of making `coLunacyDNS` a stable and
fully tested DNS server.  Test coverage is currently, as of coLunacyDNS
1.0.008, at 100%.

Note: Some blocks of code, sanity tests to make sure we’re not in a corner
case which can not be readily replicated, have been removed from the testing
code via `#ifdef`.  Read sqa/README.md for details.

