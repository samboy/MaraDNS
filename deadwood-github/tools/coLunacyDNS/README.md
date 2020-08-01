# coLunacyDNS

coLunacyDNS is a simply IPv4-only forwarding DNS server controlled
by a Lua script.  It allows a lot of flexibility because it uses
a combination of C for high performance and Lua for maximum
flexibility.

# Getting started

On a CentOS 8 Linux system, this gets us started:

```bash
./compile.coLunacyDNS.sh
su
./coLunacyDNS -d
```

Here, we use `coLunacyDNS.lua` as the configuration file.

Since coLunacyDNS runs on port 53, we need to start it as root.
As soon as coLunacyDNS binds to port 53 and seeds its internal 
secure pseudo random number generator, it calls `chroot` and drops
root privileges.

Cygwin users may use `compile.cygwin.sh` to compile coLunacyDNS, since
Cygwin does not have the same sandboxing Linux has.

# Configration file examples

In this example, we listen on 127.0.0.1, and, for any IPv4 query,
we return the IP of that query as reported by 9.9.9.9.

```lua
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
function processQuery(Q) -- Called for every DNS query received
   -- Connect to 9.9.9.9 for the query given to this routine
   t = coDNS.solve({name=Q.coQuery, type="A", upstreamIp4="9.9.9.9"})
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

Here is a more complicated example:

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

  -- Right now, coLunacyDNS can *only* process "A" (IPv4 IP) queries
  if Q.coQtype ~= 1 then -- If it is not an A (ipv4) query
    -- return {co1Type = "ignoreMe"} -- Ignore the query
    return {co1Type = "notThere"} -- Send "not there" (like NXDOMAIN)
  end

  -- Contact another DNS server to get our answer
  t = coDNS.solve({name=Q.coQuery, type="A", upstreamIp4=upstream})

  -- If coDNS.solve returns an error, the entire processQuery routine is
  -- "on probation" and unable to run coDNS.solve() again (if an attempt
  -- is made, the thread will be aborted and no DNS response sent 
  -- downstream).  
  if t.error then	
    coDNS.log(t.error)
    return {co1Type = "serverFail"} 
  end

  -- Status is 1 when we get an IP from the upstream DNS server, otherwise 0
  if t.status == 1 and t.answer then
    returnIP = t.answer
  end

  if string.match(Q.coQuery,'%.invalid%.$') then
    return {co1Type = "A", co1Data = "10.1.1.1"} -- Answer for anything.invalid
  end
  if returnIP then
    return {co1Type = "A", co1Data = returnIP} 
  end
  return {co1Type = "serverFail"} 
end
```

# Security considerations

Since the Lua file is executed as root, some effort is made to restrict
what it can do:

* Only the `math`, `string`, and `bit32` libraries are loaded from
  Lua's standard libs.  (bit32 actually is another Bit library, but with a
  `bit32` interface.)
* A special `coDNS` library is also loaded.
* The program is designed to not give Lua access to the filesystem nor 
  be able to do anything malicious.

# Limitations

coLunacyDNS, at this time, only processes requests for DNS `A`
queries—queries for IPv4 IP addresses.  Information about other query
types is not available to coLunacyDNS, and it can only return `A` queries
(or “server fail”, or “this name is not here”) in its replies.

coLunacyDNS, likewise, can only send `A` (IPv4 IP) requests to upstream
servers.  coLunacyDNS can only bind to an IPv4 IP, and can only send DNS
queries via IPv4.

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
  outputs the message on standard output.
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
  respond, or if it gives us a reply, but without a record we can use).
  This function is given a table with three members: `name`, which is
  the DNS name in human format like `example.com.` (the final dot is
  mandatory); `type`, which must be `A`, and `upstreamIp4`, which is
  the IP connect to; this is a string in IPv4 dotted decimal format,
  like `10.1.2.3` or `9.9.9.9`.  If `upstreamIp4` is not present,
  coLunacyDNS looks for a global variable called `upstreamIp4` to
  see if a default value is available.  Since this function allows
  other Lua threads to run while it awaits a DNS reply, global variables
  may change in value while the DNS record is being fetched.

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

The processQuery function returns as its output a table with one or two
parameters:

* `co1Type`: This is a string which can have the following values: 
  `ignoreMe` (no DNS reply will be sent back to the client), `notThere`
  (tell the client that this DNS name does not exist for the query
  type requested), `serverFail` (send a "server fail" to the client),
  or "A" (send an IPv4 IP answer back to the client)
* `co1Data`: When `co1Type` is `A`, this is an IPv4 IP in dotted decimal 
  format, e.g. `10.1.2.3`.  Otherwise, this field is ignored.

