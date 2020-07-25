# mmLunacyDNS

mmLunacyDNS is a simple DNS server configured with Lunacy, my fork of
Lua 5.1 (the syntax is the same).  This server can only either ignore
DNS queries or reply with "A" (IPv4 IP DNS record) replies.

It uses, as a Lua configuration file, `mmLunacyDNS.lua` by default.
It is possible to use a different config file by either:

* Renaming the `mmLunacyDNS` binary to another name.
* By specifying a config file with the `-d` option:

```
	mmLunacyDNS -d /etc/mmLunacyDNS.lua
```

Here, the `-d` option means "debug": Do not run `mmLunacyDNS` as a 
daemon.  Right now, `mmLunacyDNS` does not have built-in daemonization
support, so it *must* have the `-d` option to run.  If one is using the
`mmLunacyDNS.lua` file in the same location as the `mmLunacyDNS` binary
as the configuration file, it can be run as follows:

```
	mmLunacyDNS -d
```

The configuration file, which *always* has the suffix `.lua`, tells
mmLunacyDNS the IP to bind to, and has a Lua function which is called
every time a DNS query is received.

The script `compile.mmLunacyDNS.sh` compiles mmLunacyDNS and links it
to Lunacy (Lua).

`mmLunacyDNS` currently has no UNIX/BSD/Linux daemonization support (but
it can be made a daemon with `Duende` included with MaraDNS).  It does, 
however, install and run as a Windows service; a binary is in the
top-level `bin/` folder (see the "Windows binary" section below).

# Configuration file format

mmLunacyDNS uses a Lua script as a configuration file.

From that file, it gets the string `bindIp`, which is the IP 
mmLunacyDNS binds to.  `bindIp` is a top-level global variable.

Once it binds to the IP, every time mmLunacyDNS gets a query, it
runs the lua function processQuery, which takes as its input a
table with the following members:

* `mmQuery`: This is the DNS name requested, in the form of a string
  like `caulixtla.com.` or `samiam.org.` (observe the dot at the end of 
  the mmQuery string).  If the string has anything besides an ASCII 
  letter, an ASCII number, the `-` character (dash), or the `_` 
  character (underline), the character will be a two-digit hexadecimal 
  number in brackets.  If we get the raw UTF-8 query `ñ.samiam.org` 
  (where the first character is a n with a tilde), mmQuery will look 
  like `{c3}{b1}.samiam.org.`.
* `mmQtype`: The is the numeric DNS query type requested.  This is a number
  between 0 and 65535, and corresponds to the DNS query type made.  A
  list of DNS query type numbers is available at
  https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
  1 is "A", i.e. a request for an IPv4 IP address.
* `mmFromIP`: This is a string containing, in human-readable format, the
  IP the query came from.  The string will look like `10.9.8.7`.
* `mmFromIPtype`: This is the number 4

The processQuery function returns as its output a table with two
parameters:

* `mm1Type`: This right now has to be the string `A`, or the DNS query is
  ignored
* `mm1Data`: This is an IPv4 IP in dotted decimal format, e.g. `10.1.2.3`

# Examples

```lua
-- We bind to the IP 127.0.0.1 and always return "10.1.2.3" for every
-- DNS query we get
bindIp = "127.0.0.1"
function processQuery(mmAll)
  return {mm1Type = "A", mm1Data="10.1.2.3"}
end
```

Here is a more complex example, where *.com gets 10.1.1.1 and anything else
gets 10.1.2.3, non-A queries are ignored, and we log A queries and the
IP they came from:

```lua
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
function processQuery(mmAll) -- Called for every DNS query received
  if mmAll.mmQtype ~= 1 then -- If it is not an A (IPv4 DNS record) query
    return {mm1Type = "ignoreMe"} -- Ignore the query
  end
  if mmAll.mmFromIPtype ~= 4 then -- If this is not sent over IPv4
    return {mm1Type = "ignoreMe"} -- Ignore the query
  end
  mmDNS.log("Got IPv4 query for " .. mmAll.mmQuery) -- Log the query
  mmDNS.log("Got IPv4 from " .. mmAll.mmFromIP) -- Log the query source IP
  if string.match(mmAll.mmQuery,'%.com%.$') then
    return {mm1Type = "A", mm1Data = "10.1.1.1"} -- Answer for anything.com
  end
  return {mm1Type = "A", mm1Data = "10.1.2.3"} -- Answer for all non-.com
end
```

# Lua regular expressions

Regular expressions are a common way to (among other things) find
strings which meet certain criteria.  `string.match`, in Lua, is a
routine which looks in a string for a given regular expression.

mmLunacyDNS uses, for its `string.match` command, Lua regular 
expressions.  In the interests of keeping code as compact as possible,
these are not Perl compatible regular expressions, but the syntax is 
similar.  While this document does not go over all of Lua’s regular
expression syntax, here are some useful pointers:

* `^` at the beginning of an expression indicates that the pattern we 
  are looking needs to be at the begining of a string. `foo` matches
  either `foo bar` or `bar foo`, but `^foo` only matches `foo bar` and
  not `bar foo`.
* `$` at the end of an expression indicates that the pattern we are looking
  for needs to be at the end of a string.  `foo$` matches `bar foo` but
  not `foo bar`
* `.` indicates we can have any character at that place in the pattern.
  `f.o.o` matches the start of `frobozz` or `foofo`, but not `foaoa`.
* `%.` indicates that we need to find a literal `.` in the pattern.
  While `foo.` matches `fooz`, `foo%.` only matches against `foo.`.
* Brackets indicate a range of characters that can match; `[a-z]` matches
  all ASCII lower case letters, and `[0-9]` matches numbers.  So, 
  `f[a-z]o` matches `fao`, `foo`, and `fzo`, but not `f3o`.  Likewise,
  `f[0-9]o` matches `f7o` but not `foo`.
* To match a single number, we can use use `%d`, e.g. `f%do` matches
  `f8o` but not `foo`.  To match one or more numbers, we can use `%d+`;
  `f%d+o` matches `f12o`, `f7o`, `f12345o`, but not `fzo`.

`string.match(string, pattern)` will return the matched string if 
found; otherwise it returns `nil` (equivalent to “null”) which is 
considered false in a Lua `if` statement:

* `string.match('foo','f.o')` will return the string `foo`
* `string.match('foo','f%do')` will return “nil”
* `string.match('f1o','f%do')` will return the string `f1o`

# Sandboxing

mmLunacyDNS provides some level of protection from untrusted `.lua` 
configuration files.  It is run in sandbox mode: All top-level
functions (such as `require`) are not present.  In addition, libraries
which can affect other files (such as `io` or `lfs`) are not here.  
What *is* present are three libraries for manipulating data: `string`,
`math`, and a mostly complete implementation of `bit32`.

To make up for there not being a `print` method, `mmDNS.log` can
be called instead; note that `mmDNS.log` only takes a single string
argument.

# Windows binary

In the `bin/` folder, there is a Windows binary of mmLunacyDNS available.
This is a service for Windows computers.  To install the service,
as an administrator, do the following:

```
	mmLunacyDNS.exe --install
	net start mmLunacyDNS
```

The mmLunacyDNS.exe file will use, as a configuration file, 
`mmLunacyDNS.lua` in the same location `mmLunacyDNS.exe` is 
located.  Messages will be logged in the file `mmLunacyDNSLog.txt`,
again in the same location as `mmLunacyDNS.exe`.

To stop the service:

```
	net stop mmLunacyDNS
```

It will take about two seconds to stop the mmLunacyDNS service.



