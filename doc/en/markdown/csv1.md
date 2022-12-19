# NAME

csv1 - Format of the csv1 zone file that MaraDNS uses 

# SPECIAL NOTE

The csv1 zone file format is supported primarily for MaraDNS users who 
already have zone files in the csv1 format. MaraDNS now supports a csv2 
zone file format. Note that the csv1 zone file format will continue to 
function as long as I am MaraDNS' maintainer. 

# SPECIAL CHARACTERS

`|`This delimits fields 
`#`This signifies a comment. Lines starting with this are ignored, 
otherwise it has no significance 
`%`This, in domain names, signifies that the rest of the domain name 
should be the name of this zone 
`*`This is translated to mean "any host name that otherwise does not 
resolve". It must be at the beginning of a domain name. 
`\`This is used as an escape character, either to escape octal values 
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

