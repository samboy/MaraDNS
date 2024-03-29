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

