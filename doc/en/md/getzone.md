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

