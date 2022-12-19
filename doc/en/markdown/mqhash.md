# NAME

mqhash - Simple secure password generator 

# SYNOPSIS

**mqhash [-n #] [-s] [-u] {data to hash}** 

# DESCRIPTION

**mqhash** is a simple secure password generator. 

The program uses MaraDNS' secure random number generator as the 
compression function for a secure hash; the output of this secure hash 
can be used as passwords for various locations on the internet. 

This program solves the problem of either using the same password on 
multiple web sites, or having so many passwords that it is not 
practical to remember them all. 

# USAGE

The first step in using **mqhash** as a secure password generator is to 
set up a master secret from which all other passwords are generated. It 
is important to keep this master secret secure; such as on a Linux or 
BSD machine that is always behind a firewall and is current with 
security updates. 

This secure secret is put in the file `~/.mhash_prefix`. It is 
important that this secret is hard to guess; the security of all 
generated passwords is only as secure as the master secret. 

Once the `~/.mhash_prefix` file is set up, mqhash is run thusly:

```
mqhash -s {location} 
```

Where {location} is a web site, email address, or any other text 
string that describes where a given password is located. It is 
recommended that one uses a consistent style for {location} so that one 
can remember passwords for web sites that one has not visited for a 
while. Mqhash does not impose a style for remembering passwords; it is 
up to the user to create one. 

**mqhash** will output four potential passwords that have 32 bits of 
entropy. If more entropy is desired in a password, two 32-bit passwords 
can be joined together to generate a 64-bit password. A 32-bit password 
will protect against casual attacks but can be broken by a determined 
attacker with extensive resources attacking a website that does not 
lock out a user after too many failed attempts. A 64-bit password is 
immune to even a very determined attacker. 

## OPTIONS

-n It is wise to periodically change ones password on sites that 
one uses frequently. This allows one to continue to have passwords 
after the four initial passwords have already been used; this can have 
a value between 2 and 9. 

-s The normal mode for mqhash: To create a secure password based on 
both the contents of `~/.mhash_prefix` and the final argument to 
mqhash. 

-u This will generate a cryptographic hash out of the final 
argument sent to mqhash. This is useful when one does not need a secure 
password, but just wants to hash a short string.  

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
 

