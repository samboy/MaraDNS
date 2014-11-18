Deadwood is a program that allows one to have a recursive DNS cache on their
Windows system.  

The supplied 'install.bat' program will install and start the
Deadwood service on a Windows system.  This file needs to be run as
an administrator in this directory; Windows Vista and Windows 7 users
need to read "Vista.txt" for details on how to install Deadwood on 
their systems.

Do not move the contents of this folder after installing Deadwood.
Otherwise, Windows may not be able to find the Deadwood service.

Once 'install.bat' is run, Deadwood should automatically start whenever 
the system is booted.  

The file dwood3rc.txt can be edited to change a number of options that are 
described in Reference.txt.  People should not use dwood3rc.txt files from 
beta-test versions of Deadwood.

Deadwood uses a file to store messages called "dwlog.txt" (without the quotes)
in the same directory where Deadwood is started.  If there are any errors
that make it so Deadwood can not start, they should be noted in this log
file.  

To stop Deadwood:

        net stop Deadwood

(Or from the Services control panel if you prefer mousing it)

Deadwood will write its cache to a file when stopped as a service.  
This file has the name 'dw_cache_bin'.

In order to actually use the Deadwood DNS cache on your computer, go
to the control panel entry for network connections (Control Panel ->
Network connections), then right-click on the network connection you use
and select "properties", select the TCP/IP protocol in the list of network
types in the window, click on the button marked "properties", manually
select DNS servers, and make 127.0.0.1 the DNS server used.

It is also possible to remove the Deadwood service.  'uninstall.bat' will 
remove the Deadwood service from a Windows system; this file needs to be 
run as an administrator.

Be sure to reset the DNS servers used before uninstalling Deadwood, 
otherwise it won't be possible to use the internet.

LEGAL DISCLAIMER

THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
