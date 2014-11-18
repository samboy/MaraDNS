# Zone file for example.com (example file)

# See 'doc/csv1.format' for detailed help on the format of this file

# The SOA record must be first, followed by all authoritative NS records
# for this zone.
Sexample.com.|86400|example.com.|hostmaster@example.com.|19771108|7200|3600|604800|1800
Nexample.com.|86400|ns1.example.com.

# Some 'IN A' records
Aexample.com.|86400|10.1.2.3
Amx.example.com.|86400|10.1.2.4
Ans1.example.com.|86400|127.0.3.4

# An 'IN MX' record
@example.com.|86400|10|mx.example.com.

# A record chain
Awww.example.com.|86400|192.168.0.1
Awww.example.com.|86400|192.168.0.2
Awww.example.com.|86400|192.168.0.3
Awww.example.com.|86400|192.168.0.4
Awww.example.com.|86400|192.168.0.5
Awww.example.com.|86400|192.168.0.6
Awww.example.com.|86400|192.168.0.7
Awww.example.com.|86400|192.168.0.8
Awww.example.com.|86400|192.168.0.9
Awww.example.com.|86400|192.168.0.10

# A CNAME chain
Ccname1.example.com.|86400|cname2.example.com.
Ccname2.example.com.|86400|cname3.example.com.
Ccname3.example.com.|86400|cname4.example.com.
Ccname4.example.com.|86400|cname5.example.com.
Ccname5.example.com.|86400|cname6.example.com.
Ccname6.example.com.|86400|cname7.example.com.
Ccname7.example.com.|86400|cname8.example.com.
Ccname8.example.com.|86400|example.com.

# A NS delegation chain
Nnslist.example.com.|86400|ns.nslist.example.com.
Ans.nslist.example.com.|86400|127.99.99.99
Ans.nslist.example.com.|86400|127.0.3.7

# An 'IN TXT' record
Texample.com.|86400|Example.com: Buy examples of products online!

# An 'A' record showing the use of percent as a shortcut for the name
# of this zone (in this case, 'example.com.')
Aftp.%|3600|10.7.8.9

# A 'TXT' record showing the use of the backslash which allows any octal
# code in the record
Tpercent.%|7200|Get 50\045 off all \%items\% at example.com!
 
# A 'PTR' record which, while marked as unauthoritative, allows this
# program to work with the obsolete tool nslookup when bound on IP 127.0.0.3
#P4.3.0.127.in-addr.arpa.|1234|ns1.example.com.

