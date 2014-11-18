# Zone file for example.com (example file)

# See 'doc/csv1.format' for detailed help on the format of this file

# The SOA record must be first, followed by all authoritative NS records
# for this zone.
Scom.|86400|com.|hostmaster@example.com.|19771108|7200|3600|604800|1800
Ncom.|86400|ns2.example.net.

# Some 'IN A' records
Ans2.example.net.|86400|127.0.3.2


# NS delegation
# Error handling testing
#Nexample.com.|86400|nsbad.example.com.
#Ansbad.example.com.|86400|10.1.1.1
# Good in-bailiwick record
#Nexample.com.|86400|ns1.example.com.
#Ans1.example.com.|86400|127.0.3.4
# out-of-bailiwick record
Nexample.com.|86400|example-com.example.org.
# Massive timeout (disabled)
#Nexample.com.|86400|i1.example.net.
# Some records deliberately deigned to time out
Ai1.example.net.|86400|127.240.240.241
Ai2.example.net.|86400|127.240.240.242
Ai3.example.net.|86400|127.240.240.243
Ai4.example.net.|86400|127.240.240.244
Ai5.example.net.|86400|127.240.240.245
Ai6.example.net.|86400|127.240.240.246
Ai7.example.net.|86400|127.240.240.247
Ai8.example.net.|86400|127.240.240.248
Ai9.example.net.|86400|127.240.240.249

# A 'PTR' record which, while marked as unauthoritative, allows this
# program to work with the obsolete tool nslookup when bound on IP 127.0.0.3
P2.3.0.127.in-addr.arpa.|1234|ns2.example.net.

