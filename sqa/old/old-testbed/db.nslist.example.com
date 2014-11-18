# Zone file for example.com (example file)

# See 'doc/csv1.format' for detailed help on the format of this file

# The SOA record must be first, followed by all authoritative NS records
# for this zone.
S%|86400|%|hostmaster@%|19771108|7200|3600|604800|1800
N%|86400|ns.%

# An 'IN A' records
Asub.%|86400|10.66.66.66

