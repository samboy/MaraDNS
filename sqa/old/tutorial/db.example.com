example.com. +86400 soa example.com. hostmaster@example.com. 140352450 7200 3600 604800 3600
example.com. +86400 ns synth-ip-7f000001.example.com.
synth-ip-7f000001.example.com. +86400 a 127.0.0.1
a.example.com. +86400 a 10.10.10.1
example.com. +86400 txt 'foo1'
# Second SOA received, exiting
