# What this is

This is a tool which generates a *block hash*, a list of binary strings 
along with hashing used to generate a compact database which can quickly
see if a given binary string is in a given list.

This is useful for what I call “naughty lists”; a list of domains we 
do not want Deadwood to resolve.  A current real-world list of over 200,000
domains would take around 200 megabytes of memory with Deadwood; by using
this compact format, we can have the same data take up less than eight
megabytes of data.

## To use

Let’s have a hosts.txt (or simply `hosts`) file of names we do not
want to resolve, where the undesirable names are given the IP `0.0.0.0`.  
To convert them in to a compact hash:

```
make # Compile the programs
cat naughty.hosts.txt | grep 0.0.0.0 | awk '{print $2}
  ' | fgrep '.' | ./blockHashMake 
./blockHashRead
```

This generates a file named `bigBlock.bin` which is a compact representation
of a hosts file with names black listed.

## Getting that naughty hosts.txt file

One possible source of a hosts file which can block naughty domains is
here:

https://github.com/StevenBlack/hosts


