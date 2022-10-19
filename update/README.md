Between 2005 and early 2020, MaraDNS was updated by a shell script which
would run a bunch of patches against the code to make a new release.
This system is still used for making updates to the 3.4 legacy
branch of MaraDNS, which is only updated with security and other
important fixes.

This allowed me to track changes without having to use a revision control
system.  In 2014, I started using Git to make some of the changes, but I
did not transition to making stable releases directly from Git until 2020.

This directory has the full history of MaraDNS changes done using this 
system; the corresponding Deadwood changes are in the folder 
`deadwood-{version}/update`.
