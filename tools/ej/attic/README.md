These are the original EJ tools developed in early 2002 to give
MaraDNS a unified document format, as was requested on the MaraDNS
mailing list.

Since these tools were written in Perl, I rewrote the tools in 2022
in Lua so that the document building tools no longer need a tool that
is not part of POSIX and is not included with MaraDNS -- MaraDNS, yes,
has a fully functional standalone Lua implementation for coLunacyDNS.
